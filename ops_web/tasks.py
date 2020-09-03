import concurrent.futures
import datetime
import elasticapm
import flask
import logging
import ops_web.aws
import ops_web.config
import ops_web.db
import requests
import requests.auth
import time
import urllib.parse

log = logging.getLogger(__name__)


class TaskContext:
    app: flask.Flask
    apm: elasticapm.Client
    config: ops_web.config.Config
    db: ops_web.db.Database

    def __init__(self, app, apm, config, db):
        self.app = app
        self.apm = apm
        self.config = config
        self.db = db


def create_zendesk_ticket(tc: TaskContext, requester, form_data):
    tc.apm.begin_transaction('task')
    task_name = 'create-zendesk-ticket'
    log.info('Creating a Zendesk ticket')

    settings = ops_web.db.Settings(tc.db)

    if not settings.monolith_support_group_id:
        log.warning('Cannot create a ticket, monolith-support-group-id is not set')
        tc.apm.end_transaction(task_name)
        return

    if not settings.zendesk_api_token:
        log.warning('Cannot create a ticket, zendesk-api-token is not set')
        tc.apm.end_transaction(task_name)
        return

    if not settings.zendesk_email_address:
        log.warning('Cannot create a ticket, zendesk-email-address is not set')
        tc.apm.end_transaction(task_name)
        return

    if not settings.zendesk_company:
        log.warning('Cannot create a ticket, zendesk-company is not set')
        tc.apm.end_transaction(task_name)
        return

    ticket_data = {
        'comment': {
            'body': 'This is a test.'
        },
        'custom_fields': [
            {'id': 455056, 'value': 'project_monolith'},  # service type
            {'id': 455040, 'value': 'n/a'},  # sfdc account number
            {'id': 455041, 'value': 'n/a'},  # sfdc opportunity number
            {'id': 20655668, 'value': 'na'}  # primary product
        ],
        'group_id': settings.monolith_support_group_id
    }

    auth = requests.auth.HTTPBasicAuth(f'{settings.zendesk_email_address}/token', settings.zendesk_api_token)

    # find this user in zendesk
    query = {'query': requester}
    url = f'https://{settings.zendesk_company}.zendesk.com/api/v2/users/search.json?{urllib.parse.urlencode(query)}'
    response = requests.get(url, auth=auth)
    response.raise_for_status()
    users = response.json().get('users')
    if users:
        ticket_data.update({'requester_id': users[0].get('id')})
    else:
        # create this user in zendesk
        url = f'https://{settings.zendesk_company}.zendesk.com/api/v2/users.json'
        json = {
            'user': {
                'email': requester,
                'name': requester.split('@')[0],
                'verified': True
            }
        }
        response = requests.post(url, json=json, auth=auth)
        response.raise_for_status()
        user = response.json().get('user')
        ticket_data.update({'requester_id': user.get('id')})

    ctx = form_data.to_dict()
    ctx['requester'] = requester

    with tc.app.app_context():
        if form_data.get('request-type') == 'system-down':
            region = form_data.get('region')
            ticket_data.update({
                'subject': f'Monolith is down in {region} region',
                'comment': {
                    'html_body': f'{requester} reports that Monolith is down in {region} region.'
                }
            })
        elif form_data.get('request-type') == 'bug':
            region = form_data.get('region')
            ticket_data.update({
                'subject': f'Bug report for Monolith in {region} region',
                'comment': {
                    'html_body': flask.render_template('zendesk-tickets/monolith-bug.html', ctx=ctx)
                }
            })
        elif form_data.get('request-type') == 'change-request':
            ticket_data.update({
                'subject': 'Change request for Monolith',
                'comment': {
                    'html_body': flask.render_template('zendesk-tickets/monolith-change-request.html', ctx=ctx)
                }
            })
        else:
            log.warning('Unknown request type')
            tc.apm.end_transaction(task_name)
            return

    url = f'https://{settings.zendesk_company}.zendesk.com/api/v2/tickets.json'
    json = {'ticket': ticket_data}
    response = requests.post(url, auth=auth, json=json)
    response.raise_for_status()
    ticket_id = response.json().get('ticket', {}).get('id')
    log.debug(f'Created a Zendesk ticket: {ticket_id}')

    tc.apm.end_transaction(task_name)


def get_cost_data(tc: TaskContext):
    tc.apm.begin_transaction('task')
    log.info('Getting cost data from Cloudability')

    settings = ops_web.db.Settings(tc.db)
    if not settings.cloudability_auth_token:
        log.info('cloudability-auth-token is not set')
        tc.apm.end_transaction('get-cost-data')
        return

    if not settings.cloudability_vendor_account_ids:
        log.info('cloudability-vendor-account-ids is not set')
        tc.apm.end_transaction('get-cost-data')
        return

    base_url = 'https://app.cloudability.com/api/1/reporting/cost'
    token_only = {'auth_token': settings.cloudability_auth_token}
    query = {
        'auth_token': settings.cloudability_auth_token,
        'dimensions': 'resource_identifier',
        'metrics': 'unblended_cost',
        'start_date': '30 days ago at 00:00:00',
        'end_date': '23:59:59'
    }
    filters = [f'vendor_account_identifier=={i}' for i in settings.cloudability_vendor_account_ids]
    filters.append('resource_identifier!=@(not set)')
    query['filters'] = ','.join(filters)

    url = f'{base_url}/enqueue?{urllib.parse.urlencode(query)}'
    log.debug(f'Cloudability url is {url}')
    enqueue_response = requests.get(url)
    enqueue_response.raise_for_status()
    enqueue_data = enqueue_response.json()
    job_id = enqueue_data.get('id')
    log.debug(f'Cloudability report job_id is {job_id}')
    url = f'{base_url}/reports/{job_id}/state?{urllib.parse.urlencode(token_only)}'
    job_status = 'requested'
    while job_status not in ('errored', 'finished'):
        time.sleep(5)
        state_response = requests.get(url)
        state_response.raise_for_status()
        state_data = state_response.json()
        job_status = state_data.get('status')
    if job_status == 'finished':
        url = f'{base_url}/reports/{job_id}/results?{urllib.parse.urlencode(token_only)}'
        results_response = requests.get(url)
        results_response.raise_for_status()
        results_data = results_response.json()
        tc.db.cost_data_pre_sync()
        for result in results_data.get('results', []):
            log.debug(f'Adding result to database: {result}')
            tc.db.add_cost_data(**result)
        tc.db.cost_data_post_sync()
    else:
        log.critical(f'Cloudability report job {job_id} is {job_status}')
    log.info('Done getting cost data from Cloudability')
    tc.apm.end_transaction('get-cost-data')


def update_termination_protection(tc: TaskContext):
    tc.apm.begin_transaction('task')
    log.info('Checking termination protection for all AWS machines')
    sync_start = datetime.datetime.utcnow()

    def _update_one_machine(_aws: ops_web.aws.AWSClient, _db: ops_web.db.Database, _region: str, _machine_id: str):
        tp = _aws.get_termination_protection(_region, _machine_id)
        _db.set_machine_termination_protection(_machine_id, tp)

    aws_clients = {}
    with concurrent.futures.ThreadPoolExecutor() as ex:
        fs = []
        for machine in tc.db.get_all_visible_machines():
            if machine.get('cloud') == 'aws':
                machine_id = machine.get('id')
                account_id = machine.get('account_id')
                if account_id in aws_clients:
                    aws = aws_clients.get(account_id)
                else:
                    cred = tc.db.get_one_credential_for_use(account_id)
                    aws = ops_web.aws.AWSClient(tc.config, cred.get('username'), cred.get('password'))
                    aws_clients[account_id] = aws
                fs.append(ex.submit(_update_one_machine, aws, tc.db, machine.get('region'), machine_id))
        concurrent.futures.wait(fs)
    sync_duration = datetime.datetime.utcnow() - sync_start
    log.info(f'Done checking termination protection for all AWS machines / {sync_duration}')
    tc.apm.end_transaction('update-termination-protection')
