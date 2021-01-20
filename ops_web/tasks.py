import concurrent.futures
import datetime
import elasticapm
import flask
import json
import logging
import ops_web.aws
import ops_web.config
import ops_web.db
import ops_web.send_email
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


def get_zendesk_user(email: str, settings: ops_web.db.Settings) -> int:
    """Use an email address to get the user_id in Zendesk. Create a user if one does not already exist."""

    auth = requests.auth.HTTPBasicAuth(f'{settings.zendesk_email_address}/token', settings.zendesk_api_token)
    session = requests.Session()
    session.auth = auth

    query = {'query': email}
    url = f'https://{settings.zendesk_company}.zendesk.com/api/v2/users/search.json?{urllib.parse.urlencode(query)}'
    response = session.get(url)
    response.raise_for_status()
    users = response.json().get('users')
    if users:
        return users[0].get('id')
    else:
        # create this user in zendesk
        url = f'https://{settings.zendesk_company}.zendesk.com/api/v2/users.json'
        json_data = {
            'user': {
                'email': email,
                'name': email.split('@')[0],
                'verified': True
            }
        }
        response = session.post(url, json=json_data)
        response.raise_for_status()
        user = response.json().get('user')
        return user.get('id')


def create_zendesk_ticket(tc: TaskContext, ticket_data: dict):
    settings = ops_web.db.Settings(tc.db)

    if not settings.zendesk_api_token:
        log.warning('Cannot create a ticket, zendesk-api-token is not set')
        return

    if not settings.zendesk_email_address:
        log.warning('Cannot create a ticket, zendesk-email-address is not set')
        return

    if not settings.zendesk_company:
        log.warning('Cannot create a ticket, zendesk-company is not set')
        return

    auth = requests.auth.HTTPBasicAuth(f'{settings.zendesk_email_address}/token', settings.zendesk_api_token)
    session = requests.Session()
    session.auth = auth

    url = f'https://{settings.zendesk_company}.zendesk.com/api/v2/tickets.json'
    json_data = {'ticket': ticket_data}
    response = session.post(url, json=json_data)
    log.debug(response.json())
    response.raise_for_status()
    ticket_id = response.json().get('ticket', {}).get('id')
    log.debug(f'Created a Zendesk ticket: {ticket_id}')


def create_zendesk_ticket_unity(tc: TaskContext, requester, form_data):
    tc.apm.begin_transaction('task')
    task_name = 'create-zendesk-ticket-unity'
    log.info('Creating a Zendesk ticket')

    settings = ops_web.db.Settings(tc.db)

    if not settings.unity_support_group_id:
        log.warning('Cannot create a ticket, monolith-support-group-id is not set')
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
        'group_id': settings.unity_support_group_id
    }

    ticket_data.update({'requester_id': get_zendesk_user(requester, settings)})

    ctx = form_data.to_dict()
    ctx['requester'] = requester

    with tc.app.app_context():
        if form_data.get('request-type') == 'system-down':
            region = form_data.get('region')
            ticket_data.update({
                'subject': f'The Unity Global Demo Environment is down in {region}',
                'comment': {
                    'html_body': f'{requester} reports that the Unity Global Demo Environment is down in {region}.'
                }
            })
        elif form_data.get('request-type') == 'bug':
            bug_description = form_data.get('bug-description')
            ticket_data.update({
                'subject': f'Unity bug report: {bug_description}',
                'comment': {
                    'html_body': flask.render_template('zendesk-tickets/unity-bug.html', ctx=ctx)
                },
                'external_id': 'monolith-jira-candidate'
            })
        elif form_data.get('request-type') == 'change-request':
            feature_description = form_data.get('feature-description')
            ticket_data.update({
                'subject': f'Unity change request: {feature_description}',
                'comment': {
                    'html_body': flask.render_template('zendesk-tickets/unity-change-request.html', ctx=ctx)
                },
                'external_id': 'monolith-jira-candidate'
            })
        else:
            log.warning('Unknown request type')
            tc.apm.end_transaction(task_name)
            return

    auth = requests.auth.HTTPBasicAuth(f'{settings.zendesk_email_address}/token', settings.zendesk_api_token)
    session = requests.Session()
    session.auth = auth

    # upload a json representation of the request
    query = {
        'filename': 'monolith-request.json'
    }
    url = f'https://{settings.zendesk_company}.zendesk.com/api/v2/uploads.json?{urllib.parse.urlencode(query)}'
    data = json.dumps(ctx, sort_keys=True, indent=1)
    response = session.post(url, headers={'Content-Type': 'application/json'}, data=data)
    response.raise_for_status()
    upload_token = response.json().get('upload', {}).get('token')
    ticket_comment = ticket_data.get('comment')
    ticket_comment.update({'uploads': [upload_token]})
    ticket_data.update({'comment': ticket_comment})

    create_zendesk_ticket(tc, ticket_data)

    tc.apm.end_transaction(task_name)


def create_zendesk_ticket_seas(tc: TaskContext, requester: str, form_data: dict):
    tc.apm.begin_transaction('task')
    task_name = 'create-zendesk-ticket-seas'

    settings = ops_web.db.Settings(tc.db)

    if not settings.seas_support_group_id:
        log.warning('Cannot create a ticket, seas-support-group-id is not set')
        tc.apm.end_transaction(task_name)
        return

    if 'td-completed' in form_data:
        request_quality = None
        td_completed = 'Yes'
    else:
        request_quality = 'incomplete_or_insufficient_quality'
        td_completed = 'No'
    request = form_data.get('request')

    ecosystem = form_data.get('ecosystem', '')
    existing_solution = form_data.get('existing-solution')
    primary_product = form_data.get('primary-product')
    primary_product_name = form_data.get('primary-product-name')
    department = form_data.get('department')
    subject = f'{ecosystem} {primary_product_name} {department} SEAS Request'

    sf_account_number = form_data.get('sf-account-number')
    if not sf_account_number:
        sf_account_number = ecosystem
    sf_opportunity_number = form_data.get('sf-opportunity-number')
    if not sf_opportunity_number:
        sf_opportunity_number = 'N/A'

    initial_activity = form_data.get('activity')

    target_timeline = form_data.get('target-timeline')
    target_date = datetime.datetime.strptime(target_timeline, '%Y-%m-%d').date()
    lead_days = (target_date - datetime.date.today()).days
    if lead_days < 1:
        lead_days_value = 'less_than_1_day'
    elif lead_days < 2:
        lead_days_value = '1_day'
    elif lead_days < 5:
        lead_days_value = '2_4_days'
    else:
        lead_days_value = '5_days'

    with tc.app.app_context():
        html_body = flask.render_template('zendesk-tickets/seas-request.html')

    ticket_data = {
        'comment': {
            'html_body': html_body
        },
        'custom_fields': [
            # sfdc account number
            {'id': 455040, 'value': sf_account_number},
            # sfdc opportunity number
            {'id': 455041, 'value': sf_opportunity_number},
            # service type
            {'id': 455056, 'value': 'ecosystem_architect_request'},
            # primary product
            {'id': 20655668, 'value': primary_product},
            # lead days provided
            {'id': 21350618, 'value': lead_days_value},
            # initial activity
            {'id': 21497921, 'value': initial_activity},
            # business drivers
            {'id': 360000390987, 'value': form_data.get('business-drivers')},
            # request quality
            {'id': 360000398388, 'value': request_quality},
            # existing solution
            {'id': 360000391027, 'value': f'{ecosystem} {existing_solution}'},
            # what are you requesting to be done?
            {'id': 360000398408, 'value': f'Technical Discovery Completed: {td_completed} / {request}'},
            # target timeline
            {'id': 360000398428, 'value': target_timeline},
            # audience
            {'id': 360000398448, 'value': form_data.get('audience')}
        ],
        'due_at': form_data.get('target-timeline'),
        'group_id': settings.seas_support_group_id,
        'priority': form_data.get('priority', 'normal').lower(),
        'subject': subject,
        'tags': ['ecosystem', ecosystem],
        'type': 'task'
    }

    ticket_data.update({'requester_id': get_zendesk_user(requester, settings)})
    create_zendesk_ticket(tc, ticket_data)
    tc.apm.end_transaction(task_name)


def get_cost_data(tc: TaskContext):
    try:
        tc.apm.begin_transaction('task')
        log.info('Getting cost data from Cloudability')

        ready = True

        settings = ops_web.db.Settings(tc.db)
        if not settings.cloudability_auth_token:
            log.info('cloudability-auth-token is not set')
            ready = False

        if ready and not settings.cloudability_vendor_account_ids:
            log.info('cloudability-vendor-account-ids is not set')
            ready = False

        if ready:
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
    finally:
        tc.db.update_scheduled_task_last_run('get-cost-data')
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


def check_for_images_to_delete(tc: TaskContext):
    tc.apm.begin_transaction('task')
    images = tc.db.get_images_to_delete()
    if images:
        ctx = {'images': images}
        with tc.app.app_context():
            body = flask.render_template('email/admin-images-to-delete.html', ctx=ctx)
            ops_web.send_email.send_email(tc.config, tc.config.support_email, 'Ops Web image deletion request', body)
    tc.db.update_scheduled_task_last_run('check-for-images-to-delete')
    tc.apm.end_transaction('check-for-images-to-delete')
