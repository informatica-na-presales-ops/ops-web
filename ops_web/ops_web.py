import apscheduler.schedulers.background
import datetime
import decimal
import elasticapm.contrib.flask
import ipaddress
import ops_web.aws
import ops_web.az
import ops_web.gcp
import ops_web.config
import ops_web.db
import ops_web.op_debrief_surveys
import ops_web.send_email
import ops_web.tasks
import ops_web.util.human_time
import flask
import functools
import io
import jwt
import logging
import pathlib
import pendulum
import sys
import urllib.parse
import uuid
import waitress
import werkzeug.middleware.proxy_fix
import whitenoise
import xlsxwriter

config = ops_web.config.Config()
db = ops_web.db.Database(config)
scheduler = apscheduler.schedulers.background.BackgroundScheduler(job_defaults={'misfire_grace_time': 900})

app = flask.Flask(__name__)
app.wsgi_app = werkzeug.middleware.proxy_fix.ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_port=1)

whitenoise_root = pathlib.Path(__file__).resolve().with_name('static')
app.wsgi_app = whitenoise.WhiteNoise(app.wsgi_app, root=whitenoise_root, prefix='static/')

apm = elasticapm.contrib.flask.ElasticAPM(app, service_name='ops-web', service_version=config.version)

app.secret_key = config.secret_key

# for generating external URLs outside a request context (e.g. automated emails)
app.config['PREFERRED_URL_SCHEME'] = config.scheme
app.config['SERVER_NAME'] = config.server_name

if config.scheme == 'https':
    app.config['SESSION_COOKIE_SECURE'] = True


def permission_required(permission: str):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            app.logger.debug(f'Checking permission for {flask.g.email}')
            if flask.g.email is None:
                flask.session['sign-in-target-url'] = flask.request.url
                return flask.redirect(flask.url_for('sign_in'))
            if permission in flask.g.permissions:
                return f(*args, **kwargs)
            flask.g.required_permission = permission
            return flask.render_template('not-authorized.html')

        return decorated_function

    return decorator


def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        app.logger.debug(f'Checking login, flask.g.email: {flask.g.email}')
        if flask.g.email is None:
            flask.session['sign-in-target-url'] = flask.request.url
            return flask.redirect(flask.url_for('sign_in'))
        return f(*args, **kwargs)

    return decorated_function


@app.before_request
def log_request():
    app.logger.debug(f'{flask.request.method} {flask.request.path}')


@app.before_request
def make_session_permanent():
    if config.permanent_sessions:
        flask.session.permanent = True


@app.before_request
def load_request_data():
    flask.g.config = config
    flask.g.db = db
    flask.g.settings = ops_web.db.Settings(flask.g.db)
    flask.g.email = flask.session.get('email')
    flask.g.permissions = flask.g.db.get_permissions(flask.g.email)


@app.route('/')
def index():
    if flask.g.email is None:
        return flask.render_template('sign-in.html')
    flask.g.is_manager = db.is_manager(flask.g.email)
    return flask.render_template('index.html')


@app.route('/admin')
@permission_required('admin')
def admin():
    return flask.redirect(flask.url_for('admin_users'))


@app.route('/admin/cloud-credentials')
@permission_required('admin')
def admin_cloud_credentials():
    flask.g.cloud_credentials = db.get_cloud_credentials()
    return flask.render_template('admin/cloud-credentials.html')


@app.route('/admin/cloud-credentials/delete', methods=['POST'])
@permission_required('admin')
def admin_cloud_credentials_delete():
    cred_id = flask.request.values.get('id')
    db.delete_cloud_credentials(cred_id)
    db.add_log_entry(flask.g.email, f'Delete cloud credentials {cred_id}')
    return flask.redirect(flask.url_for('admin_cloud_credentials'))


@app.route('/admin/cloud-credentials/edit', methods=['POST'])
@permission_required('admin')
def admin_cloud_credentials_edit():
    params = flask.request.values.to_dict()
    app.logger.debug(params)
    cred_id = params.get('id')
    if cred_id:
        if 'set-password' not in params:
            params.pop('password', None)
        db.update_cloud_credentials(params)
        db.add_log_entry(flask.g.email, f'Update cloud credentials for {cred_id}')
    else:
        cred_id = db.add_cloud_credentials(params)
        db.add_log_entry(flask.g.email, f'Add cloud credentials for {cred_id}')
    return flask.redirect(flask.url_for('admin_cloud_credentials'))


@app.route('/admin/settings')
@permission_required('admin')
def admin_settings():
    flask.g.current_image_name_max_length = db.get_image_name_max_length()
    flask.g.tasks = db.get_scheduled_tasks()
    return flask.render_template('admin/settings.html')


@app.route('/admin/settings/cloudability', methods=['POST'])
@permission_required('admin')
def admin_settings_cost_data():
    settings: ops_web.db.Settings = flask.g.settings
    settings.cloudability_auth_token = flask.request.values.get('cloudability-auth-token', '').strip()
    vendor_account_ids = set(flask.request.values.get('cloudability-vendor-account-ids', '').split())
    settings.cloudability_vendor_account_ids = vendor_account_ids
    db.add_log_entry(flask.g.email, 'Updated Cloudability integration settings')
    return flask.redirect(flask.url_for('admin_settings'))


@app.route('/admin/settings/cloudability/sync', methods=['POST'])
@permission_required('admin')
def admin_cost_data_sync():
    db.add_log_entry(flask.g.email, 'Manual cost data sync')
    tc = ops_web.tasks.TaskContext(app, apm.client, config, db)
    scheduler.add_job(ops_web.tasks.get_cost_data, args=[tc])
    flask.flash('Cost data synchronization has started.', 'primary')
    return flask.redirect(flask.url_for('admin_settings'))


@app.route('/admin/settings/display', methods=['POST'])
@permission_required('admin')
def admin_settings_display():
    settings: ops_web.db.Settings = flask.g.settings
    settings.app_env_values = flask.request.values.get('app-env-values', '').splitlines()
    settings.image_name_display_length = int(flask.request.values.get('image-name-display-length'))
    settings.show_account_for_images = flask.request.values.get('show-account-for-images') == 'on'
    settings.show_all_images = flask.request.values.get('show-all-images') == 'on'
    settings.show_monolith_request_link = flask.request.values.get('show-monolith-request-link') == 'on'
    settings.show_op_debrief_survey_link = flask.request.values.get('show-op-debrief-survey-link') == 'on'
    settings.show_sap_access_link = flask.request.values.get('show-sap-access-link') == 'on'
    settings.show_sc_assignments_link = flask.request.values.get('show-sc-assignments-link') == 'on'
    settings.show_sc_competency_link = flask.request.values.get('show-sc-competency-link') == 'on'
    settings.show_security_groups_link = flask.request.values.get('show-security-groups-link') == 'on'
    db.add_log_entry(flask.g.email, 'Update display settings')
    flask.flash('Successfully updated display settings', 'success')
    return flask.redirect(flask.url_for('admin_settings'))


@app.route('/admin/settings/global-permissions', methods=['POST'])
@permission_required('admin')
def admin_settings_global_permissions():
    settings: ops_web.db.Settings = flask.g.settings
    settings.allow_users_to_delete_images = flask.request.values.get('allow-users-to-delete-images') == 'on'
    db.add_log_entry(flask.g.email, 'Update global permission settings')
    flask.flash('Successfully updated global permission settings', 'success')
    return flask.redirect(flask.url_for('admin_settings'))


@app.route('/admin/settings/tasks', methods=['POST'])
@permission_required('admin')
def admin_settings_tasks():
    active_tasks = list(flask.request.values)
    db_tasks = db.get_scheduled_tasks()
    for task in db_tasks:
        task_name = task.get('task_name')
        db.set_scheduled_task_active(task_name, task_name in active_tasks)
    db.add_log_entry(flask.g.email, 'Update list of active scheduled tasks')
    flask.flash('Active scheduled tasks updated.', 'success')
    return flask.redirect(flask.url_for('admin_settings'))


@app.route('/admin/settings/zendesk', methods=['POST'])
@permission_required('admin')
def admin_settings_zendesk():
    settings: ops_web.db.Settings = flask.g.settings
    settings.monolith_support_group_id = int(flask.request.values.get('monolith-support-group-id', 0))
    settings.zendesk_api_token = flask.request.values.get('zendesk-api-token', '')
    settings.zendesk_company = flask.request.values.get('zendesk-company', '')
    settings.zendesk_email_address = flask.request.values.get('zendesk-email-address', '')
    settings.zendesk_widget_key = flask.request.values.get('zendesk-widget-key', '')
    db.add_log_entry(flask.g.email, 'Updated Zendesk integration settings')
    flask.flash('You successfully updated the Zendesk integration settings', 'success')
    return flask.redirect(flask.url_for('admin_settings'))


@app.route('/admin/users')
@permission_required('admin')
def admin_users():
    flask.g.users = db.get_all_permissions()
    flask.g.available_permissions = {
        'admin': ('view and manage all environments, launch sync manually, grant permissions to other users, manage '
                  'cloud credentials'),
        'cert-approval': 'receive notifications of and approve new ecosystem certifications',
        'manager': 'access tools for managers (use this permission if email addresses do not match)',
        'sc-assignments': 'view and manage sales consultant assignments',
        'survey-admin': 'view all opportunity debrief surveys'
    }
    return flask.render_template('admin/users.html')


@app.route('/admin/users/edit', methods=['POST'])
@permission_required('admin')
def admin_users_edit():
    email = flask.request.values.get('email')
    permissions = set(flask.request.values.getlist('permissions'))
    db.add_log_entry(flask.g.email, f'Set permissions for {email} to {permissions}')
    db.set_permissions(email, permissions)
    return flask.redirect(flask.url_for('admin'))


@app.route('/admin/users/impersonate', methods=['POST'])
@permission_required('admin')
def admin_users_impersonate():
    target = flask.request.form.get('target')
    db.add_log_entry(flask.g.email, f'Impersonate user {target}')
    flask.session['email'] = target
    return flask.redirect(flask.url_for('index'))


@app.route('/audit-log')
@permission_required('admin')
def audit_log():
    flask.g.log_entries = db.get_log_entries()
    return flask.render_template('log.html')


@app.route('/authorize', methods=['POST'])
def authorize():
    for key, value in flask.request.values.items():
        app.logger.debug(f'{key}: {value}')
    id_token = flask.request.values.get('id_token')
    claim = jwt.decode(id_token, verify=False, algorithms='RS256')
    app.logger.debug(claim)
    state = flask.request.values.get('state')
    if state is None or state != flask.session.get('state'):
        app.logger.info('Authorization failure due to state mismatch')
        return flask.redirect(flask.url_for('index'))
    flask.session.pop('state')

    email = claim.get('email').lower()
    flask.session['email'] = email
    app.logger.info(f'Successful sign in for {email}')
    target = flask.session.pop('sign-in-target-url', flask.url_for('index'))
    app.logger.debug(f'sign-in-target-url: {target}')
    return flask.redirect(target)


@app.route('/az_launch', methods=['POST'])
@login_required
def az_launch():
    cdwversion = flask.request.values.get("cdwversion")
    app.logger.info(cdwversion)
    quantity = flask.request.values.get('count')
    name = flask.request.values.get('name')
    owner = flask.request.values.get('owner').lower()
    q = int(quantity)
    idlist = []
    instance_info = []
    for account in db.get_all_credentials_for_use('az'):
        for i in range(q):
            az_idlist = []
            az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                     account.get('azure_tenant_id'))
            if cdwversion == 'CDW104-AZ':
                vmbase = name + str("104") + "-" + str(i)
                infa_result = az.launch_infa104(account.get('username'), account.get('password'),
                                                account.get('azure_tenant_id'), vmbase, owner)
                windows_result = az.launch_windows104(account.get('username'), account.get('password'),
                                                      account.get('azure_tenant_id'), vmbase, owner)

            else:
                vmbase = name + "-" + str(i)

                cdh_result = az.launch_cdh_instance(account.get('username'), account.get('password'),
                                                    account.get('azure_tenant_id'), vmbase, owner)

                windows_result = az.launch_windows(account.get('username'), account.get('password'),
                                                   account.get('azure_tenant_id'), vmbase, owner)
                infa_result = az.launch_infa(account.get('username'), account.get('password'),
                                             account.get('azure_tenant_id'), vmbase, owner)
                az_idlist.append(cdh_result)

            az_idlist.append(windows_result)
            az_idlist.append(infa_result)
            app.logger.info(az_idlist)
            for i in az_idlist:
                virtualmachine_info = az.get_virtualmachine_info(i, "rg-cdw-workshops-201904")
                instance_info.append(virtualmachine_info)
                idlist.append(virtualmachine_info['id'])
                virtualmachine_info['account_id'] = account.get('id')
                db.add_machine(virtualmachine_info)
            app.logger.info(idlist)
            app.logger.info(instance_info)
        return flask.render_template('postdep_az.html', instance=instance_info, idlist=idlist)


@app.route('/ecosystem-certification')
@login_required
def ecosystem_certification():
    flask.g.certs = db.get_ecosystem_certifications_for_user(flask.g.email)
    return flask.render_template('ecosystem-certification/index.html')


@app.route('/ecosystem-certification/add', methods=['POST'])
@login_required
def ecosystem_certification_add():
    app.logger.debug(f'Adding a new ecosystem certification for {flask.g.email}')
    app.logger.debug(list(flask.request.values.items()))
    ecosystem = flask.request.values.get('ecosystem')
    title = flask.request.values.get('title')
    params = {
        'user_login': flask.g.email,
        'ecosystem': ecosystem,
        'title': title,
        'certification_date': flask.request.values.get('date'),
        'expiration_date': flask.request.values.get('expiration-date'),
        'aws_partner_portal_updated': flask.request.values.get('aws-partner-portal-updated') == 'on',
        'document_name': None,
        'document_size': None,
        'document_data': None
    }

    if flask.request.values.get('title') == 'other':
        params.update({'title': flask.request.values.get('custom-title')})

    for field in ('certification_date', 'expiration_date'):
        if params.get(field) == '':
            params.update({field: None})

    document = flask.request.files.get('document')
    if document:
        data = document.read()
        params.update({
            'document_name': document.filename,
            'document_size': len(data),
            'document_data': data
        })
    db.add_ecosystem_certification(params)
    db.add_log_entry(flask.g.email, f'Add ecosystem certification: {ecosystem}, {title}')
    return flask.redirect(flask.url_for('ecosystem_certification'))


@app.route('/ecosystem-certification/approval')
@permission_required('cert-approval')
def ecosystem_certification_approval():
    flask.g.certs = db.get_ecosystem_certifications_for_approval()
    return flask.render_template('ecosystem-certification/approval.html')


@app.route('/ecosystem-certification/approval/add', methods=['POST'])
@permission_required('cert-approval')
def ecosystem_certification_approval_add():
    cert_id = flask.request.values.get('cert-id')
    db.approve_ecosystem_certification(cert_id, flask.g.email)
    db.add_log_entry(flask.g.email, f'Approve ecosystem certification {cert_id}')
    flask.flash(f'Successfully approved ecosystem certification with id {cert_id}', 'success')
    return flask.redirect(flask.url_for('ecosystem_certification_approval'))


@app.route('/ecosystem-certification/delete', methods=['POST'])
@login_required
def ecosystem_certification_delete():
    cert_id = flask.request.values.get('cert-id')
    db.delete_ecosystem_certification(cert_id)
    db.add_log_entry(flask.g.email, f'Delete ecosystem certification {cert_id}')
    flask.flash(f'Successfully deleted ecosystem certification with id {cert_id}', 'success')
    return flask.redirect(flask.url_for('ecosystem_certification'))


@app.route('/ecosystem-certification/document/<document_id>')
@login_required
def ecosystem_certification_document(document_id):
    document = db.get_ecosystem_certification_document(document_id)
    data = io.BytesIO(document.get('document_data'))
    filename = document.get('document_name')
    return flask.send_file(data, as_attachment=True, attachment_filename=filename)


@app.route('/elasticip', methods=['GET', 'POST'])
@login_required
def elasticip():
    idlist_str = flask.request.values.get('instance')
    region = 'us-west-2'
    for account in db.get_all_credentials_for_use('aws'):
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        aws.allocate_elasticip(idlist_str)
        instances_list = []
        idlist = aws.convert_instanceidstr_list(idlist_str)
        for i in idlist:
            result = aws.get_single_instance(region, i)
            instances_list.append(result)
    return flask.render_template('postdep.html', idlist=idlist_str, instance=instances_list)


@app.route('/environment-usage-events', methods=['POST'])
def environment_usage_events():
    request_secret = flask.request.values.get('secret')
    if request_secret == config.secret_key:
        params = {
            'environment_name': flask.request.values.get('environment_name'),
            'event_name': flask.request.values.get('event_name'),
            'user_name': flask.request.values.get('user_name')
        }
        db.add_environment_usage_event(params)
        return 'OK'
    flask.abort(403)


@app.route('/environments')
@login_required
def environments():
    flask.g.environments = ops_web.util.human_time.add_running_time_human(db.get_environments())
    return flask.render_template('environments/index.html')


@app.route('/environments/<environment>')
@login_required
def environment_detail(environment):
    app.logger.debug(f'Getting information for environment {environment!r}')
    flask.g.environment = environment
    _machines = db.get_machines_for_env(flask.g.email, environment)
    flask.g.machines = ops_web.util.human_time.add_running_time_human(_machines)
    flask.g.environments = db.get_env_list()
    flask.g.today = datetime.date.today()
    flask.g.machine_state_class_map = {
        'running': 'text-success',
        'starting': 'text-warning',
        'stopped': 'text-danger',
        'stopping': 'text-warning',
        'terminated': 'text-muted',
        'terminating': 'text-muted'
    }
    return flask.render_template('environments/detail.html')


@app.route('/environments/<environment>/delete', methods=['POST'])
@login_required
def environment_delete(environment):
    app.logger.info(f'Got a request from {flask.g.email} to delete machines in environment {environment!r}')
    machines = db.get_machines_for_env(flask.g.email, environment)
    for machine in machines:
        machine_id = machine.get('id')
        if machine.get('can_modify'):
            cloud = machine.get('cloud')
            if cloud == 'gcp':
                return flask.render_template('500.html', error="Cannot terminate GCP Instances")
            else:
                db.add_log_entry(flask.g.email, f'Delete machine {machine_id}')
                db.set_machine_state(machine_id, 'terminating')
                scheduler.add_job(delete_machine, args=[machine_id])
        else:
            app.logger.warning(f'{flask.g.email} does not have permission to delete machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=environment))


@app.route('/environments/<environment>/start', methods=['POST'])
@login_required
def environment_start(environment):
    app.logger.info(f'Got a request from {flask.g.email} to start machines in environment {environment!r}')
    machines = db.get_machines_for_env(flask.g.email, environment)
    app.logger.info(machines)
    for machine in machines:
        machine_id = machine.get('id')
        if machine.get('can_control'):
            cloud = machine.get('cloud')
            db.add_log_entry(flask.g.email, f'Start machine {machine_id}')
            db.set_machine_state(machine_id, 'starting')
            if cloud == 'gcp':
                start_machine(machine_id)
            else:
                scheduler.add_job(start_machine, args=[machine_id])
        else:
            app.logger.warning(f'{flask.g.email} does not have permission to start machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=environment))


@app.route('/environments/<environment>/stop', methods=['POST'])
@login_required
def environment_stop(environment):
    app.logger.info(f'Got a request from {flask.g.email} to stop machines in environment {environment!r}')
    machines = db.get_machines_for_env(flask.g.email, environment)
    for machine in machines:
        machine_id = machine.get('id')
        if machine.get('can_control'):
            machine_id = machine.get('id')
            cloud = machine.get('cloud')
            db.add_log_entry(flask.g.email, f'Stop machine {machine_id}')
            db.set_machine_state(machine_id, 'stopping')
            if cloud == 'gcp':
                stop_machine(machine_id)
            else:
                scheduler.add_job(stop_machine, args=[machine_id])
        else:
            app.logger.warning(f'{flask.g.email} does not have permission to stop machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=environment))


@app.route('/excel_sheet', methods=['GET', 'POST'])
@login_required
def excel_sheet():
    idlist = flask.request.values.get('instance')
    app.logger.info(idlist)
    for account in db.get_all_credentials_for_use('aws'):
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        idlist2 = aws.convert_instanceidstr_list(idlist)
        app.logger.info(idlist2)
        instance_list = []
        valdir = {}
        for i in idlist2:

            instance_info = aws.get_single_instance('us-west-2', i)
            instance_name = instance_info['name']
            instance_ip = instance_info['public_ip']

            app.logger.info(instance_name)
            if "Windows" in instance_name:
                valdir[instance_name] = instance_ip
                instance_list.append(valdir)
            app.logger.info(valdir)
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})
        worksheet = workbook.add_worksheet()

        headers = ['Instance name', 'Public IP']
        worksheet.write_row(0, 0, headers)
        row = 0
        col = 0

        for key in valdir.keys():
            row = row + 1
            worksheet.write(row, col, key)
            worksheet.write(row, col + 1, valdir[key])

        workbook.close()
        response = flask.make_response(output.getvalue())
        response.headers['Content-Disposition'] = 'attachment; filename="workshop_CDW.csv"'
        response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
        return response


@app.route('/external-links')
@login_required
def external_links():
    flask.g.external_links = db.get_external_links()
    return flask.render_template('external-links.html')


@app.route('/external-links/add', methods=['POST'])
@permission_required('admin')
def external_links_add():
    url = flask.request.values.get('url')
    title = flask.request.values.get('title')
    description = flask.request.values.get('description')
    db.add_external_link(url, title, description)
    db.add_log_entry(flask.g.email, f'Added an external link with title {title}')
    flask.flash(f'Successfully added a new external link, {title!r}', 'success')
    return flask.redirect(flask.url_for('external_links'))


@app.route('/external-links/delete', methods=['POST'])
@permission_required('admin')
def external_links_delete():
    link_id = flask.request.values.get('link-id')
    db.delete_external_link(link_id)
    db.add_log_entry(flask.g.email, f'Deleted an external link with id {link_id}')
    flask.flash('Successfully deleted an external link', 'success')
    return flask.redirect(flask.url_for('external_links'))


@app.route('/images')
@login_required
def images():
    flask.g.images = db.get_images(flask.g.email)
    flask.g.environments = db.get_env_list()
    username = flask.g.email.split('@')[0]
    flask.g.default_environment = f'{username}-{datetime.datetime.utcnow():%Y%m%d-%H%M%S}'
    return flask.render_template('images/index.html')


@app.route('/images/create', methods=['POST'])
@login_required
def images_create():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to create an image from {machine_id}')
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_modify'):
        db.add_log_entry(flask.g.email, f'Create image from machine {machine_id}')
        cloud = flask.request.values.get('cloud')
        region = flask.request.values.get('region')
        name = flask.request.values.get('image-name')
        owner = flask.request.values.get('owner').lower()
        public = 'public' in flask.request.values
        business_unit = flask.request.values.get('business-unit', '')
        application_env = flask.request.values.get('application-env', '')
        application_role = flask.request.values.get('application-role', '')
        if cloud == 'az':
            app.logger.warning(f'Unable to create images for cloud {cloud}')
            environment = flask.request.values.get('environment')
            return flask.redirect(flask.url_for('environment_detail', environment=environment))
        elif cloud == 'aws':
            account = db.get_one_credential_for_use(machine.get('account_id'))
            aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
            image_id = aws.create_image(region, machine_id, name, owner, public, business_unit, application_env,
                                        application_role)
            params = {
                'id': image_id,
                'cloud': cloud,
                'region': region,
                'name': name,
                'owner': owner,
                'public': public,
                'state': 'pending',
                'created': datetime.datetime.utcnow(),
                'instanceid': machine_id,
                'account_id': machine.get('account_id'),
                'cost': decimal.Decimal('0'),
                'business_unit': flask.request.values.get('business-unit', ''),
                'application_env': flask.request.values.get('application-env', ''),
                'application_role': flask.request.values.get('application-role', '')
            }
            db.add_image(params)
            return flask.redirect(flask.url_for('images'))
        elif cloud == 'gcp':
            ops_web.gcp.create_machine_image(machine.get('name'), machine.get('region'), name)
            app.logger.info(name)
            params = {
                'id': 'pending',
                'cloud': cloud,
                'region': machine.get('region'),
                'name': name,
                'state': 'pending',
                'created': datetime.datetime.utcnow(),
                'instanceid': machine.get('id'),
                'account_id': None,
                'owner': owner,
                'public': public,
                'cost': decimal.Decimal('0')
            }
            db.add_image(params)
            return flask.redirect(flask.url_for('images'))

    else:
        app.logger.warning(f'{flask.g.email} does not have permission to create an image from {machine_id}')
        return flask.redirect(flask.url_for('environment_detail', environment=machine.get('env_group')))


@app.route('/images/delete', methods=['POST'])
@login_required
def images_delete():
    settings: ops_web.db.Settings = flask.g.settings
    image_id = flask.request.values.get('image-id')
    next_view = flask.request.values.get('next-view')
    app.logger.info(f'Got a request from {flask.g.email} to delete image {image_id}')

    image = db.get_image(image_id)
    if image is None:
        flask.flash(f'Could not find image with id {image_id}', 'warning')
        return flask.redirect(flask.url_for(next_view))

    image_name = image.get('name')
    owner = image.get('owner')

    if 'admin' in flask.g.permissions or (settings.allow_users_to_delete_images and owner == flask.g.email):
        db.add_log_entry(flask.g.email, f'Delete image {image_id}')
        db.set_image_state(image_id, 'deleting')
        if image is None:
            flask.flash(f'Could not find image with id {image_id}', 'warning')
        else:
            account = db.get_one_credential_for_use(image.get('account_id'))
            cloud = image.get('cloud')
            if cloud == 'aws':
                aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
                region = image.get('region')
                aws.delete_image(region, image_id)
                flask.flash(f'Successfully deleted image {image_name}', 'success')
    elif owner == flask.g.email:
        db.add_log_entry(flask.g.email, f'Request deletion of image {image_id}')
        db.set_image_delete_requested(image_id)
        flask.flash(f'Your request to delete the image {image_name} was successful', 'success')
    else:
        flask.flash(f'You do not have permission to request deletion of the image {image_name}', 'warning')
    return flask.redirect(flask.url_for(next_view))


@app.route('/images/edit', methods=['POST'])
@login_required
def images_edit():
    image_id = flask.request.values.get('image-id')
    app.logger.info(f'Got a request from {flask.g.email} to edit image {image_id}')
    image = db.get_image(image_id)
    if 'admin' in flask.g.permissions or image.get('owner') == flask.g.email:
        db.add_log_entry(flask.g.email, f'Update tags on image {image_id}')
        image_name = flask.request.values.get('image-name')
        owner = flask.request.values.get('owner').lower()
        application_env = flask.request.values.get('application-env', '')
        application_role = flask.request.values.get('application-role', '')
        business_unit = flask.request.values.get('business-unit', '')
        public = 'public' in flask.request.values
        params = {
            'id': image_id,
            'name': image_name,
            'owner': owner,
            'application_env': application_env,
            'application_role': application_role,
            'business_unit': business_unit,
            'public': public
        }
        db.set_image_tags(params)
        tags = {
            'NAME': image_name,
            'OWNEREMAIL': owner,
            'APPLICATIONENV': application_env,
            'APPLICATIONROLE': application_role,
            'BUSINESSUNIT': business_unit,
            'image_public': str(public)
        }
        cloud = image.get('cloud')
        account = db.get_one_credential_for_use(image.get('account_id'))
        if cloud == 'aws':
            aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
            region = image.get('region')
            aws.update_resource_tags(region, image_id, tags)
        elif cloud == 'az':
            az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                     account.get('azure_tenant_id'))
            az.update_image_tags(image_id, tags)
        flask.flash(f'Successfully updated image {image_name}', 'success')
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to edit {image_id}')
        flask.flash('You do not have permission to edit this image', 'danger')
    return flask.redirect(flask.url_for('images'))


@app.route('/images/restore', methods=['POST'])
@permission_required('admin')
def images_restore():
    image_id = flask.request.values.get('image-id')
    image_name = flask.request.values.get('image-name')
    next_view = flask.request.values.get('next-view')
    db.add_log_entry(flask.g.email, f'Restore image {image_id}')
    db.set_image_delete_requested(image_id, False)
    flask.flash(f'Image {image_name} as been restored', 'success')
    return flask.redirect(flask.url_for(next_view))


@app.route('/images/trash')
@permission_required('admin')
def images_trash():
    flask.g.images = db.get_images_to_delete()
    return flask.render_template('images/trash.html')


@app.route('/launch', methods=['GET', 'POST'])
@login_required
def launch():
    ws_details = flask.request.values.get('id')
    security_group = flask.request.values.get('security_groups')
    quantity = flask.request.values.get('quantity')
    event_type = flask.request.values.get('event_type')
    customer = flask.request.values.get('customer')
    owner_email = flask.request.values.get('owner_email').lower()
    env_role = flask.request.values.get('env')
    subnet = flask.request.values.get('subnet')
    whitelist = flask.request.values.get('whitelist')
    app.logger.info(whitelist)
    region = 'us-west-2'

    infodict = {
        "securitygrp": security_group,
        "quantity": quantity,
        "eventtype": event_type,
        "customer": customer,
        "owneremail": owner_email,
        "envrole": env_role,
        "subnet": subnet,
        "whitelist": whitelist
    }

    for account in db.get_all_credentials_for_use('aws'):
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        idlist = aws.create_instances(ws_details, infodict)
        instanceslist = []
        instanceidlist = []
        for i in idlist:
            result = aws.get_single_instance(region, i)
            state = aws.get_instance_attr(region, i, 'state')
            idlist2 = result['id']
            instanceslist.append(result)
            instanceidlist.append(idlist2)
            result['account_id'] = account.get('id')
            while state['Name'] == 'pending':
                state = aws.get_instance_attr(region, i, 'state')
                if state['Name'] == 'running':
                    break
            db.add_machine(result)
        return flask.render_template('postdep.html', instance=instanceslist, idlist=instanceidlist)


@app.route('/machines/create', methods=['POST'])
@login_required
def machine_create():
    image_id = flask.request.values.get('image-id')
    app.logger.info(f'Got a request from {flask.g.email} to create machine from image {image_id}')
    image = db.get_image(image_id)
    if 'admin' in flask.g.permissions or image.get('public') or image.get('owner') == flask.g.email:
        db.add_log_entry(flask.g.email, f'Create machine from image {image_id}')
        region = image.get('region')
        instance_id = image.get('instanceid')
        name = flask.request.values.get('name')
        owner = flask.request.values.get('owner').lower()
        cloud = image.get('cloud')
        environment = flask.request.values.get('environment')
        if cloud == 'gcp':
            instance = ops_web.gcp.create_instance(region, name, image.get('name'), environment, owner)
            db.add_machine(instance)
            return flask.redirect(flask.url_for('environment_detail', environment=environment))
        else:
            vpc = flask.request.values.get('vpc')
            account = db.get_one_credential_for_use(image.get('account_id'))
            aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
            if instance_id == '':
                return flask.render_template('Default_launchinstance.html', region=region, image_id=image_id, name=name,
                                             owner=owner, environment=environment, vpc=vpc)
            else:
                if vpc == 'Default':
                    response = aws.create_instance(region, image_id, instance_id, name, owner, environment, '')
                    if response == 'Unsuccessful':

                        return flask.render_template('Default_launchinstance.html', region=region, image_id=image_id,
                                                     name=name,
                                                     owner=owner, environment=environment, vpc=vpc)
                    elif response == 'launch_error':
                        return flask.render_template('500.html', error = "Error while creating the instance")

                    else:
                        instance = aws.get_single_instance(region, response[0].id)
                        instance['account_id'] = account.get('id')
                        db.add_machine(instance)
                        return flask.redirect(flask.url_for('environment_detail', environment=environment))

                elif vpc == 'MdmDemo':
                    response = aws.create_instance(region, image_id, instance_id, name, owner, environment, 'mdmdemo')
                    if response == 'Unsuccessful':
                        response = aws.create_instance_defaultspecs(region, image_id, name, owner, environment,
                                                                    'mdmdemo')
                        instance = aws.get_single_instance(region, response[0].id)
                        instance['account_id'] = account.get('id')
                        db.add_machine(instance)
                        return flask.redirect(flask.url_for('environment_detail', environment=environment))
                    else:
                        instance = aws.get_single_instance(region, response[0].id)
                        instance['account_id'] = account.get('id')
                        db.add_machine(instance)
                        return flask.redirect(flask.url_for('environment_detail', environment=environment))

                elif vpc == 'PresalesDemo':
                    response = aws.create_instance(region, image_id, instance_id, name, owner, environment,
                                                   'presalesdemo')
                    app.logger.info(response)
                    if response == 'Unsuccessful':
                        response = aws.create_instance_defaultspecs(region, image_id, name, owner, environment,
                                                                    'presalesdemo')
                        instance = aws.get_single_instance(region, response[0].id)
                        instance['account_id'] = account.get('id')
                        db.add_machine(instance)
                        return flask.redirect(flask.url_for('environment_detail', environment=environment))
                    else:
                        instance = aws.get_single_instance(region, response[0].id)
                        instance['account_id'] = account.get('id')
                        db.add_machine(instance)
                        return flask.redirect(flask.url_for('environment_detail', environment=environment))
                else:
                    pass

    else:
        app.logger.warning(f'{flask.g.email} does not have permission to create machine from image {image_id}')
        return flask.redirect(flask.url_for('images'))


@app.route('/machines/create/launchmachine_default_specs', methods=['POST', 'GET'])
@login_required
def launchmachine_default_specs():
    image_id = flask.request.values.get('image_id')
    app.logger.info(image_id)
    owner = flask.request.values.get('owner').lower()
    name = flask.request.values.get('name')
    region = flask.request.values.get('region')
    environment = flask.request.values.get('environment')

    for account in db.get_all_credentials_for_use('aws'):
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        response = aws.create_instance_defaultspecs(region, image_id, name, owner, environment, 'default')
        app.logger.info(response[0])
        instance = aws.get_single_instance(region, response[0].id)
        instance['account_id'] = account.get('id')
        db.add_machine(instance)
        return flask.redirect(flask.url_for('environment_detail', environment=environment))


@app.route('/machines/delete', methods=['POST'])
@login_required
def machine_delete():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to delete machine {machine_id}')
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_modify'):
        cloud = machine.get('cloud')
        if cloud == 'gcp':
            return flask.render_template('500.html', error="Cannot terminate GCP Instances")
        else:
            db.add_log_entry(flask.g.email, f'Delete machine {machine_id}')
            db.set_machine_state(machine_id, 'terminating')
            scheduler.add_job(delete_machine, args=[machine_id])
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to delete machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=machine.get('env_group')))


@app.route('/machines/edit', methods=['POST'])
@login_required
def machine_edit():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to edit machine {machine_id}')
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_modify'):
        db.add_log_entry(flask.g.email, f'Update tags on machine {machine_id}')
        db.set_machine_tags({
            'application_env': flask.request.values.get('application-env'),
            'application_role': flask.request.values.get('application-role'),
            'business_unit': flask.request.values.get('business-unit'),
            'contributors': flask.request.values.get('contributors'),
            'environment': flask.request.values.get('environment'),
            'id': machine_id,
            'name': flask.request.values.get('machine-name'),
            'owner': flask.request.values.get('owner').lower(),
            'running_schedule': flask.request.values.get('running-schedule'),
            'dns_names': flask.request.values.get('dns-names')
        })
        cloud = machine.get('cloud')
        app.logger.info(cloud)
        if cloud == 'gcp':
            contributor_tag = flask.request.values.get('contributors').replace("@informatica.com", '-')
            contributor = contributor_tag.replace(' ', '')

            tags = {
                'applicationenv': flask.request.values.get('application-env'),
                'applicationrole': flask.request.values.get('application-role'),
                'business_unit': flask.request.values.get('business-unit'),
                'contributors': contributor,
                'machine__environment_group': flask.request.values.get('environment'),
                'image__dns_names_private': '',
                'name': flask.request.values.get('machine-name'),
                'owneremail': flask.request.values.get('owner').split('@')[0],
                'running_schedule': ''
            }

        else:
            tags = {
                'APPLICATIONENV': flask.request.values.get('application-env'),
                'APPLICATIONROLE': flask.request.values.get('application-role'),
                'BUSINESSUNIT': flask.request.values.get('business-unit'),
                'CONTRIBUTORS': flask.request.values.get('contributors'),
                'machine__environment_group': flask.request.values.get('environment'),
                'image__dns_names_private': flask.request.values.get('dns-names'),
                'NAME': flask.request.values.get('machine-name'),
                'OWNEREMAIL': flask.request.values.get('owner').lower(),
                'RUNNINGSCHEDULE': flask.request.values.get('running-schedule')
            }

        account = db.get_one_credential_for_use(machine.get('account_id'))
        if cloud == 'aws':
            aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
            region = machine.get('region')
            aws.update_resource_tags(region, machine_id, tags)
        elif cloud == 'az':
            az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                     account.get('azure_tenant_id'))
            az.update_machine_tags(machine_id, tags)
        elif cloud == 'gcp':
            zone = machine.get('region')
            ops_web.gcp.update_machine_tags(machine_id, zone, tags)
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to edit machine {machine_id}')
    environment = flask.request.values.get('environment')
    if environment:
        return flask.redirect(flask.url_for('environment_detail', environment=environment))
    return flask.redirect(flask.url_for('environments'))


@app.route('/machines/start', methods=['POST'])
@login_required
def machine_start():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to start machine {machine_id}')
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_control'):
        db.add_log_entry(flask.g.email, f'Start machine {machine_id}')
        db.set_machine_state(machine_id, 'starting')
        scheduler.add_job(start_machine, args=[machine_id])
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to start machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=machine.get('env_group')))


@app.route('/machines/stop', methods=['POST'])
@login_required
def machine_stop():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to stop machine {machine_id}')
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_control'):
        db.add_log_entry(flask.g.email, f'Stop machine {machine_id}')
        db.set_machine_state(machine_id, 'stopping')
        scheduler.add_job(stop_machine, args=[machine_id])
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to stop machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=machine.get('env_group')))


@app.route('/manager-toolbox')
@login_required
def manager_toolbox():
    flask.g.is_manager = db.is_manager(flask.g.email)
    return flask.render_template('manager-toolbox.html')


@app.route('/monolith')
def monolith():
    return flask.redirect(flask.url_for('monolith_request'))


@app.route('/monolith/request')
@login_required
def monolith_request():
    return flask.render_template('monolith-request.html')


@app.route('/monolith/request/submit', methods=['POST'])
@login_required
def monolith_request_submit():
    tc = ops_web.tasks.TaskContext(app, apm.client, config, db)
    scheduler.add_job(ops_web.tasks.create_zendesk_ticket, args=[tc, flask.g.email, flask.request.values])
    flask.flash('Thank you for submitting this request', 'success')
    return flask.redirect(flask.url_for('monolith_request'))


@app.route('/op-debrief')
@login_required
def op_debrief():
    flask.g.surveys = db.get_active_surveys(flask.g.email)
    return flask.render_template('op-debrief/index.html')


@app.route('/op-debrief/archive')
@login_required
def op_debrief_archive():
    flask.g.surveys = db.get_completed_surveys(flask.g.email)
    return flask.render_template('op-debrief/archive.html')


@app.route('/op-debrief/configure')
@permission_required('survey-admin')
def op_debrief_configure():
    flask.g.roles = db.get_roles()
    return flask.render_template('op-debrief/configure.html')


@app.route('/op-debrief/configure/roles', methods=['POST'])
@permission_required('survey-admin')
def op_debrief_configure_roles():
    selected_roles = flask.request.values.getlist('selected-roles')
    app.logger.debug(f'Selected roles: {selected_roles}')
    db.update_roles(selected_roles)
    return flask.redirect(flask.url_for('op_debrief_configure'))


@app.route('/op-debrief/<uuid:survey_id>', methods=['GET', 'POST'])
@login_required
def op_debrief_survey(survey_id: uuid.UUID):
    survey = db.get_survey(survey_id)
    if 'survey-admin' in flask.g.permissions or flask.g.email == survey.get('email'):
        if flask.request.method == 'GET':
            flask.g.survey = survey
            flask.g.close_contacts = flask.g.survey.get('close_contacts', '')
            if flask.g.close_contacts is None:
                flask.g.close_contacts = ''
            flask.g.close_contacts = flask.g.close_contacts.split()
            flask.g.op_contacts = db.get_op_contacts(survey.get('opportunity_number'))
            flask.g.template = ops_web.op_debrief_surveys.survey_template
            return flask.render_template('op-debrief/survey.html')
        elif flask.request.method == 'POST':
            for k, v in flask.request.form.lists():
                app.logger.debug(f'{k}: {v}')
            params = ops_web.op_debrief_surveys.convert_form_to_record(flask.request.form)
            params['survey_id'] = survey_id
            params['completed'] = datetime.datetime.utcnow()
            db.complete_survey(params)
            db.add_log_entry(flask.g.email, f'Completed opportunity debrief survey {survey_id}')
            return flask.redirect(flask.url_for('op_debrief_survey', survey_id=survey_id))

    # see if there is another survey for this opportunity for the signed-in user
    new_survey_id = db.search_for_survey(flask.g.email, survey.get('opportunity_number'))
    if new_survey_id is None:
        return flask.redirect(flask.url_for('op_debrief'))
    else:
        return flask.redirect(flask.url_for('op_debrief_survey', survey_id=new_survey_id))


@app.route('/op-debrief/<uuid:survey_id>/cancel')
@login_required
def op_debrief_survey_cancel(survey_id: uuid.UUID):
    survey = db.get_survey(survey_id)
    if 'survey-admin' in flask.g.permissions or flask.g.email == survey.get('email'):
        db.cancel_survey(survey_id)
        db.add_log_entry(flask.g.email, f'Cancelled opportunity debrief survey {survey_id}')
    return flask.redirect(flask.url_for('op_debrief_survey', survey_id=survey_id))


@app.route('/rep-sc-pairs')
def rep_sc_pairs_redirect():
    return flask.redirect(flask.url_for('sc_assignments_sales_reps'))


@app.route('/rep-sc-pairs.xlsx')
def rep_sc_pairs_xlsx_redirect():
    return flask.redirect(flask.url_for('sc_assignments_sales_reps_xlsx'))


@app.route('/sap_access', methods=['GET', 'POST'])
@login_required
def sap_access():
    flask.g.environments = ops_web.util.human_time.add_running_time_human(db.get_own_environments(flask.g.email))
    return flask.render_template('sap-access.html')


@app.route('/sap_access/<environment>')
@login_required
def sap_access_detail(environment):
    app.logger.debug(f'Getting information for environment {environment!r}')
    flask.g.environment = environment
    _machines = db.get_machines_for_env(flask.g.email, environment)
    flask.g.machines = ops_web.util.human_time.add_running_time_human(_machines)
    flask.g.environments = db.get_env_list()
    flask.g.today = datetime.date.today()
    return flask.render_template('sap_access_detail.html')


@app.route('/sap_access/<environment>/attach_sap_sg', methods=['GET', 'POST'])
@login_required
def attach_sap_sg(environment):
    app.logger.info(f'Got a request from {flask.g.email} to give SAP access to {environment}')
    machines = db.get_machines_for_env(flask.g.email, environment)
    final_result = []
    for machine in machines:
        app.logger.info(machine.get('id'))
        region = machine.get('region')
        machine_id = machine.get('id')
        vpc = machine.get('vpc')
        account = db.get_one_credential_for_use(machine.get('account_id'))
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        app.logger.info(machine_id)
        result = aws.add_sap_sg(region, machine_id, vpc)
        final_result.append(result)
    if all(c == 'Successful' for c in final_result):
        return flask.redirect(flask.url_for('sap_access'))
    else:
        _error = ("Cannot give SAP Access to this environment. "
                  "Check if the instances already have access or if they are in the correct VPC.")
        return flask.render_template('500.html', error=_error)


@app.route('/sap_access/<environment>/detach_sap_sg', methods=['GET', 'POST'])
@login_required
def detach_sap_sg(environment):
    app.logger.info(f'Got a request from {flask.g.email} to remove SAP access from {environment}')
    machines = db.get_machines_for_env(flask.g.email, environment)
    final_result = []
    for machine in machines:
        region = machine.get('region')
        machine_id = machine.get('id')
        vpc = machine.get('vpc')
        account = db.get_one_credential_for_use(machine.get('account_id'))
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        app.logger.info(machine_id)
        result = aws.remove_sap_sg(region, machine_id, vpc)
        final_result.append(result)
    if all(c == 'Successful' for c in final_result):
        return flask.redirect(flask.url_for('sap_access'))
    else:
        return flask.render_template('500.html',
                                     error="Cannot remove SAP Access from this environment. Check if the Access has "
                                           "already been revoked")


@app.route('/sap_access/attach_sap_sg_machine', methods=['POST'])
@login_required
def attach_sap_sg_machine():
    machine_id = flask.request.values.get('machine-id')
    environment = flask.request.values.get('environment')
    app.logger.info(f'Got a request from {flask.g.email} to give SAP access to {machine_id}')
    machine = db.get_machine(machine_id, flask.g.email)
    region = machine.get('region')
    vpc = machine.get('vpc')
    account = db.get_one_credential_for_use(machine.get('account_id'))
    aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
    result = aws.add_sap_sg(region, machine_id, vpc)
    if result == "Successful":
        return flask.redirect(flask.url_for('sap_access_detail', environment=environment))
    else:
        return flask.render_template('500.html',
                                     error="Cannot give SAP Access to this instance. Check if the instance already has access or if it is in the correct vpc")


@app.route('/sap_access/detach_sap_sg_machine', methods=['POST'])
@login_required
def detach_sap_sg_machine():
    machine_id = flask.request.values.get('machine-id')
    environment = flask.request.values.get('environment')
    app.logger.info(f'Got a request from {flask.g.email} to remove SAP access from {machine_id}')
    machine_id = flask.request.values.get('machine-id')
    machine = db.get_machine(machine_id, flask.g.email)
    region = machine.get('region')
    machine_id = machine.get('id')
    vpc = machine.get('vpc')
    account = db.get_one_credential_for_use(machine.get('account_id'))
    aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
    app.logger.info(machine_id)
    result = aws.remove_sap_sg(region, machine_id, vpc)
    if result == "Successful":
        return flask.redirect(flask.url_for('sap_access_detail', environment=environment))
    else:
        return flask.render_template('500.html',
                                     error="Cannot remove SAP Access from this instance. Check if the Access has already been revoked")


@app.route('/sc-assignments/regional-advisors')
@login_required
def sc_assignments_regional_advisors():
    flask.g.assignments = db.get_sc_ra_assignments()
    flask.g.regional_advisors = db.get_regional_advisors()
    return flask.render_template('sc-assignments/regional-advisors.html')


@app.route('/sc-assignments/regional-advisors/edit', methods=['POST'])
@permission_required('sc-assignments')
def sc_assignments_regional_advisors_edit():
    sc_employee_id = flask.request.values.get('sc-employee-id')
    ra_employee_id = flask.request.values.get('ra-employee-id')
    if ra_employee_id == 'none':
        ra_employee_id = None
    db.set_sc_ra_assignment(sc_employee_id, ra_employee_id)
    db.add_log_entry(flask.g.email, f'Update SC assignment to regional advisor: {sc_employee_id} / {ra_employee_id}')
    return flask.redirect(flask.url_for('sc_assignments_regional_advisors'))


@app.route('/sc-assignments/sales-reps')
@login_required
def sc_assignments_sales_reps():
    flask.g.sales_reps = db.get_rep_sc_pairs()
    flask.g.sales_consultants = db.get_sales_consultants()
    return flask.render_template('sc-assignments/sales-reps.html')


@app.route('/sc-assignments/sales-reps/edit', methods=['POST'])
@permission_required('sc-assignments')
def sc_assignments_sales_reps_edit():
    territory_name = flask.request.values.get('territory_name')
    sc_employee_id = flask.request.values.get('sc_employee_id')
    app.logger.debug(f'sc assignment territory: {territory_name}, employee_id: {sc_employee_id}')
    db.add_log_entry(flask.g.email, f'Update SC assignment to sales rep: {territory_name} / {sc_employee_id}')
    if sc_employee_id == 'none':
        sc_employee_id = None
    db.set_rep_sc_pair(territory_name, sc_employee_id)
    return flask.redirect(flask.url_for('sc_assignments_sales_reps'))


@app.route('/sc-assignments/sales-reps.xlsx')
@login_required
def sc_assignments_sales_reps_xlsx():
    records = db.get_rep_sc_pairs()
    filter_input = flask.request.values.get('filter-input')
    if filter_input is not None:
        def matches_filter(record):
            return filter_input in record['filter_value']

        records = filter(matches_filter, records)
    output = io.BytesIO()
    workbook = xlsxwriter.Workbook(output, {'in_memory': True})
    worksheet = workbook.add_worksheet()
    headers = ['Geo', 'Area', 'Sub-Area', 'Region', 'Sub-Region', 'Territory Name', 'Sales Rep', 'Sales Consultant']
    worksheet.write_row(0, 0, headers)
    for i, r in enumerate(records, start=1):
        worksheet.write_string(i, 0, r['geo'])
        worksheet.write_string(i, 1, r['area'])
        worksheet.write_string(i, 2, r['sub_area'])
        worksheet.write_string(i, 3, r['region'])
        worksheet.write_string(i, 4, r['sub_region'])
        worksheet.write_string(i, 5, r['territory_name'])
        worksheet.write_string(i, 6, r['rep_name'])
        worksheet.write_string(i, 7, r['sc_name'])
    workbook.close()
    response = flask.make_response(output.getvalue())
    response.headers['Content-Disposition'] = 'attachment; filename="rep-sc-pairs.xlsx"'
    response.headers['Content-Type'] = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    return response


@app.route('/sc-competency')
@login_required
def sc_competency():
    flask.g.employees = db.get_employees_for_manager(flask.g.email)
    return flask.render_template('sc-competency.html')


@app.route('/sc-competency/scores/add', methods=['POST'])
@login_required
def sc_competency_scores_add():
    for name, value in flask.request.values.lists():
        app.logger.debug(f'{name}: {value}')
    if 'sc-employee-id' in flask.request.values:
        sc_employee_id = flask.request.values.get('sc-employee-id')
        params = {
            'sc_employee_id': sc_employee_id,
            'technical_acumen': int(flask.request.values.get('technical-acumen')),
            'domain_knowledge': int(flask.request.values.get('domain-knowledge')),
            'discovery_and_qualification': int(flask.request.values.get('discovery-and-qualification')),
            'teamwork_and_collaboration': int(flask.request.values.get('teamwork-and-collaboration')),
            'leadership_skills': int(flask.request.values.get('leadership-skills')),
            'communication': int(flask.request.values.get('communication')),
            'planning_and_prioritization': int(flask.request.values.get('planning-and-prioritization')),
            'customer_advocacy': int(flask.request.values.get('customer-advocacy')),
            'attitude': int(flask.request.values.get('attitude')),
            'corporate_citizenship': int(flask.request.values.get('corporate-citizenship'))
        }
        db.add_sc_competency_score(params)
        db.add_log_entry(flask.g.email, f'Add SC competency score for {sc_employee_id}')
        flask.flash('SC competency score added successfully.', 'success')
    else:
        flask.flash('Please choose an SC.', 'danger')
    return flask.redirect(flask.url_for('sc_competency'))


@app.route('/security-groups')
@login_required
def security_groups():
    flask.g.sg = db.get_security_groups(flask.g.email)
    return flask.render_template('security-groups.html')


@app.route('/security-groups/add-rule', methods=['POST'])
@login_required
def security_groups_add_rule():
    cloud = flask.request.values.get('cloud')
    region = flask.request.values.get('region')
    sg_id = flask.request.values.get('security-group-id')
    ip = flask.request.values.get('new-ip-address')
    description = flask.request.values.get('description')

    redir = flask.redirect(flask.url_for('security_groups'))
    if not db.can_modify_security_group(flask.g.email, sg_id):
        flask.flash('You do not have permission to modify this security group.', 'danger')
        return redir
    if '/' in ip:
        ip = ip.split('/')[0]
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        flask.flash(f'{ip!r} does not appear to be a valid IP address.', 'danger')
        return redir
    if ip.startswith('0.0.0.0'):
        flask.flash(f'You can\'t add this IP address: {ip}', 'danger')
        return redir
    if ip.startswith('10.') or ip.startswith('192.168.'):
        flask.flash(f'You can\'t add this internal IP address: {ip}', 'danger')
        return redir

    app.logger.info(f'Adding IP address {ip} to {sg_id}')
    db.add_log_entry(flask.g.email, f'Add IP address {ip} to {sg_id}')
    sg = db.get_security_group(sg_id)
    account = db.get_one_credential_for_use(sg.get('account_id'))
    aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
    result = aws.add_security_group_rule(region, sg_id, ip, description)
    if result == 'successful':
        flask.flash(f'Successfully added {ip} to {sg_id}', 'success')
        params = {
            'sg_id': sg_id,
            'ip_range': f'{ip}/32',
            'cloud': cloud,
            'description': description
        }
        db.add_security_group_rule(params)
    else:
        flask.flash(f'Error adding {ip}: {result}', 'danger')

    return redir


@app.route('/security-groups/delete-rule', methods=['POST'])
@login_required
def security_groups_delete_rule():
    redir = flask.redirect(flask.url_for('security_groups'))
    group_id = flask.request.values.get('security-group-id')
    ip_range = flask.request.values.get('ip-range')
    region = flask.request.values.get('region')
    if not db.can_modify_security_group(flask.g.email, group_id):
        flask.flash('You do not have permission to modify this security group.', 'danger')
        return redir

    app.logger.debug(f'Removing IP address range {ip_range} from {group_id}')
    security_group = db.get_security_group(group_id)
    account = db.get_one_credential_for_use(security_group.get('account_id'))
    aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
    aws.delete_security_group_rule(region, group_id, ip_range)
    db.delete_security_group_rule(group_id, ip_range)
    return redir


@app.route('/sign-in')
def sign_in():
    state = str(uuid.uuid4())
    flask.session['state'] = state
    nonce = str(uuid.uuid4())
    flask.session['nonce'] = nonce
    redirect_uri = flask.url_for('authorize', _external=True)
    app.logger.debug(f'redirect_uri: {redirect_uri}')
    query = {
        'client_id': config.az_client_id,
        'nonce': nonce,
        'redirect_uri': redirect_uri,
        'response_mode': 'form_post',
        'response_type': 'id_token',
        'scope': 'email openid',
        'state': state,
    }
    authorization_url = f'{config.az_auth_endpoint}?{urllib.parse.urlencode(query)}'
    app.logger.debug(f'Redirecting to {authorization_url}')
    return flask.redirect(authorization_url, 307)


@app.route('/sign-out')
def sign_out():
    flask.session.pop('email', None)
    return flask.redirect(flask.url_for('index'))


@app.route('/sync-info')
@login_required
def sync_info():
    sync_data = db.get_sync_data()
    flask.g.sync_data = sync_data
    if sync_data['last_sync_start'] is None:
        flask.g.sync_start_human = 'never'
    else:
        flask.g.sync_start_human = pendulum.instance(sync_data['last_sync_start']).diff_for_humans()
    if not sync_data['syncing_now']:
        if sync_data['last_sync_end'] is None:
            flask.g.sync_end_human = 'never'
        else:
            flask.g.sync_end_human = pendulum.instance(sync_data['last_sync_end']).diff_for_humans()
    return flask.render_template('sync-info.html')


@app.route('/sync-now', methods=['POST'])
@permission_required('admin')
def sync_now():
    db.add_log_entry(flask.g.email, 'Manual sync')
    scheduler.add_job(sync_machines)
    return flask.redirect(flask.url_for('sync_info'))


@app.route('/synchosts', methods=['GET', 'POST'])
@login_required
def synchosts():
    idliststr = flask.request.values.get('instance')
    region = 'us-west-2'
    for account in db.get_all_credentials_for_use('aws'):
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        result = aws.sync_hosts(idliststr)
        idlist = aws.convert_instanceidstr_list(idliststr)
        instanceslist = []
        for i in idlist:
            instance = aws.get_single_instance(region, i)
            instanceslist.append(instance)
        if result is None:
            return flask.render_template('postdep.html', idlist=idlist, instance=instanceslist)
        else:
            return flask.render_template('500.html', error=result)


@app.route('/synchosts_az', methods=['GET', 'POST'])
@login_required
def synchosts_az():
    app.logger.info("entered in for updating hosts")
    idliststr = flask.request.values.get('instance')
    instance_info = flask.request.values.get('instance_info')
    id_list = idliststr
    id_list2 = id_list[1:]
    id_list3 = id_list2[:-1]
    id_list4 = id_list3[1:]
    id_list5 = id_list4[:-1]
    id_list6 = id_list5.replace("\'", "")
    id_list8 = id_list6.replace(' ', '')
    id_list7 = id_list8.split(',')
    app.logger.info(instance_info)
    instance_info2 = []
    for account in db.get_all_credentials_for_use('az'):
        az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                 account.get('azure_tenant_id'))
        app.logger.info(idliststr)
        if '104' in idliststr:
            app.logger.info("found new cdw image")
            result = az.sync_hosts_104(idliststr)
        else:
            result = az.sync_hosts(idliststr)
        for i in id_list7:
            i = "'" + i + "'"
            instance_info2.append(az.get_virtualmachine_info(i, 'rg-cdw-workshops-201904'))

        return flask.render_template('postdep_az.html', instance=instance_info2, idlist=id_list7)


@app.route('/toolbox')
@permission_required('admin')
def toolbox():
    return flask.render_template('toolbox.html')


@app.route('/workshop-tools')
@login_required
def workshop_tools():
    return flask.render_template('workshop_tools.html')


@app.route('/ws_postdep', methods=['GET', 'POST'])
@login_required
def ws_postdep():
    return flask.render_template('postdep.html')


@app.route('/ws_postdep_filter', methods=['GET', 'POST'])
@login_required
def ws_postdep_filter():
    env_group = flask.request.values.get("env_group_name")
    for account in db.get_all_credentials_for_use('aws'):
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        instance_list = aws.get_instance_of_envgrp(env_group)
        instances_list2 = []
        for i in instance_list:
            result = aws.get_single_instance('us-west-2', i)
            instances_list2.append(result)
        return flask.render_template('postdep.html', idlist=str(instance_list), instance=instances_list2)


@app.route('/wscreator')
@login_required
def wscreator():
    return flask.render_template('ws_creator.html')


@app.route('/wsimage', methods=['GET', 'POST'])
@login_required
def wsimage():
    ws = flask.request.values.get("ws")
    app.logger.info(ws)
    if (ws != 'CDW-AZ' and ws != 'CDW104-AZ'):
        for account in db.get_all_credentials_for_use('aws'):
            aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
            result = aws.workshop_images(ws)
            wslist = []
            wsidlist = []
            for i in result:
                wslist.append(i)
                wsidlist.append(i['id'])
        return flask.render_template('ws_creator.html', ws2=ws, ws=wslist, id=wsidlist)
    else:
        app.logger.info("entered in ops-web")
        app.logger.info(ws)
        return flask.render_template('ws_creator.html', ws2=ws, ws=['ami1'])


def delete_machine(machine_id):
    apm.client.begin_transaction('task')
    app.logger.info(f'Attempting to delete machine {machine_id}')
    machine = db.get_machine(machine_id)
    cloud = machine.get('cloud')
    account = db.get_one_credential_for_use(machine.get('account_id'))
    if cloud == 'aws':
        region = machine.get('region')
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        aws.delete_machine(region, machine_id)
    elif cloud == 'az':
        az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                 account.get('azure_tenant_id'))
        ops_web.az.delete_machine(az, machine_id)
    db.set_machine_public_ip(machine_id)
    db.set_machine_state(machine_id, 'terminated')
    apm.client.end_transaction('delete-machine')


def start_machine(machine_id):
    apm.client.begin_transaction('task')
    app.logger.info(f'Attempting to start machine {machine_id}')
    machine = db.get_machine(machine_id)
    cloud = machine.get('cloud')
    account = db.get_one_credential_for_use(machine.get('account_id'))
    if cloud == 'aws':
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        region = machine.get('region')
        instance = aws.start_machine(region, machine_id)
        app.logger.debug(f'Waiting for {machine_id} to be running')
        instance.wait_until_running()
        app.logger.debug(f'{machine_id} is now running')
        db.set_machine_state(machine_id, 'running')
        db.set_machine_public_ip(machine_id, instance.public_ip_address)
        db.set_machine_created(machine_id, instance.launch_time)
    elif cloud == 'az':
        az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                 account.get('azure_tenant_id'))
        az.start_machine(machine_id)
    elif cloud == 'gcp':
        zone = machine.get('region')
        app.logger.info(zone)
        ops_web.gcp.start_machine(machine_id, zone)
    apm.client.end_transaction('start-machine')


def stop_machine(machine_id):
    apm.client.begin_transaction('task')
    app.logger.info(f'Attempting to stop machine {machine_id}')
    machine = db.get_machine(machine_id)
    cloud = machine.get('cloud')
    account = db.get_one_credential_for_use(machine.get('account_id'))
    if cloud == 'aws':
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        region = machine.get('region')
        instance = aws.stop_machine(region, machine_id)
        app.logger.debug(f'Waiting for {machine_id} to be stopped')
        instance.wait_until_stopped()
        app.logger.debug(f'{machine_id} is now stopped')
        db.set_machine_state(machine_id, 'stopped')
        db.set_machine_public_ip(machine_id, instance.public_ip_address)
        db.set_machine_created(machine_id, instance.launch_time)
    elif cloud == 'az':
        az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                 account.get('azure_tenant_id'))
        az.stop_machine(machine_id)
    elif cloud == 'gcp':
        zone = machine.get('region')
        ops_web.gcp.stop_machine(machine_id, zone)
    apm.client.end_transaction('stop-machine')


def check_sync():
    apm.client.begin_transaction('task')
    app.logger.debug('Checking for a stuck sync ...')
    sync_data = db.get_sync_data()
    if sync_data['syncing_now']:
        now = datetime.datetime.utcnow()
        duration = now - sync_data['last_sync_start']
        if duration > datetime.timedelta(minutes=config.auto_sync_max_duration):
            app.logger.warning(f'Sync has been running for {duration}, aborting now ...')
            db.end_sync()
    apm.client.end_transaction('check-sync')


def sync_machines():
    apm.client.begin_transaction('task')
    app.logger.info('Syncing information from cloud providers now ...')

    sync_data = db.get_sync_data()
    if sync_data['syncing_now']:
        app.logger.warning('Aborting because there is another sync happening right now')
        return

    db.start_sync()
    sync_start = datetime.datetime.utcnow()

    aws_start = datetime.datetime.utcnow()
    if 'aws' in config.clouds_to_sync:
        db.pre_sync('aws')
        for account in db.get_all_credentials_for_use('aws'):
            aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
            try:
                for security_group in aws.get_all_security_groups():
                    security_group['account_id'] = account.get('id')
                    db.add_security_group(security_group)
                for instance in aws.get_all_instances():
                    instance['account_id'] = account.get('id')
                    if instance.get('environment') is None:
                        instance.update({'environment': account.get('default_environment_name')})
                    db.add_machine(instance)
                for image in aws.get_all_images():
                    image['account_id'] = account.get('id')
                    db.add_image(image)
            except Exception as e:
                apm.capture_exception()
                app.logger.exception(e)
        db.post_sync('aws')
        tc = ops_web.tasks.TaskContext(app, apm.client, config, db)
        scheduler.add_job(ops_web.tasks.update_termination_protection, args=[tc])
    else:
        app.logger.info(f'Skipping AWS because CLOUDS_TO_SYNC={config.clouds_to_sync}')
    aws_duration = datetime.datetime.utcnow() - aws_start

    az_start = datetime.datetime.utcnow()
    if 'az' in config.clouds_to_sync:
        db.pre_sync('az')
        for account in db.get_all_credentials_for_use('az'):
            az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                     account.get('azure_tenant_id'))
            for vm in az.get_all_virtual_machines():
                vm['account_id'] = account.get('id')
                if vm.get('environment') is None:
                    vm.update({'environment': account.get('default_environment_name')})
                db.add_machine(vm)
            for image in az.get_all_images():
                image['account_id'] = account.get('id')
                db.add_image(image)
        db.post_sync('az')
    else:
        app.logger.info(f'Skipping Azure because CLOUDS_TO_SYNC={config.clouds_to_sync}')
    az_duration = datetime.datetime.utcnow() - az_start

    gcp_start = datetime.datetime.utcnow()
    if 'gcp' in config.clouds_to_sync:
        db.pre_sync('gcp')
        for account in db.get_all_credentials_for_use('gcp'):
            gcp = ops_web.gcp.GCPClient(config, account.get('username'), account.get('password'))
            gcp.get_all_instances()
        # for vm in ops_web.gcp.get_all_virtual_machines():
        #     vm['account_id'] = None
        #     db.add_machine(vm)
        # for image in ops_web.gcp.get_all_images():
        #     image['account_id'] = None
        #     db.add_image(image)
        db.post_sync('gcp')
    else:
        app.logger.info(f'Skipping GCP because CLOUDS_TO_SYNC={config.clouds_to_sync}')
    gcp_duration = datetime.datetime.utcnow() - gcp_start

    sync_duration = datetime.datetime.utcnow() - sync_start
    app.logger.info(f'Done syncing virtual machines / '
                    f'AWS {aws_duration} / Azure {az_duration} / GCP {gcp_duration} / total {sync_duration}')
    db.end_sync()
    apm.client.end_transaction('sync-machines')


def run_tasks():
    app.logger.debug('Checking for tasks to run...')

    tasks = {
        'check-for-images-to-delete': {
            'default-active': True,
            'function': ops_web.tasks.check_for_images_to_delete,
            'interval': datetime.timedelta(days=1)
        },
        'get-cost-data': {
            'default-active': True,
            'function': ops_web.tasks.get_cost_data,
            'interval': datetime.timedelta(days=1)
        },
        'op-debrief-surveys-generate': {
            'default-active': False,
            'function': ops_web.op_debrief_surveys.generate,
            'interval': datetime.timedelta(hours=6)
        },
        'op-debrief-surveys-remind': {
            'default-active': False,
            'function': ops_web.op_debrief_surveys.remind,
            'interval': datetime.timedelta(days=1)
        }
    }

    db_tasks = [t.get('task_name') for t in db.get_scheduled_tasks()]

    for task_name in tasks:
        if task_name not in db_tasks:
            task_interval = tasks.get(task_name).get('interval')
            task_active = tasks.get(task_name).get('default-active')
            db.add_scheduled_task(task_name, task_interval, task_active)

    tc = ops_web.tasks.TaskContext(app, apm.client, config, db)
    for task in db.get_scheduled_tasks_to_run():
        task_name = task.get('task_name')
        if task_name in tasks:
            scheduler.add_job(tasks.get(task_name).get('function'), args=[tc], id=task_name)


def main():
    logging.basicConfig(format=config.log_format, level='DEBUG', stream=sys.stdout)
    app.logger.debug(f'ops-web {config.version}')
    if not config.log_level == 'DEBUG':
        app.logger.debug(f'Changing log level to {config.log_level}')
    logging.getLogger().setLevel(config.log_level)
    for logger, level in config.other_log_levels.items():
        app.logger.debug(f'Changing log level for {logger} to {level}')
        logging.getLogger(logger).setLevel(level)

    app.logger.info(f'The following feature flags are set: {config.feature_flags}')

    if config.reset_database:
        db.reset()

    db.migrate()
    db.bootstrap_admin()

    scheduler.start()

    app.logger.info(f'RUNNER: {config.runner}')
    if config.runner:
        sync_data = db.get_sync_data()
        if sync_data['syncing_now']:
            app.logger.warning('A previous sync task was aborted, cleaning up ...')
            db.end_sync()

        app.logger.info(f'AUTO_SYNC: {config.auto_sync}')
        if config.auto_sync:
            scheduler.add_job(sync_machines, 'interval', minutes=config.auto_sync_interval)
            scheduler.add_job(sync_machines)
            scheduler.add_job(check_sync, 'interval', minutes=1)

        scheduler.add_job(run_tasks, 'interval', minutes=1)

    waitress.serve(app, ident=None, threads=config.web_server_threads)
