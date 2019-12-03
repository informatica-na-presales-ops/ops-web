import apscheduler.schedulers.background
import datetime
import ops_web.aws
import ops_web.az
import ops_web.config
import ops_web.db
import ops_web.send_email
import flask
import functools
import io
import jwt
import logging
import pendulum
import sys
import urllib.parse
import uuid
import waitress
import werkzeug.middleware.proxy_fix
import xlsxwriter

from typing import Dict, List

config = ops_web.config.Config()
scheduler = apscheduler.schedulers.background.BackgroundScheduler()

app = flask.Flask(__name__)
app.wsgi_app = werkzeug.middleware.proxy_fix.ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_port=1)

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
def load_user():
    flask.g.config = config
    flask.g.db = ops_web.db.Database(config)
    flask.g.email = flask.session.get('email')
    flask.g.permissions = flask.g.db.get_permissions(flask.g.email)


@app.route('/')
def index():
    if flask.g.email is None:
        return flask.render_template('sign-in.html')
    return flask.render_template('index.html')


@app.route('/admin')
@permission_required('admin')
def admin():
    return flask.redirect(flask.url_for('admin_users'))


@app.route('/admin/users')
@permission_required('admin')
def admin_users():
    db: ops_web.db.Database = flask.g.db
    flask.g.users = db.get_users()
    flask.g.available_permissions = {
        'admin': ('view and manage all environments, launch sync manually, grant permissions to other users, manage '
                  'cloud credentials'),
        'rep-sc-pairs': 'view and manage pairings between Sales Reps and SCs',
        'survey-admin': 'view all opportunity debrief surveys'
    }
    flask.g.cloud_credentials = db.get_cloud_credentials()
    return flask.render_template('admin-users.html')


@app.route('/admin/cloud-credentials')
@permission_required('admin')
def admin_cloud_credentials():
    db: ops_web.db.Database = flask.g.db
    flask.g.cloud_credentials = db.get_cloud_credentials()
    return flask.render_template('admin-cloud-credentials.html')


@app.route('/admin/cloud-credentials/delete', methods=['POST'])
@permission_required('admin')
def admin_cloud_credentials_delete():
    db: ops_web.db.Database = flask.g.db
    cred_id = flask.request.values.get('id')
    db.delete_cloud_credentials(cred_id)
    db.add_log_entry(flask.g.email, f'Delete cloud credentials {cred_id}')
    return flask.redirect(flask.url_for('admin_cloud_credentials'))


@app.route('/admin/cloud-credentials/edit', methods=['POST'])
@permission_required('admin')
def admin_cloud_credentials_edit():
    db: ops_web.db.Database = flask.g.db
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


@app.route('/admin/edit-user', methods=['POST'])
@permission_required('admin')
def admin_edit_user():
    db: ops_web.db.Database = flask.g.db
    email = flask.request.values.get('email')
    permissions = flask.request.values.getlist('permissions')
    db.add_log_entry(flask.g.email, f'Set permissions for {email} to {permissions}')
    db.set_permissions(email, permissions)
    return flask.redirect(flask.url_for('admin'))


@app.route('/admin/impersonate', methods=['POST'])
@permission_required('admin')
def admin_impersonate():
    db: ops_web.db.Database = flask.g.db
    target = flask.request.form.get('target')
    db.add_log_entry(flask.g.email, f'Impersonate user {target}')
    flask.session['email'] = target
    return flask.redirect(flask.url_for('index'))


@app.route('/audit-log')
@permission_required('admin')
def audit_log():
    db: ops_web.db.Database = flask.g.db
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
    if state != flask.session['state']:
        raise ValueError('State does not match')
    flask.session.pop('state')

    email = claim.get('email').lower()
    flask.session['email'] = email
    app.logger.info(f'Successful sign in for {email}')
    target = flask.session.pop('sign-in-target-url', flask.url_for('index'))
    app.logger.debug(f'sign-in-target-url: {target}')
    return flask.redirect(target)


def timedelta_human(td: datetime.timedelta) -> str:
    parts = []
    dur = pendulum.Duration(seconds=td.total_seconds())
    if dur.days > 0:
        day_part = f'{dur.days} day'
        if dur.days > 1:
            day_part = f'{day_part}s'
        parts.append(day_part)
    if dur.hours > 0:
        hour_part = f'{dur.hours} hr'
        if dur.hours > 1:
            hour_part = f'{hour_part}s'
        parts.append(hour_part)
    if dur.minutes > 0:
        minute_part = f'{dur.minutes} min'
        if dur.minutes > 1:
            minute_part = f'{minute_part}s'
        parts.append(minute_part)
    return ' '.join(parts)


def add_running_time_human(col: List[Dict]) -> List[Dict]:
    new_col = []
    for i in col:
        new_i = dict(i)
        if i.get('running_time'):
            new_i['running_time_human'] = timedelta_human(i.get('running_time'))
        else:
            new_i['running_time_human'] = ''
        new_col.append(new_i)
    return new_col


@app.route('/environments')
@login_required
def environments():
    db: ops_web.db.Database = flask.g.db
    flask.g.environments = add_running_time_human(db.get_environments())
    flask.g.default_filter = flask.request.values.get('filter', '').lower()
    return flask.render_template('environments.html')


@app.route('/environments/<environment>')
@login_required
def environment_detail(environment):
    app.logger.debug(f'Getting information for environment {environment!r}')
    db: ops_web.db.Database = flask.g.db
    flask.g.environment = environment
    flask.g.machines = add_running_time_human(db.get_machines_for_env(flask.g.email, environment))
    flask.g.environments = db.get_environments()
    flask.g.today = datetime.date.today()
    flask.g.machine_state_class_map = {
        'running': 'text-success',
        'starting': 'text-warning',
        'stopped': 'text-danger',
        'stopping': 'text-warning',
        'terminated': 'text-muted',
        'terminating': 'text-muted'
    }
    return flask.render_template('environment-detail.html')


@app.route('/environments/<environment>/delete', methods=['POST'])
@login_required
def environment_delete(environment):
    app.logger.info(f'Got a request from {flask.g.email} to delete machines in environment {environment!r}')
    db: ops_web.db.Database = flask.g.db
    machines = db.get_machines_for_env(flask.g.email, environment)
    for machine in machines:
        machine_id = machine.get('id')
        if machine.get('can_modify'):
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
    db: ops_web.db.Database = flask.g.db
    machines = db.get_machines_for_env(flask.g.email, environment)
    for machine in machines:
        machine_id = machine.get('id')
        if machine.get('can_control'):
            db.add_log_entry(flask.g.email, f'Start machine {machine_id}')
            db.set_machine_state(machine_id, 'starting')
            scheduler.add_job(start_machine, args=[machine_id])
        else:
            app.logger.warning(f'{flask.g.email} does not have permission to start machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=environment))


@app.route('/environments/<environment>/stop', methods=['POST'])
@login_required
def environment_stop(environment):
    app.logger.info(f'Got a request from {flask.g.email} to stop machines in environment {environment!r}')
    db: ops_web.db.Database = flask.g.db
    machines = db.get_machines_for_env(flask.g.email, environment)
    for machine in machines:
        machine_id = machine.get('id')
        if machine.get('can_control'):
            db.add_log_entry(flask.g.email, f'Stop machine {machine_id}')
            db.set_machine_state(machine_id, 'stopping')
            scheduler.add_job(stop_machine, args=[machine_id])
        else:
            app.logger.warning(f'{flask.g.email} does not have permission to stop machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=environment))


@app.route('/images')
@login_required
def images():
    db: ops_web.db.Database = flask.g.db
    flask.g.images = db.get_images(flask.g.email)
    flask.g.environments = db.get_env_list()
    username = flask.g.email.split('@')[0]
    flask.g.default_environment = f'{username}-{datetime.datetime.utcnow():%Y%m%d-%H%M%S}'
    flask.g.default_filter = flask.request.values.get('filter', '').lower()
    return flask.render_template('images.html')


@app.route('/images/create', methods=['POST'])
@login_required
def image_create():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to create an image from {machine_id}')
    db: ops_web.db.Database = flask.g.db
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_modify'):
        db.add_log_entry(flask.g.email, f'Create image from machine {machine_id}')
        cloud = flask.request.values.get('cloud')

        if not cloud == 'aws':
            app.logger.warning(f'Unable to create images for cloud {cloud}')
            environment = flask.request.values.get('environment')
            return flask.redirect(flask.url_for('environment_detail', environment=environment))

        account = db.get_one_credential_for_use(machine.get('account_id'))
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        region = flask.request.values.get('region')
        name = flask.request.values.get('image-name')
        owner = flask.request.values.get('owner')
        public = 'public' in flask.request.values
        image_id = aws.create_image(region, machine_id, name, owner, public)
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
            'account_id': machine.get('account_id')
        }
        db.add_image(params)
        return flask.redirect(flask.url_for('images'))
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to create an image from {machine_id}')
        return flask.redirect(flask.url_for('environment_detail', environment=machine.get('env_group')))


@app.route('/images/delete', methods=['POST'])
@permission_required('admin')
def image_delete():
    db: ops_web.db.Database = flask.g.db
    image_id = flask.request.values.get('image-id')
    app.logger.info(f'Got a request from {flask.g.email} to delete image {image_id}')
    db.add_log_entry(flask.g.email, f'Delete image {image_id}')
    db.set_image_state(image_id, 'deleting')
    image = db.get_image(image_id)
    account = db.get_one_credential_for_use(image.get('account_id'))
    cloud = image.get('cloud')
    if cloud == 'aws':
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        region = image.get('region')
        aws.delete_image(region, image_id)
    return flask.redirect(flask.url_for('toolbox'))


@app.route('/images/edit', methods=['POST'])
@login_required
def image_edit():
    image_id = flask.request.values.get('image-id')
    app.logger.info(f'Got a request from {flask.g.email} to edit image {image_id}')
    db: ops_web.db.Database = flask.g.db
    image = db.get_image(image_id)
    if 'admin' in flask.g.permissions or image.get('owner') == flask.g.email:
        db.add_log_entry(flask.g.email, f'Update tags on image {image_id}')
        image_name = flask.request.values.get('image-name')
        owner = flask.request.values.get('owner')
        public = 'public' in flask.request.values
        db.set_image_tags(image_id, image_name, owner, public)
        tags = {
            'NAME': image_name,
            'OWNEREMAIL': owner,
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
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to edit {image_id}')
    return flask.redirect(flask.url_for('images'))


@app.route('/machines/create', methods=['POST'])
@login_required
def machine_create():
    image_id = flask.request.values.get('image-id')
    app.logger.info(f'Got a request from {flask.g.email} to create machine from image {image_id}')
    db: ops_web.db.Database = flask.g.db
    image = db.get_image(image_id)
    if 'admin' in flask.g.permissions or image.get('public') or image.get('owner') == flask.g.email:
        db.add_log_entry(flask.g.email, f'Create machine from image {image_id}')
        region = image.get('region')
        instance_id = image.get('instanceid')
        name = flask.request.values.get('name')
        owner = flask.request.values.get('owner')
        environment = flask.request.values.get('environment')
        account = db.get_one_credential_for_use(image.get('account_id'))
        aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
        response = aws.create_instance(region, image_id, instance_id, name, owner, environment)
        instance = aws.get_single_instance(region, response[0].id)
        instance['account_id'] = account.get('id')
        db.add_machine(instance)
        return flask.redirect(flask.url_for('environment_detail', environment=environment))
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to create machine from image {image_id}')
        return flask.redirect(flask.url_for('images'))


@app.route('/machines/delete', methods=['POST'])
@login_required
def machine_delete():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to delete machine {machine_id}')
    db: ops_web.db.Database = flask.g.db
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_modify'):
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
    db: ops_web.db.Database = flask.g.db
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_modify'):
        db.add_log_entry(flask.g.email, f'Update tags on machine {machine_id}')
        db.set_machine_tags({
            'application_env': flask.request.values.get('application-env'),
            'business_unit': flask.request.values.get('business-unit'),
            'contributors': flask.request.values.get('contributors'),
            'environment': flask.request.values.get('environment'),
            'id': machine_id,
            'name': flask.request.values.get('machine-name'),
            'owner': flask.request.values.get('owner'),
            'running_schedule': flask.request.values.get('running-schedule'),
            'dns_names': flask.request.values.get('dns-names')
        })
        tags = {
            'APPLICATIONENV': flask.request.values.get('application-env'),
            'BUSINESSUNIT': flask.request.values.get('business-unit'),
            'CONTRIBUTORS': flask.request.values.get('contributors'),
            'machine__environment_group': flask.request.values.get('environment'),
            'image__dns_names_private': flask.request.values.get('dns-names'),
            'NAME': flask.request.values.get('machine-name'),
            'OWNEREMAIL': flask.request.values.get('owner'),
            'RUNNINGSCHEDULE': flask.request.values.get('running-schedule')
        }
        cloud = machine.get('cloud')
        account = db.get_one_credential_for_use(machine.get('account_id'))
        if cloud == 'aws':
            aws = ops_web.aws.AWSClient(config, account.get('username'), account.get('password'))
            region = machine.get('region')
            aws.update_resource_tags(region, machine_id, tags)
        elif cloud == 'az':
            az = ops_web.az.AZClient(config, account.get('username'), account.get('password'),
                                     account.get('azure_tenant_id'))
            az.update_machine_tags(machine_id, tags)
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
    db: ops_web.db.Database = flask.g.db
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
    db: ops_web.db.Database = flask.g.db
    machine = db.get_machine(machine_id, flask.g.email)
    if machine.get('can_control'):
        db.add_log_entry(flask.g.email, f'Stop machine {machine_id}')
        db.set_machine_state(machine_id, 'stopping')
        scheduler.add_job(stop_machine, args=[machine_id])
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to stop machine {machine_id}')
    return flask.redirect(flask.url_for('environment_detail', environment=machine.get('env_group')))


@app.route('/op-debrief')
@login_required
def op_debrief():
    db: ops_web.db.Database = flask.g.db
    flask.g.surveys = db.get_surveys(flask.g.email)
    return flask.render_template('op-debrief.html')


@app.route('/op-debrief/<uuid:survey_id>', methods=['GET', 'POST'])
@login_required
def op_debrief_survey(survey_id: uuid.UUID):
    db: ops_web.db.Database = flask.g.db
    survey = db.get_survey(survey_id)
    if 'admin' in flask.g.permissions or 'survey-admin' in flask.g.permissions or flask.g.email == survey.get('email'):
        if flask.request.method == 'GET':
            flask.g.survey = survey
            flask.g.plr_options = {
                'key-decision-maker-left': 'Key decision maker left',
                'project-cancelled': 'Project cancelled',
                'competitive-loss': 'Competitive loss'
            }
            flask.g.clr_options = {
                'relationship-loss': 'Relationship loss',
                'technology-gap': 'Technology gap',
                'perceived-poor-fit': 'Perceived poor brand/solution fit',
                'partner-influenced': 'Partner influenced'
            }
            flask.g.tgt_options = {
                'option-1': 'Option 1',
                'option-2': 'Option 2',
                'option-3': 'Option 3'
            }
            flask.g.ppfr_options = {
                'option-1': 'Option 1',
                'option-2': 'Option 2',
                'option-3': 'Option 3'
            }
            return flask.render_template('op-debrief-survey.html')
        elif flask.request.method == 'POST':
            for k, v in flask.request.form.items():
                app.logger.debug(f'{k}: {v}')
            params = {
                'survey_id': survey_id,
                'completed': datetime.datetime.utcnow(),
                'primary_loss_reason': flask.request.form.get('primary-loss-reason'),
                'competitive_loss_reason': flask.request.form.get('competitive-loss-reason'),
                'technology_gap_type': flask.request.form.get('technology-gap-type'),
                'perceived_poor_fit_reason': flask.request.form.get('perceived-poor-fit-reason')
            }
            db.complete_survey(params)
            db.add_log_entry(flask.g.email, f'Completed opportunity debrief survey {survey_id}')
            return flask.redirect(flask.url_for('op_debrief_survey', survey_id=survey_id))
    # see if there is another survey for this opportunity for the signed-in user
    return flask.redirect(flask.url_for('op_debrief'))


@app.route('/rep-sc-pairs')
@permission_required('rep-sc-pairs')
def rep_sc_pairs():
    db: ops_web.db.Database = flask.g.db
    flask.g.sales_reps = db.get_rep_sc_pairs()
    flask.g.sales_consultants = db.get_sales_consultants()
    return flask.render_template('rep-sc-pairs.html')


@app.route('/rep-sc-pairs.xlsx')
@permission_required('rep-sc-pairs')
def rep_sc_pairs_xlsx():
    db: ops_web.db.Database = flask.g.db
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


@app.route('/rep-sc-pairs/edit', methods=['POST'])
@permission_required('rep-sc-pairs')
def rep_sc_pairs_edit():
    db: ops_web.db.Database = flask.g.db
    rep_name = flask.request.values.get('rep_name')
    sc_name = flask.request.values.get('sc_name')
    db.add_log_entry(flask.g.email, f'Update Rep/SC pair: {rep_name}/{sc_name}')
    if sc_name == 'none':
        sc_name = None
    db.set_rep_sc_pair(rep_name, sc_name)
    return flask.redirect(flask.url_for('rep_sc_pairs'))


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
    flask.session.pop('email')
    return flask.redirect(flask.url_for('index'))


@app.route('/sync-info')
@login_required
def sync_info():
    db: ops_web.db.Database = flask.g.db
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
    db: ops_web.db.Database = flask.g.db
    db.add_log_entry(flask.g.email, 'Manual sync')
    scheduler.add_job(sync_machines)
    return flask.redirect(flask.url_for('sync_info'))


@app.route('/toolbox')
@permission_required('admin')
def toolbox():
    return flask.render_template('toolbox.html')


def delete_machine(machine_id):
    app.logger.info(f'Attempting to delete machine {machine_id}')
    db = ops_web.db.Database(config)
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


def start_machine(machine_id):
    app.logger.info(f'Attempting to start machine {machine_id}')
    db = ops_web.db.Database(config)
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


def stop_machine(machine_id):
    app.logger.info(f'Attempting to stop machine {machine_id}')
    db = ops_web.db.Database(config)
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


def sync_machines():
    app.logger.info('Syncing information from cloud providers now ...')

    db = ops_web.db.Database(config)
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
            for instance in aws.get_all_instances():
                instance['account_id'] = account.get('id')
                db.add_machine(instance)
            for image in aws.get_all_images():
                image['account_id'] = account.get('id')
                db.add_image(image)
        db.post_sync('aws')
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
                db.add_machine(vm)
            for image in az.get_all_images():
                image['account_id'] = account.get('id')
                db.add_image(image)
        db.post_sync('az')
    else:
        app.logger.info(f'Skipping Azure because CLOUDS_TO_SYNC={config.clouds_to_sync}')
    az_duration = datetime.datetime.utcnow() - az_start

    sync_duration = datetime.datetime.utcnow() - sync_start
    app.logger.info(f'Done syncing virtual machines / AWS {aws_duration} / Azure {az_duration} / total {sync_duration}')
    db.end_sync()


def generate_op_debrief_surveys():
    app.logger.info('Generating opportunity debrief surveys')
    now = datetime.datetime.utcnow()
    db = ops_web.db.Database(config)
    last_check = db.get_last_op_debrief_check()
    app.logger.info(f'Looking for opportunities modified after {last_check}')
    modified_ops = db.get_modified_opportunities(last_check)
    existing_survey_op_numbers = db.get_op_numbers_for_existing_surveys()
    for op in modified_ops:
        op_number = op.get('opportunity_number')
        if op_number in existing_survey_op_numbers:
            app.logger.debug(f'Already sent surveys for {op_number}')
            continue
        app.logger.info(f'Generating surveys for {op_number}')
        team_members = db.get_op_team_members(op.get('opportunity_key'))
        for t in team_members:
            email = t.get('email')
            survey_id = db.add_survey(op_number, email, t.get('role'))
            c = {
                'opportunity': op,
                'person': t,
                'survey_id': survey_id
            }
            with app.app_context():
                body = flask.render_template('op-debrief-survey-email.jinja2', c=c)
            ops_web.send_email.send_email(config, email, 'Opportunity debrief survey', body)
    db.update_op_debrief_tracking(now)


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

    db = ops_web.db.Database(config)
    if config.reset_database:
        db.reset()

    db.migrate()
    db.bootstrap_admin()
    sync_data = db.get_sync_data()
    if sync_data['syncing_now']:
        app.logger.warning('A previous sync task was aborted, cleaning up ...')
        db.end_sync()

    scheduler.start()
    app.logger.info(f'AUTO_SYNC is {config.auto_sync}')
    if config.auto_sync:
        scheduler.add_job(sync_machines, 'interval', minutes=config.auto_sync_interval)
        scheduler.add_job(sync_machines)

    # op debrief survey jobs
    if 'op-debrief' in config.feature_flags:
        scheduler.add_job(generate_op_debrief_surveys)
        scheduler.add_job(generate_op_debrief_surveys, 'interval', hours=6)

    waitress.serve(app, ident=None)
