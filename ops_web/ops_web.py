import apscheduler.schedulers.background
import datetime
import ops_web.aws
import ops_web.az
import ops_web.config
import ops_web.db
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


def permission_required(permission: str):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            app.logger.debug(f'Checking permission for {flask.g.email}')
            if flask.g.email is None:
                return flask.redirect(flask.url_for('index'))
            if flask.g.db.has_permission(flask.g.email, permission):
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
            return flask.redirect(flask.url_for('index'))
        return f(*args, **kwargs)

    return decorated_function


@app.before_request
def log_request():
    app.logger.info(f'{flask.request.method} {flask.request.path}')


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
    db: ops_web.db.Database = flask.g.db
    flask.g.users = db.get_users()
    flask.g.available_permissions = {
        'admin': 'view and manage all environments, launch sync manually, grant permissions to other users',
        'rep-sc-pairs': 'view and manage pairings between Sales Reps and SCs'
    }
    return flask.render_template('admin.html')


@app.route('/admin/edit-user', methods=['POST'])
@permission_required('admin')
def admin_edit_user():
    db: ops_web.db.Database = flask.g.db
    email = flask.request.values.get('email')
    permissions = flask.request.values.getlist('permissions')
    db.set_permissions(email, permissions)
    return flask.redirect(flask.url_for('admin'))


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

    email = claim.get('email')
    flask.session['email'] = email
    app.logger.info(f'Successful sign in for {email}')
    return flask.redirect(flask.url_for('index'))


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
    flask.g.environments = add_running_time_human(db.get_environments(flask.g.email))
    return flask.render_template('environments.html')


@app.route('/environments/<environment>')
@login_required
def environment_detail(environment):
    app.logger.debug(f'Getting information for environment {environment!r}')
    db: ops_web.db.Database = flask.g.db
    flask.g.environment = environment
    flask.g.machines = add_running_time_human(db.get_machines_for_env(flask.g.email, environment))
    flask.g.environments = db.get_environments(flask.g.email)
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


@app.route('/environments/<env_name>/delete', methods=['POST'])
@login_required
def environment_delete(env_name):
    app.logger.info(f'Got a request from {flask.g.email} to delete machines in environment {env_name!r}')
    db: ops_web.db.Database = flask.g.db
    machines = db.get_machines_for_env(flask.g.email, env_name)
    for machine in machines:
        machine_id = machine['id']
        app.logger.debug(f'Attempting to delete machine {machine_id}')
        db.set_machine_state({'id': machine_id, 'state': 'terminating'})
        if machine['cloud'] == 'aws':
            ops_web.aws.delete_machine(machine['region'], machine_id)
        elif machine['cloud'] == 'az':
            az = ops_web.az.AZClient(config)
            scheduler.add_job(ops_web.az.delete_machine, args=[az, machine_id])
    return flask.redirect(flask.url_for('environment_detail', environment=env_name))


@app.route('/environments/<env_name>/start', methods=['POST'])
@login_required
def environment_start(env_name):
    app.logger.info(f'Got a request from {flask.g.email} to start machines in environment {env_name!r}')
    db: ops_web.db.Database = flask.g.db
    machines = db.get_machines_for_env(flask.g.email, env_name)
    for machine in machines:
        machine_id = machine['id']
        app.logger.debug(f'Attempting to start machine {machine_id}')
        db.set_machine_state({'id': machine_id, 'state': 'starting'})
        if machine['cloud'] == 'aws':
            ops_web.aws.start_machine(machine['region'], machine_id)
        elif machine['cloud'] == 'az':
            az = ops_web.az.AZClient(config)
            az.start_machine(machine['id'])
    return flask.redirect(flask.url_for('environment_detail', environment=env_name))


@app.route('/environments/<env_name>/stop', methods=['POST'])
@login_required
def environment_stop(env_name):
    app.logger.info(f'Got a request from {flask.g.email} to stop machines in environment {env_name!r}')
    db: ops_web.db.Database = flask.g.db
    machines = db.get_machines_for_env(flask.g.email, env_name)
    for machine in machines:
        machine_id = machine['id']
        app.logger.debug(f'Attempting to stop machine {machine_id}')
        db.set_machine_state({'id': machine_id, 'state': 'stopping'})
        if machine['cloud'] == 'aws':
            ops_web.aws.stop_machine(machine['region'], machine_id)
        elif machine['cloud'] == 'az':
            az = ops_web.az.AZClient(config)
            az.stop_machine(machine['id'])
    return flask.redirect(flask.url_for('environment_detail', environment=env_name))


@app.route('/images')
@login_required
def images():
    db: ops_web.db.Database = flask.g.db
    flask.g.images = db.get_images(flask.g.email)
    return flask.render_template('images.html')


@app.route('/images/instcreate', methods=['POST'])
@login_required
def instance_create():
    imageid = flask.request.values.get('imageid')
    instanceid = flask.request.values.get('instanceid')
    name = flask.request.values.get('name')
    owner = flask.request.values.get('owner')
    region = flask.request.values.get('region')
    response = ops_web.aws.create_instance(region, imageid, instanceid, name, owner)
    aws = ops_web.aws.AWSClient(config)
    instance = aws.get_single_instance(region, response[0].id)
    environment = instance['environment']
    db: ops_web.db.Database = flask.g.db
    db.add_machine(instance)
    return flask.redirect(flask.url_for('environment_detail', environment=environment))


@app.route('/images/create', methods=['POST'])
@login_required
def image_create():
    env_name = flask.request.values.get('environment')
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to create an image from {machine_id}')
    cloud = flask.request.values.get('cloud')
    owner = flask.request.values.get('owner')
    region = flask.request.values.get('region')
    name = flask.request.values.get('image-name')
    if cloud == 'aws':
        image_id = ops_web.aws.create_image(region, machine_id, name, owner)
    else:
        return flask.redirect(flask.url_for('environment_detail', environment=env_name))
    db: ops_web.db.Database = flask.g.db
    params = {
        'id': image_id,
        'cloud': cloud,
        'region': region,
        'name': name,
        'owner': owner,
        'state': 'pending',
        'created': datetime.datetime.utcnow(),
        'instanceid': machine_id
    }
    db.add_image(params)
    return flask.redirect(flask.url_for('images'))


@app.route('/machines/delete', methods=['POST'])
@login_required
def machine_delete():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to delete machine {machine_id}')
    db: ops_web.db.Database = flask.g.db
    if db.can_control_machine(flask.g.email, machine_id):
        db.set_machine_state({'id': machine_id, 'state': 'terminating'})
        cloud = flask.request.values.get('cloud')
        if cloud == 'aws':
            region = flask.request.values.get('region')
            ops_web.aws.delete_machine(region, machine_id)
        elif cloud == 'az':
            az = ops_web.az.AZClient(config)
            scheduler.add_job(ops_web.az.delete_machine, args=[az, machine_id])
    env_name = flask.request.values.get('environment')
    return flask.redirect(flask.url_for('environment_detail', environment=env_name))


@app.route('/machines/edit', methods=['POST'])
@login_required
def machine_edit():
    machine_id = flask.request.values.get('machine-id')
    app.logger.info(f'Got a request from {flask.g.email} to edit machine {machine_id}')
    db: ops_web.db.Database = flask.g.db
    if db.can_control_machine(flask.g.email, machine_id):
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
        cloud = flask.request.values.get('cloud')
        if cloud == 'aws':
            region = flask.request.values.get('region')
            ops_web.aws.update_resource_tags(region, machine_id, tags)
        elif cloud == 'az':
            az = ops_web.az.AZClient(config)
            az.update_machine_tags(machine_id, tags)
    else:
        app.logger.warning(f'{flask.g.email} does not have permission to edit {machine_id}')
    env_name = flask.request.values.get('environment')
    if env_name:
        return flask.redirect(flask.url_for('environment_detail', environment=env_name))
    return flask.redirect(flask.url_for('environments'))


@app.route('/rep-sc-pairs')
@permission_required('rep-sc-pairs')
def rep_sc_pairs():
    db = ops_web.db.RepSCPairsDatabase(config.rep_sc_pairs_db)
    flask.g.sales_reps = db.get_rep_sc_pairs()
    flask.g.sales_consultants = db.get_sales_consultants()
    return flask.render_template('rep-sc-pairs.html')


@app.route('/rep-sc-pairs.xlsx')
@permission_required('rep-sc-pairs')
def rep_sc_pairs_xlsx():
    db = ops_web.db.RepSCPairsDatabase(config.rep_sc_pairs_db)
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
    rep_name = flask.request.values.get('rep_name')
    sc_name = flask.request.values.get('sc_name')
    if sc_name == 'none':
        sc_name = None
    ops_web.db.RepSCPairsDatabase(config.rep_sc_pairs_db).set_rep_sc_pair(rep_name, sc_name)
    return flask.redirect(flask.url_for('rep_sc_pairs'))


@app.route('/rep-sc-pairs/sc-candidates.json')
@permission_required('rep-sc-pairs')
def rep_sc_pairs_sc_candidates_json():
    db = ops_web.db.RepSCPairsDatabase(config.rep_sc_pairs_db)
    return flask.jsonify([r['sc_name'] for r in db.get_sales_consultants()])


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
    scheduler.add_job(sync_machines)
    return flask.redirect(flask.url_for('sync_info'))


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
        aws = ops_web.aws.AWSClient(config)
        for instance in aws.get_all_instances():
            db.add_machine(instance)
        for image in aws.get_all_images():
            db.add_image(image)
        db.post_sync('aws')
    else:
        app.logger.info(f'Skipping AWS because CLOUDS_TO_SYNC={config.clouds_to_sync}')
    aws_duration = datetime.datetime.utcnow() - aws_start

    az_start = datetime.datetime.utcnow()
    if 'az' in config.clouds_to_sync:
        db.pre_sync('az')
        az = ops_web.az.AZClient(config)
        for vm in az.get_all_virtual_machines():
            db.add_machine(vm)
        for image in az.get_all_images():
            db.add_image(image)
        db.post_sync('az')
    else:
        app.logger.info(f'Skipping Azure because CLOUDS_TO_SYNC={config.clouds_to_sync}')
    az_duration = datetime.datetime.utcnow() - az_start

    sync_duration = datetime.datetime.utcnow() - sync_start
    app.logger.info(f'Done syncing virtual machines / AWS {aws_duration} / Azure {az_duration} / total {sync_duration}')
    db.end_sync()


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

    waitress.serve(app, ident=None)
