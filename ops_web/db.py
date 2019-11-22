import datetime
import fort
import ops_web.config
import uuid

from typing import Dict, List, Optional, Set


class Database(fort.PostgresDatabase):
    _version: int = None

    def __init__(self, config: ops_web.config.Config):
        super().__init__(config.db)
        self.config = config

    # users and permissions

    def bootstrap_admin(self):
        if self.config.bootstrap_admin in (None, ''):
            return
        self.log.info(f'Adding a bootstrap admin: {self.config.bootstrap_admin}')
        self.add_permission(self.config.bootstrap_admin, 'admin')

    def get_users(self):
        sql = 'SELECT email, permissions FROM permissions ORDER BY email'
        for record in self.q(sql):
            yield {'email': record['email'], 'permissions': record['permissions'].split()}

    def add_permission(self, email: str, permission: str):
        current_permissions = set(self.get_permissions(email))
        current_permissions.add(permission)
        self.set_permissions(email, sorted(current_permissions))

    def get_permissions(self, email: str) -> List[str]:
        sql = 'SELECT permissions FROM permissions WHERE email = %(email)s'
        permissions = self.q_val(sql, {'email': email})
        if permissions is None:
            return []
        return sorted(set(permissions.replace(',', ' ').split()))

    def set_permissions(self, email: str, permissions: List[str]):
        params = {'email': email, 'permissions': ' '.join(sorted(set(permissions)))}
        self.u('DELETE FROM permissions WHERE email = %(email)s', params)
        if permissions:
            self.u('INSERT INTO permissions (email, permissions) VALUES (%(email)s, %(permissions)s)', params)

    def has_permission(self, email: str, permission: str) -> bool:
        return permission in self.get_permissions(email)

    # logging

    def add_log_entry(self, actor: str, action: str):
        params = {
            'id': uuid.uuid4(),
            'log_time': datetime.datetime.utcnow(),
            'actor': actor,
            'action': action
        }
        sql = '''
            INSERT INTO log_entries (id, log_time, actor, action)
            VALUES (%(id)s, %(log_time)s, %(actor)s, %(action)s)
        '''
        self.u(sql, params)

    def get_log_entries(self):
        sql = '''
            SELECT id, log_time, actor, action, lower(actor || ' ' || action) filter_value
            FROM log_entries
            ORDER BY log_time DESC
        '''
        return self.q(sql)

    # cloud credentials

    def add_cloud_credentials(self, params: Dict) -> uuid.UUID:
        sql = '''
            INSERT INTO cloud_credentials (id, cloud, description, username, password, azure_tenant_id)
            VALUES (%(id)s, %(cloud)s, %(description)s, %(username)s, %(password)s, %(azure_tenant_id)s)
        '''
        params['id'] = uuid.uuid4()
        if params.get('cloud') == 'aws':
            params['azure_tenant_id'] = 'n/a'
        self.u(sql, params)
        return params['id']

    def delete_cloud_credentials(self, cred_id: uuid.UUID):
        params = {'id': cred_id}
        for sql in ['DELETE FROM cloud_credentials WHERE id = %(id)s',
                    'UPDATE images SET visible = FALSE WHERE account_id = %(id)s',
                    'UPDATE virtual_machines SET visible = FALSE WHERE account_id = %(id)s']:
            self.u(sql, params)

    def get_cloud_credentials(self):
        sql = '''
            SELECT id, cloud, description, username, azure_tenant_id FROM cloud_credentials ORDER BY cloud, description
        '''
        return self.q(sql)

    def get_all_credentials_for_use(self, cloud: str) -> List[Dict]:
        sql = '''
            SELECT id, username, password, azure_tenant_id
            FROM cloud_credentials
            WHERE cloud = %(cloud)s
        '''
        params = {'cloud': cloud}
        return self.q(sql, params)

    def get_one_credential_for_use(self, account_id: uuid.UUID) -> Dict:
        sql = '''
            SELECT id, username, password, azure_tenant_id
            FROM cloud_credentials
            WHERE id = %(id)s
        '''
        params = {'id': account_id}
        return self.q_one(sql, params)

    def update_cloud_credentials(self, params: Dict):
        if 'password' in params:
            sql = '''
                UPDATE cloud_credentials
                SET cloud = %(cloud)s, description = %(description)s, username = %(username)s, password = %(password)s,
                    azure_tenant_id = %(azure_tenant_id)s
                WHERE id = %(id)s
            '''
        else:
            sql = '''
                UPDATE cloud_credentials
                SET cloud = %(cloud)s, description = %(description)s, username = %(username)s,
                    azure_tenant_id = %(azure_tenant_id)s
                WHERE id = %(id)s
            '''
        self.u(sql, params)

    # environments and machines

    def get_env_list(self) -> List[str]:
        sql = '''
            SELECT DISTINCT env_group
            FROM virtual_machines
            WHERE visible IS TRUE
            ORDER BY env_group
        '''
        return [r['env_group'] for r in self.q(sql)]

    def get_environments(self) -> List[Dict]:
        sql = '''
            SELECT
                cloud,
                env_group,
                owner,
                count(*) instance_count,
                bool_or(state = 'running') running,
                max(CASE WHEN state = 'running' THEN now() - created ELSE NULL END) running_time,
                lower(env_group || ' ' || owner) filter_value
            FROM virtual_machines
            WHERE visible IS TRUE
            GROUP BY cloud, env_group, owner
            ORDER BY env_group
        '''
        return self.q(sql)

    def get_machines_for_env(self, email: str, env_group: str) -> List[Dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                SELECT
                    id, cloud, region, env_group, name, owner, contributors, state, private_ip, public_ip, type,
                    running_schedule, application_env, business_unit, dns_names, whitelist, account_id,
                    CASE WHEN state = 'running' THEN now() - created ELSE NULL END running_time,
                    TRUE can_control,
                    TRUE can_modify
                FROM virtual_machines
                WHERE visible IS TRUE
                  AND env_group = %(env_group)s
                ORDER BY name
            '''
        else:
            sql = '''
                SELECT
                    id, cloud, region, env_group, name, owner, contributors, state, private_ip, public_ip, type,
                    running_schedule, application_env, business_unit, dns_names, whitelist, account_id,
                    CASE WHEN state = 'running' THEN now() - created ELSE NULL END running_time,
                    owner = %(email)s OR position(%(email)s in contributors) > 0 can_control,
                    owner = %(email)s can_modify
                FROM virtual_machines
                WHERE visible IS TRUE
                  AND env_group = %(env_group)s
                ORDER BY name
            '''
        return self.q(sql, {'email': email, 'env_group': env_group})

    def get_machine(self, machine_id: str, email: str = None) -> Dict:
        if email is None or self.has_permission(email, 'admin'):
            sql = '''
                SELECT
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    visible, synced, created, state_transition_time, application_env, business_unit, contributors,
                    dns_names, whitelist, account_id,
                    CASE WHEN state = 'running' THEN now() - created ELSE NULL END running_time,
                    TRUE can_control,
                    TRUE can_modify
                FROM virtual_machines
                WHERE id = %(id)s
            '''
        else:
            sql = '''
                SELECT
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    visible, synced, created, state_transition_time, application_env, business_unit, contributors,
                    dns_names, whitelist, account_id,
                    CASE WHEN state = 'running' THEN now() - created ELSE NULL END running_time,
                    owner = %(email)s OR position(%(email)s in contributors) > 0 can_control,
                    owner = %(email)s can_modify
                FROM virtual_machines
                WHERE id = %(id)s
            '''
        return self.q_one(sql, {'id': machine_id, 'email': email})

    def set_machine_created(self, machine_id: str, created):
        sql = 'UPDATE virtual_machines SET created = %(created)s WHERE id = %(id)s'
        self.u(sql, {'id': machine_id, 'created': created})

    def set_machine_public_ip(self, machine_id: str, public_ip: str = None):
        sql = 'UPDATE virtual_machines SET public_ip = %(public_ip)s WHERE id = %(id)s'
        self.u(sql, {'id': machine_id, 'public_ip': public_ip})

    def set_machine_state(self, machine_id: str, state: str):
        params = {'id': machine_id, 'state': state}
        sql = 'UPDATE virtual_machines SET state = %(state)s WHERE id = %(id)s'
        self.u(sql, params)

    def set_machine_tags(self, params: Dict):
        # params = {
        #   'id': '', 'running_schedule': '', 'name': '', 'owner': '', 'contributors': '', 'application_env': '',
        #   'business_unit': '', 'environment': '', 'dns_names': ''
        # }
        sql = '''
            UPDATE virtual_machines
            SET running_schedule = %(running_schedule)s, name = %(name)s, owner = %(owner)s,
                contributors = %(contributors)s, application_env = %(application_env)s,
                business_unit = %(business_unit)s, env_group = %(environment)s, dns_names = %(dns_names)s
            WHERE id = %(id)s
        '''
        self.u(sql, params)

    # images

    def get_images(self, email: str) -> List[Dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                SELECT
                    id,
                    cloud,
                    region,
                    name,
                    owner,
                    TRUE can_modify,
                    cloud = 'aws' AND state = 'available' can_launch,
                    public,
                    state,
                    created,
                    account_id,
                    coalesce(instanceid, '') instanceid,
                    lower(cloud || ' ' || coalesce(name, '') || ' ' || coalesce(owner, '')) filter_value 
                FROM images
                WHERE visible IS TRUE
                ORDER BY name
            '''
        else:
            sql = '''
                SELECT
                    id,
                    cloud,
                    region,
                    name,
                    owner,
                    owner = %(email)s can_modify,
                    cloud = 'aws' AND state = 'available' can_launch,
                    public,
                    state,
                    created,
                    account_id,
                    coalesce(instanceid, '') instanceid,
                    lower(cloud || ' ' || coalesce(name, '') || ' ' || coalesce(owner, '')) filter_value
                FROM images
                WHERE visible IS TRUE
                AND (owner = %(email)s OR public IS TRUE)
            '''
        return self.q(sql, {'email': email})

    def get_image(self, image_id: str) -> Dict:
        sql = '''
            SELECT id, cloud, region, name, owner, public, state, created, visible, synced, instanceid, account_id
            FROM images
            WHERE id = %(id)s
        '''
        return self.q_one(sql, {'id': image_id})

    def set_image_tags(self, image_id: str, name: str, owner: str, public: bool):
        sql = 'UPDATE images SET name = %(name)s, owner = %(owner)s, public = %(public)s WHERE id = %(id)s'
        params = {'id': image_id, 'name': name, 'owner': owner, 'public': public}
        self.u(sql, params)

    def set_image_state(self, image_id: str, state: str):
        sql = 'UPDATE images SET state = %(state)s WHERE id = %(id)s'
        params = {'id': image_id, 'state': state}
        self.u(sql, params)

    # syncing

    def start_sync(self):
        sql = '''
            UPDATE sync_tracking
            SET syncing_now = TRUE, last_sync_start = %(last_sync_start)s, last_sync_end = NULL
            WHERE only_row IS TRUE
        '''
        self.u(sql, {'last_sync_start': datetime.datetime.utcnow()})

    def end_sync(self):
        sql = '''
            UPDATE sync_tracking
            SET syncing_now = FALSE, last_sync_end = %(last_sync_end)s
            WHERE only_row IS TRUE
        '''
        self.u(sql, {'last_sync_end': datetime.datetime.utcnow()})

    def get_sync_data(self):
        sql = 'SELECT syncing_now, last_sync_start, last_sync_end FROM sync_tracking'
        for row in self.q(sql):
            return row

    def pre_sync(self, cloud: str):
        params = {'cloud': cloud}
        sql = '''
            UPDATE virtual_machines SET synced = FALSE WHERE (synced IS TRUE OR synced IS NULL) AND cloud = %(cloud)s
        '''
        self.u(sql, params)
        sql = 'UPDATE images SET synced = FALSE WHERE (synced IS TRUE OR synced IS NULL) AND cloud = %(cloud)s'
        self.u(sql, params)

    def post_sync(self, cloud: str):
        params = {'cloud': cloud}
        sql = 'UPDATE virtual_machines SET visible = FALSE WHERE synced IS FALSE AND cloud = %(cloud)s'
        self.u(sql, params)
        sql = 'UPDATE images SET visible = FALSE WHERE synced IS FALSE AND cloud = %(cloud)s'
        self.u(sql, params)

    def add_machine(self, params: Dict):
        # params = {
        #   'id': '', 'cloud': '', 'region': '', 'environment': '', 'name': '', 'owner': '', 'contributors': '',
        #   'private_ip': '', 'public_ip': '', 'state': '', 'type': '', 'running_schedule': '', 'created': '',
        #   'state_transition_time': '', 'application_env': '', 'business_unit': '', 'dns_names': '', 'whitelist': '',
        #   'account_id': ''
        # }
        sql = 'SELECT id FROM virtual_machines WHERE id = %(id)s'
        if self.q(sql, params):
            sql = '''
                UPDATE virtual_machines
                SET cloud = %(cloud)s, region = %(region)s, env_group = %(environment)s, name = %(name)s,
                    owner = %(owner)s, state = %(state)s, private_ip = %(private_ip)s, public_ip = %(public_ip)s,
                    type = %(type)s, running_schedule = %(running_schedule)s, created = %(created)s,
                    state_transition_time = %(state_transition_time)s, application_env = %(application_env)s,
                    business_unit = %(business_unit)s, contributors = %(contributors)s, dns_names = %(dns_names)s,
                    whitelist = %(whitelist)s, account_id = %(account_id)s,
                    visible = TRUE, synced = TRUE
                WHERE id = %(id)s
            '''
        else:
            sql = '''
                INSERT INTO virtual_machines (
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    created, state_transition_time, application_env, business_unit, contributors, dns_names, whitelist,
                    account_id, visible, synced
                ) VALUES (
                    %(id)s, %(cloud)s, %(region)s, %(environment)s, %(name)s, %(owner)s, %(state)s, %(private_ip)s,
                    %(public_ip)s, %(type)s, %(running_schedule)s, %(created)s, %(state_transition_time)s,
                    %(application_env)s, %(business_unit)s, %(contributors)s, %(dns_names)s, %(whitelist)s,
                    %(account_id)s, TRUE, TRUE
                )
            '''
        self.u(sql, params)

    def add_image(self, params: Dict):
        # params = {
        #   'id': '', 'cloud': '', 'region': '', 'name': '', 'owner': '', 'state': '', 'created': '', 'instanceid': '',
        #   'public': (bool), 'account_id': ''
        # }
        sql = 'SELECT id FROM images WHERE id = %(id)s'
        if self.q(sql, params):
            sql = '''
                UPDATE images 
                SET cloud = %(cloud)s, region = %(region)s, name = %(name)s, owner = %(owner)s, state = %(state)s,
                    public = %(public)s, created = %(created)s, instanceid = %(instanceid)s,
                    account_id = %(account_id)s, visible = TRUE, synced = TRUE
                WHERE id = %(id)s
            '''
        else:
            sql = '''
                INSERT INTO images (
                    id, cloud, region, name, owner, public, state, created, instanceid, account_id, visible, synced
                ) VALUES (
                    %(id)s, %(cloud)s, %(region)s, %(name)s, %(owner)s, %(public)s, %(state)s, %(created)s,
                    %(instanceid)s, %(account_id)s, TRUE, TRUE
                )
            '''
        self.u(sql, params)

    # rep/sc pairs

    def get_rep_sc_pairs(self):
        sql = '''
            SELECT geo, area, sub_area, region, sub_region, coalesce(territory_name, '') territory_name,
                   sales_rep rep_name, coalesce(assigned_sc, '') sc_name,
                   lower(geo || ' ' || area || ' ' || sub_area || ' ' || region || ' ' || sub_region || ' ' ||
                         coalesce(territory_name, '') || ' ' || sales_rep) filter_value
            FROM sales_reps
            ORDER BY geo, area, sub_area, region, sub_region, territory_name, rep_name
        '''
        return self.q(sql)

    def get_sales_consultants(self):
        sql = 'SELECT name sc_name FROM sales_consultants ORDER BY name'
        return self.q(sql)

    def set_rep_sc_pair(self, rep_name, sc_name):
        sql = 'UPDATE sales_reps SET assigned_sc = %(sc_name)s WHERE sales_rep = %(rep_name)s'
        self.u(sql, {'sc_name': sc_name, 'rep_name': rep_name})

    # opportunity debrief surveys

    def add_survey(self, opportunity_number: str, email: str, role: str) -> uuid.UUID:
        self.log.debug(f'Generating a survey for {opportunity_number} / {email}')
        sql = '''
            INSERT INTO op_debrief_surveys (id, opportunity_number, email, role, generated)
            VALUES (%(id)s, %(opportunity_number)s, %(email)s, %(role)s, %(generated)s)
        '''
        params = {
            'id': uuid.uuid4(),
            'opportunity_number': opportunity_number,
            'email': email,
            'role': role,
            'generated': datetime.datetime.utcnow()
        }
        self.u(sql, params)
        return params.get('id')

    def complete_survey(self, params: Dict):
        sql = '''
            UPDATE op_debrief_surveys
            SET completed = %(completed)s, primary_loss_reason = %(primary_loss_reason)s,
                competitive_loss_reason = %(competitive_loss_reason)s, technology_gap_type = %(technology_gap_type)s,
                perceived_poor_fit_reason = %(perceived_poor_fit_reason)s
            WHERE id = %(survey_id)s
        '''
        self.u(sql, params)

    def get_last_op_debrief_check(self) -> datetime.datetime:
        sql = 'SELECT last_check FROM op_debrief_tracking'
        return self.q_val(sql)

    def get_modified_opportunities(self, since: datetime.datetime) -> List[Dict]:
        sql = '''
            SELECT
                opportunity_key, id, opportunity_number, name, account_name, stage_name, close_date, last_modified_date,
                technology_ecosystem, sales_journey
            FROM sf_opportunities
            WHERE last_modified_date > %(since)s
              AND stage_name = 'Closed Lost'
              AND close_date > current_date - interval '5' day
        '''
        params = {'since': since}
        return self.q(sql, params)

    def get_op_numbers_for_existing_surveys(self) -> Set[str]:
        sql = 'SELECT DISTINCT opportunity_number FROM op_debrief_surveys'
        return set([r.get('opportunity_number') for r in self.q(sql)])

    def get_op_team_members(self, opportunity_key: int) -> List[Dict]:
        sql = '''
            SELECT DISTINCT opportunity_key, name, email, role
            FROM sf_opportunity_team_members
            WHERE opportunity_key = %(opportunity_key)s
        '''
        params = {'opportunity_key': opportunity_key}
        return self.q(sql, params)

    def get_survey(self, survey_id: uuid.UUID) -> Optional[Dict]:
        sql = '''
            SELECT
                s.id, s.opportunity_number, s.email, s.role, s.primary_loss_reason, s.competitive_loss_reason,
                s.technology_gap_type, s.perceived_poor_fit_reason, s.generated, s.completed,
                o.name opportunity_name, o.account_name, o.close_date, o.technology_ecosystem, o.sales_journey,
                o.competitors
            FROM op_debrief_surveys s
            LEFT JOIN sf_opportunities o ON o.opportunity_number = s.opportunity_number
            WHERE s.id = %(survey_id)s
        '''
        params = {'survey_id': survey_id}
        return self.q_one(sql, params)

    def get_surveys(self, email: str) -> List[Dict]:
        sql = '''
            SELECT
                s.id, s.opportunity_number, s.email, s.role, s.generated, s.completed,
                o.name, o.close_date,
                lower(s.email || ' ' || s.opportunity_number || ' ' || o.name) filter_value
            FROM op_debrief_surveys s
            LEFT JOIN sf_opportunities o ON s.opportunity_number = o.opportunity_number
        '''
        if not (self.has_permission(email, 'admin') or self.has_permission(email, 'survey-admin')):
            sql = f'{sql} WHERE email = %(email)s '
        sql = f'{sql} ORDER BY o.close_date DESC, s.opportunity_number, s.email'
        params = {'email': email}
        return self.q(sql, params)

    def update_op_debrief_tracking(self, last_check: datetime.datetime):
        sql = 'UPDATE op_debrief_tracking SET last_check = %(last_check)s WHERE only_row IS TRUE'
        params = {'last_check': last_check}
        self.u(sql, params)

    # migrations and metadata

    def add_schema_version(self, schema_version: int):
        self._version = schema_version
        sql = '''
            INSERT INTO schema_versions (schema_version, migration_timestamp)
            VALUES (%(schema_version)s, %(migration_timestamp)s)
        '''
        params = {
            'migration_timestamp': datetime.datetime.utcnow(),
            'schema_version': schema_version
        }
        self.u(sql, params)

    def reset(self):
        self.log.warning('Database reset requested, dropping all tables')
        for table in ('cloud_credentials', 'images', 'log_entries', 'op_debrief_surveys', 'op_debrief_tracking',
                      'permissions', 'sales_consultants', 'sales_reps', 'schema_versions', 'sf_opportunities',
                      'sf_opportunity_team_members', 'sync_tracking', 'virtual_machines'):
            self.u(f'DROP TABLE IF EXISTS {table} CASCADE ')

    def migrate(self):
        self.log.info(f'Database schema version is {self.version}')
        if self.version < 1:
            self.log.info('Migrating database to schema version 1')
            self.u('''
                CREATE TABLE schema_versions (
                    schema_version integer PRIMARY KEY,
                    migration_timestamp timestamp
                )
            ''')
            self.u('''
                CREATE TABLE virtual_machines (
                    id text PRIMARY KEY,
                    cloud text,
                    region text,
                    env_group text,
                    name text,
                    owner text,
                    state text,
                    private_ip inet,
                    public_ip inet,
                    type text,
                    running_schedule text,
                    active boolean
                )
            ''')
            self.u('''
                CREATE TABLE permissions (
                    email text PRIMARY KEY,
                    permissions text
                )
            ''')
            self.add_schema_version(1)
        if self.version < 2:
            self.log.info('Migrating database to schema version 2')
            # noinspection SqlResolve
            self.u('''
                ALTER TABLE virtual_machines
                RENAME COLUMN active TO visible
            ''')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN synced boolean
            ''')
            self.u('''
                CREATE TABLE sync_tracking (
                    only_row boolean PRIMARY KEY DEFAULT TRUE CONSTRAINT only_row_constraint CHECK (only_row),
                    syncing_now boolean,
                    last_sync_start timestamp,
                    last_sync_end timestamp
                )
            ''')
            self.u('INSERT INTO sync_tracking (syncing_now) VALUES (FALSE)')
            self.add_schema_version(2)
        if self.version < 3:
            self.log.info('Migrating database to schema version 3')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN created timestamp,
                ADD COLUMN state_transition_time timestamp
            ''')
            self.add_schema_version(3)
        if self.version < 4:
            self.log.info('Migrating database to schema version 4')
            self.u('''
                CREATE TABLE images (
                    id text PRIMARY KEY,
                    cloud text,
                    region text,
                    name text,
                    owner text,
                    state text,
                    created timestamp,
                    visible boolean,
                    synced boolean
                )
            ''')
            self.add_schema_version(4)
        if self.version < 5:
            self.log.info('Migrating database to schema version 5')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN application_env text,
                ADD COLUMN business_unit text
            ''')
            self.add_schema_version(5)
        if self.version < 6:
            self.log.info('Migrating database to schema version 6')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN contributors text
            ''')
            self.u('''
                ALTER TABLE images
                ADD COLUMN instanceid text
            ''')
            self.add_schema_version(6)
        if self.version < 7:
            self.log.info('Migrating database to schema version 7')
            self.u('''
                CREATE TABLE log_entries (
                    id uuid PRIMARY KEY,
                    log_time timestamp,
                    actor text,
                    action text
                )
            ''')
            self.add_schema_version(7)
        if self.version < 8:
            self.log.info('Migrating database to schema version 8')
            self.u('''
                UPDATE virtual_machines SET env_group = %(environment)s WHERE env_group IS NULL OR env_group = ''
            ''', {'environment': 'default-environment'})
            self.add_schema_version(8)
        if self.version < 9:
            self.log.info('Migrating database to schema version 9')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN dns_names text
            ''')
            self.add_schema_version(9)
        if self.version < 10:
            self.log.info('Migrating database to schema version 10')
            self.u('''
                ALTER TABLE images
                ADD COLUMN public boolean
            ''')
            self.add_schema_version(10)
        if self.version < 11:
            self.log.info('Migrating database to schema version 11')
            self.u('''
                CREATE TABLE sf_opportunities (
                    opportunity_key integer PRIMARY KEY,
                    id text,
                    opportunity_number text,
                    name text,
                    account_name text,
                    stage_name text,
                    close_date date,
                    last_modified_date timestamp,
                    technology_ecosystem text,
                    sales_journey text,
                    competitors text
                )
            ''')
            self.u('''
                CREATE TABLE sf_opportunity_team_members (
                    opportunity_team_member_key integer PRIMARY KEY,
                    opportunity_key integer,
                    name text,
                    email text,
                    role text
                )
            ''')
            self.u('''
                CREATE TABLE op_debrief_surveys (
                    id uuid PRIMARY KEY,
                    opportunity_number text,
                    email text,
                    role text,
                    primary_loss_reason text,
                    competitive_loss_reason text,
                    technology_gap_type text,
                    perceived_poor_fit_reason text,
                    generated timestamp,
                    completed timestamp
                )
            ''')
            self.u('''
                CREATE TABLE op_debrief_tracking (
                    only_row boolean PRIMARY KEY DEFAULT TRUE CONSTRAINT only_row_constraint CHECK (only_row),
                    last_check timestamp
                )
            ''')
            params = {'last_check': datetime.datetime.utcnow()}
            self.u('INSERT INTO op_debrief_tracking (last_check) VALUES (%(last_check)s)', params)
            self.add_schema_version(11)
        if self.version < 12:
            self.log.info('Migrating database to schema version 12')
            self.u('''
                CREATE TABLE sales_reps (
                    geo text,
                    area text,
                    sub_area text,
                    region text,
                    sub_region text,
                    territory_name text,
                    sales_rep text,
                    assigned_sc text,
                    synced boolean
                )
            ''')
            self.u('''
                CREATE TABLE sales_consultants (
                    name text PRIMARY KEY
                )
            ''')
            self.add_schema_version(12)
        if self.version < 13:
            self.log.info('Migrating database to schema version 13')
            self.u('''
                UPDATE sales_reps SET territory_name = '(DSG)' WHERE territory_name IS NULL
            ''')
            self.u('''
                ALTER TABLE sales_reps ADD PRIMARY KEY (territory_name, sales_rep)
            ''')
            self.add_schema_version(13)
        if self.version < 14:
            self.log.info('Migrating database to schema version 14')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN whitelist text
            ''')
            self.add_schema_version(14)
        if self.version < 15:
            self.log.info('Migrating database to schema version 15')
            self.u('''
                CREATE TABLE cloud_credentials (
                    id uuid PRIMARY KEY,
                    cloud text NOT NULL,
                    description text NOT NULL,
                    username text NOT NULL,
                    password text NOT NULL,
                    azure_tenant_id text
                )
            ''')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN account_id uuid
            ''')
            self.u('''
                ALTER TABLE images
                ADD COLUMN account_id uuid
            ''')
            self.add_schema_version(15)

    def _table_exists(self, table_name: str) -> bool:
        sql = 'SELECT count(*) table_count FROM information_schema.tables WHERE table_name = %(table_name)s'
        for record in self.q(sql, {'table_name': table_name}):
            if record['table_count'] == 0:
                return False
        return True

    @property
    def version(self) -> int:
        if self._version is None:
            self._version = 0
            if self._table_exists('schema_versions'):
                sql = 'SELECT max(schema_version) current_version FROM schema_versions'
                current_version: int = self.q_val(sql)
                if current_version is not None:
                    self._version = current_version
        return self._version
