import datetime
import fort
import ops_web.config
import uuid

from typing import Dict, List


class RepSCPairsDatabase(fort.PostgresDatabase):
    def get_rep_sc_pairs(self):
        sql = '''
            SELECT geo, area, sub_area, region, sub_region, coalesce(territory_name, '') territory_name,
                   employee_name rep_name, coalesce(assigned_sc, '') sc_name,
                   lower(geo || ' ' || area || ' ' || sub_area || ' ' || region || ' ' || sub_region || ' ' ||
                         coalesce(territory_name, '') || ' ' || employee_name) filter_value
            FROM sales_rep_sc_coverage
            WHERE geo = 'NA'
            ORDER BY geo, area, sub_area, region, sub_region, territory_name, rep_name
        '''
        return self.q(sql)

    def get_sales_consultants(self):
        sql = 'SELECT employee_name sc_name FROM presales_users ORDER BY employee_name'
        return self.q(sql)

    def set_rep_sc_pair(self, rep_name, sc_name):
        sql = 'UPDATE sales_rep_sc_coverage SET assigned_sc = %(sc_name)s WHERE employee_name = %(rep_name)s'
        self.u(sql, {'sc_name': sc_name, 'rep_name': rep_name})


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

    def can_control_machine(self, email: str, machine_id: str) -> bool:
        if self.has_permission(email, 'admin'):
            return True
        sql = '''
            SELECT id
            FROM virtual_machines
            WHERE id = %(id)s
              AND (owner = %(email)s OR position(%(email)s in contributors) > 0)
        '''
        controllable = self.q_one(sql, {'id': machine_id, 'email': email})
        return controllable is not None

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

    # environments and machines

    def get_environments(self, email: str) -> List[Dict]:
        if self.has_permission(email, 'admin'):
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
        else:
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
                WHERE (owner = %(email)s OR position(%(email)s in contributors) > 0)
                  AND visible IS TRUE
                GROUP BY cloud, env_group, owner
                ORDER BY env_group
            '''
        return self.q(sql, {'email': email})

    def get_machines_for_env(self, email: str, env_group: str) -> List[Dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                SELECT
                    id, cloud, region, env_group, name, owner, contributors, state, private_ip, public_ip, type,
                    running_schedule, application_env, business_unit, dns_names,
                    CASE WHEN state = 'running' THEN now() - created ELSE NULL END running_time
                FROM virtual_machines
                WHERE visible IS TRUE
                  AND env_group = %(env_group)s
                ORDER BY name
            '''
        else:
            sql = '''
                SELECT
                    id, cloud, region, env_group, name, owner, contributors, state, private_ip, public_ip, type,
                    running_schedule, application_env, business_unit, dns_names,
                    CASE WHEN state = 'running' THEN now() - created ELSE NULL END running_time
                FROM virtual_machines
                WHERE visible IS TRUE
                  AND env_group = %(env_group)s
                  AND (owner = %(email)s OR position(%(email)s in contributors) > 0)
                ORDER BY name
            '''
        return self.q(sql, {'email': email, 'env_group': env_group})

    def get_machine(self, machine_id: str) -> Dict:
        sql = '''
            SELECT
                id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                visible, synced, created, state_transition_time, application_env, business_unit, contributors, dns_names
            FROM virtual_machines
            WHERE id = %(id)s
        '''
        return self.q_one(sql, {'id': machine_id})

    def set_machine_created(self, machine_id: str, created):
        sql = 'UPDATE virtual_machines SET created = %(created)s WHERE id = %(id)s'
        self.u(sql, {'id': machine_id, 'created': created})

    def set_machine_public_ip(self, machine_id: str, public_ip: str):
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
                SELECT id, cloud, region, name, owner, state, created, coalesce(instanceid, '') instanceid,
                    lower(cloud || ' ' || coalesce(name, '') || ' ' || coalesce(owner, '')) filter_value 
                FROM images
                WHERE visible IS TRUE
                ORDER BY name
            '''
        else:
            sql = '''
                SELECT id, cloud, region, name, owner, state, created, coalesce(instanceid, '') instanceid,
                    lower(cloud || ' ' || coalesce(name, '') || ' ' || coalesce(owner, '')) filter_value
                FROM images
                WHERE visible IS TRUE
                AND owner = %(email)s
            '''
        return self.q(sql, {'email': email})

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
        #   'state_transition_time': '', 'application_env': '', 'business_unit': '', 'dns_names': ''
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
                    visible = TRUE, synced = TRUE
                WHERE id = %(id)s
            '''
        else:
            sql = '''
                INSERT INTO virtual_machines (
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    created, state_transition_time, application_env, business_unit, contributors, dns_names, visible,
                    synced
                ) VALUES (
                    %(id)s, %(cloud)s, %(region)s, %(environment)s, %(name)s, %(owner)s, %(state)s, %(private_ip)s,
                    %(public_ip)s, %(type)s, %(running_schedule)s, %(created)s, %(state_transition_time)s,
                    %(application_env)s, %(business_unit)s, %(contributors)s, %(dns_names)s, TRUE, TRUE
                )
            '''
        self.u(sql, params)

    def add_image(self, params: Dict):
        # params = {
        #   'id': '', 'cloud': '', 'region': '', 'name': '', 'owner': '', 'state': '', 'created': '', 'instanceid': ''
        # }
        sql = 'SELECT id FROM images WHERE id = %(id)s'
        if self.q(sql, params):
            sql = '''
                UPDATE images 
                SET cloud = %(cloud)s, region = %(region)s, name = %(name)s, owner = %(owner)s, state = %(state)s,
                    created = %(created)s, instanceid = %(instanceid)s, visible = TRUE, synced = TRUE
                WHERE id = %(id)s
            '''
        else:
            sql = '''
                INSERT INTO images (
                    id, cloud, region, name, owner, state, created, instanceid, visible, synced
                ) VALUES (
                    %(id)s, %(cloud)s, %(region)s, %(name)s, %(owner)s, %(state)s, %(created)s, %(instanceid)s, TRUE,
                    TRUE
                )
            '''
        self.u(sql, params)

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
        self.u('DROP TABLE IF EXISTS virtual_machines CASCADE')
        self.u('DROP TABLE IF EXISTS permissions CASCADE')
        self.u('DROP TABLE IF EXISTS schema_versions CASCADE')
        self.u('DROP TABLE IF EXISTS sync_tracking CASCADE')
        self.u('DROP TABLE IF EXISTS images CASCADE')
        self.u('DROP TABLE IF EXISTS log_entries CASCADE ')

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
