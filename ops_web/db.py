import datetime
import decimal
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
        sql = 'select email, permissions from permissions order by email'
        for record in self.q(sql):
            yield {'email': record['email'], 'permissions': record['permissions'].split()}

    def add_permission(self, email: str, permission: str):
        current_permissions = set(self.get_permissions(email))
        current_permissions.add(permission)
        self.set_permissions(email, sorted(current_permissions))

    def get_permissions(self, email: str) -> List[str]:
        sql = 'select permissions from permissions where email = %(email)s'
        permissions = self.q_val(sql, {'email': email})
        if permissions is None:
            return []
        return sorted(set(permissions.replace(',', ' ').split()))

    def set_permissions(self, email: str, permissions: List[str]):
        params = {'email': email, 'permissions': ' '.join(sorted(set(permissions)))}
        self.u('delete from permissions where email = %(email)s', params)
        if permissions:
            self.u('insert into permissions (email, permissions) values (%(email)s, %(permissions)s)', params)

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
            insert into log_entries (id, log_time, actor, action)
            values (%(id)s, %(log_time)s, %(actor)s, %(action)s)
        '''
        self.u(sql, params)

    def get_log_entries(self, limit: int = None):
        if limit is None:
            limit = 100
        params = {'limit': limit}
        sql = '''
            select id, log_time, actor, action, lower(actor || ' ' || action) filter_value
            from log_entries
            order by log_time desc
            limit %(limit)s
        '''
        return self.q(sql, params)

    # cloud credentials

    def add_cloud_credentials(self, params: Dict) -> uuid.UUID:
        sql = '''
            insert into cloud_credentials (id, cloud, description, username, password, azure_tenant_id)
            values (%(id)s, %(cloud)s, %(description)s, %(username)s, %(password)s, %(azure_tenant_id)s)
        '''
        params['id'] = uuid.uuid4()
        if params.get('cloud') == 'aws':
            params['azure_tenant_id'] = 'n/a'
        self.u(sql, params)
        return params['id']

    def delete_cloud_credentials(self, cred_id: uuid.UUID):
        params = {'id': cred_id}
        for sql in ['delete from cloud_credentials where id = %(id)s',
                    'update images set visible = false where account_id = %(id)s',
                    'update virtual_machines set visible = false where account_id = %(id)s']:
            self.u(sql, params)

    def get_cloud_credentials(self):
        sql = '''
            select id, cloud, description, username, azure_tenant_id
            from cloud_credentials
            order by cloud, description
        '''
        return self.q(sql)

    def get_all_credentials_for_use(self, cloud: str) -> List[Dict]:
        sql = '''
            select id, username, password, azure_tenant_id
            from cloud_credentials
            where cloud = %(cloud)s
        '''
        params = {'cloud': cloud}
        return self.q(sql, params)

    def get_one_credential_for_use(self, account_id: uuid.UUID) -> Dict:
        sql = '''
            select id, username, password, azure_tenant_id
            from cloud_credentials
            where id = %(id)s
        '''
        params = {'id': account_id}
        return self.q_one(sql, params)

    def update_cloud_credentials(self, params: Dict):
        if 'password' in params:
            sql = '''
                update cloud_credentials
                set cloud = %(cloud)s, description = %(description)s, username = %(username)s, password = %(password)s,
                    azure_tenant_id = %(azure_tenant_id)s
                where id = %(id)s
            '''
        else:
            sql = '''
                update cloud_credentials
                set cloud = %(cloud)s, description = %(description)s, username = %(username)s,
                    azure_tenant_id = %(azure_tenant_id)s
                where id = %(id)s
            '''
        self.u(sql, params)

    # environments and machines

    def get_env_list(self) -> List[str]:
        sql = '''
            select distinct env_group
            from virtual_machines
            where visible is true
            order by env_group
        '''
        return [r['env_group'] for r in self.q(sql)]

    def get_environments(self) -> List[Dict]:
        sql = '''
            select
                cloud,
                env_group,
                owner,
                sum(cost) as cost,
                sum(cost)::numeric cost_n,
                count(*) instance_count,
                bool_or(state = 'running') running,
                max(case when state = 'running' then now() - created else null end) running_time,
                lower(env_group || ' ' || owner || string_agg(id, ', ') ) filter_value
            from virtual_machines
            where visible is true
            group by cloud, env_group, owner
            order by env_group
        '''
        return self.q(sql)

    def get_own_environments(self, email: str) -> List[Dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                select
                    cloud,
                    env_group,
                    owner,
                    sum(cost) cost,
                    sum(cost)::numeric cost_n,
                    count(*) instance_count,
                    bool_or(state = 'running') running,
                    max(case when state = 'running' then now() - created else null end) running_time,
                    lower(env_group || ' ' || owner || string_agg(id, ', ') ) filter_value
                from virtual_machines
                where visible is true
                and cloud = 'aws'
                group by cloud, env_group, owner
                order by env_group
            '''
        else:
            sql = '''
                select  
                    cloud,
                    env_group,
                    owner,
                    sum(cost) cost,
                    sum(cost)::numeric cost_n,
                    count(*) instance_count,
                    bool_or(state = 'running') running,
                    max(case when state = 'running' then now() - created else null end) running_time,
                    lower(env_group || ' ' || owner || string_agg(id, ', ') ) filter_value
                from virtual_machines
                where visible is true
                and (owner = %(email)s) 
                and cloud = 'aws'
                group by cloud, env_group, owner
                order by env_group
            '''
        return self.q(sql, {'email': email})

    def get_instance_zone(self, machine_id: str):
        sql = 'select region from virtual_machines where id=%(id)s'
        return self.q_one(sql, {'id': machine_id})

    def get_all_visible_machines(self) -> List[Dict]:
        sql = '''
            select account_id, cloud, region, id
            from virtual_machines
            where visible is true
        '''
        return self.q(sql)

    def get_machines_for_env(self, email: str, env_group: str) -> List[Dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                select
                    id, cloud, region, env_group, name, owner, contributors, state, private_ip, public_ip, type,
                    running_schedule, application_env, business_unit, dns_names, whitelist, vpc, termination_protection,
                    cost, cost::numeric cost_n, account_id,
                    case when state = 'running' then now() - created else null end running_time,
                    true can_control,
                    true can_modify
                from virtual_machines
                where visible is true
                  and env_group = %(env_group)s
                order by name
            '''
        else:
            sql = '''
                select
                    id, cloud, region, env_group, name, owner, contributors, state, private_ip, public_ip, type,
                    running_schedule, application_env, business_unit, dns_names, whitelist, vpc, termination_protection,
                    cost, cost::numeric cost_n, account_id,
                    case when state = 'running' then now() - created else null end running_time,
                    owner = %(email)s or position(%(email)s in contributors) > 0 can_control,
                    owner = %(email)s can_modify
                from virtual_machines
                where visible is true
                  and env_group = %(env_group)s
                order by name
            '''
        return self.q(sql, {'email': email, 'env_group': env_group})

    def get_machine(self, machine_id: str, email: str = None) -> Dict:
        if email is None or self.has_permission(email, 'admin'):
            sql = '''
                select
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    visible, synced, created, state_transition_time, application_env, business_unit, contributors,
                    dns_names, whitelist, vpc, termination_protection, cost, cost::numeric cost_n, account_id,
                    case when state = 'running' then now() - created else null end running_time,
                    true can_control,
                    true can_modify
                from virtual_machines
                where id = %(id)s
            '''
        else:
            sql = '''
                select
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    visible, synced, created, state_transition_time, application_env, business_unit, contributors,
                    dns_names, whitelist, vpc, termination_protection, cost, cost::numeric cost_n, account_id,
                    case when state = 'running' then now() - created else null end running_time,
                    owner = %(email)s or position(%(email)s in contributors) > 0 can_control,
                    owner = %(email)s can_modify
                from virtual_machines
                where id = %(id)s
            '''
        return self.q_one(sql, {'id': machine_id, 'email': email})

    def set_machine_created(self, machine_id: str, created):
        sql = 'update virtual_machines set created = %(created)s where id = %(id)s'
        self.u(sql, {'id': machine_id, 'created': created})

    def set_machine_public_ip(self, machine_id: str, public_ip: str = None):
        sql = 'update virtual_machines set public_ip = %(public_ip)s where id = %(id)s'
        self.u(sql, {'id': machine_id, 'public_ip': public_ip})

    def set_machine_state(self, machine_id: str, state: str):
        params = {'id': machine_id, 'state': state}
        sql = 'update virtual_machines set state = %(state)s where id = %(id)s'
        self.u(sql, params)

    def set_machine_tags(self, params: Dict):
        # params = {
        #   'id': '', 'running_schedule': '', 'name': '', 'owner': '', 'contributors': '', 'application_env': '',
        #   'business_unit': '', 'environment': '', 'dns_names': ''
        # }
        sql = '''
            update virtual_machines
            set running_schedule = %(running_schedule)s, name = %(name)s, owner = %(owner)s,
                contributors = %(contributors)s, application_env = %(application_env)s,
                business_unit = %(business_unit)s, env_group = %(environment)s, dns_names = %(dns_names)s
            where id = %(id)s
        '''
        self.u(sql, params)

    def set_machine_termination_protection(self, machine_id: str, termination_protection: bool):
        sql = '''
            update virtual_machines
            set termination_protection = %(termination_protection)s
            where id = %(id)s
        '''
        params = {
            'id': machine_id,
            'termination_protection': termination_protection
        }
        self.u(sql, params)

    # images

    def get_groups(self, email: str) -> List[Dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                SELECT
                    id,
                    cloud,
                    inbound_rules,
                    group_name,
                    owner,
                    account_id,
                    lower(coalesce(id,'') || ' ' || coalesce(group_name, '') || ' ' || coalesce(owner, '')) filter_value 
                FROM security_group
                '''
        else:
            sql = '''
                SELECT
                    id,
                    cloud,
                    inbound_rules,
                    group_name,
                    owner,
                    account_id,
                    lower(coalesce(id,'') || ' ' || coalesce(group_name, '') || ' ' || coalesce(owner, '')) filter_value 
                FROM security_group
                WHERE 
                 (owner = %(email)s)
            '''
        return self.q(sql, {'email': email})

    def get_images(self, email: str) -> List[Dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                select
                    id,
                    cloud,
                    region,
                    name,
                    owner,
                    true can_modify,
                    state = 'available' and (cloud = 'aws' or cloud ='gcp') can_launch,
                    public,
                    state,
                    created,
                    account_id,
                    cost,
                    coalesce(instanceid, '') instanceid,
                    lower(cloud || ' ' || coalesce(name, '') || ' ' || coalesce(owner, '')) filter_value 
                from images
                where visible is true
                order by name
            '''
        else:
            sql = '''
                select
                    id,
                    cloud,
                    region,
                    name,
                    owner,
                    owner = %(email)s can_modify,
                    state = 'available' and (cloud = 'aws' or cloud ='gcp') can_launch,
                    public,
                    state,
                    created,
                    account_id,
                    cost,
                    coalesce(instanceid, '') instanceid,
                    lower(cloud || ' ' || coalesce(name, '') || ' ' || coalesce(owner, '')) filter_value
                from images
                where visible is true
                and (owner = %(email)s or public is true)
            '''
        return self.q(sql, {'email': email})

    def get_image(self, image_id: str) -> Dict:
        sql = '''
            select id, cloud, region, name, owner, public, state, created, visible, synced, instanceid, account_id, cost
            from images
            where id = %(id)s
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
                    whitelist = %(whitelist)s, vpc = %(vpc)s, cost = %(cost)s, account_id = %(account_id)s,
                    visible = TRUE, synced = TRUE
                WHERE id = %(id)s
            '''
        else:
            sql = '''
                INSERT INTO virtual_machines (
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    created, state_transition_time, application_env, business_unit, contributors, dns_names, whitelist,
                    vpc, cost, account_id, visible, synced
                ) VALUES (
                    %(id)s, %(cloud)s, %(region)s, %(environment)s, %(name)s, %(owner)s, %(state)s, %(private_ip)s,
                    %(public_ip)s, %(type)s, %(running_schedule)s, %(created)s, %(state_transition_time)s,
                    %(application_env)s, %(business_unit)s, %(contributors)s, %(dns_names)s, %(whitelist)s, %(vpc)s,
                    %(cost)s, %(account_id)s, TRUE, TRUE
                )
            '''
        self.u(sql, params)

    def add_image(self, params: Dict):
        # params = {
        #   'id': '', 'cloud': '', 'region': '', 'name': '', 'owner': '', 'state': '', 'created': '', 'instanceid': '',
        #   'public': (bool), 'account_id': ''
        # }
        sql = 'select id from images where id = %(id)s'
        if self.q(sql, params):
            sql = '''
                update images 
                set cloud = %(cloud)s, region = %(region)s, name = %(name)s, owner = %(owner)s, state = %(state)s,
                    public = %(public)s, created = %(created)s, instanceid = %(instanceid)s,
                    account_id = %(account_id)s, cost = %(cost)s, visible = true, synced = true
                where id = %(id)s
            '''
        else:
            sql = '''
                insert into images (
                    id, cloud, region, name, owner, public, state, created, instanceid, account_id, cost, visible,
                    synced
                ) values (
                    %(id)s, %(cloud)s, %(region)s, %(name)s, %(owner)s, %(public)s, %(state)s, %(created)s,
                    %(instanceid)s, %(account_id)s, %(cost)s, true, true
                )
            '''
        self.u(sql, params)

    def add_group(self, params: Dict):
        # params = {
        #   'id': '', 'cloud': '', 'owner':'', 'inbound_rules':'', 'group_name':'', 'account_id': ''
        # }

        sql = 'SELECT id FROM security_group WHERE id = %(id)s'
        if self.q(sql, params):
            sql = '''
                UPDATE security_group
                SET cloud = %(cloud)s, owner = %(owner)s, inbound_rules = %(inbound_rules)s,
                    group_name = %(group_name)s, account_id = %(account_id)s
                WHERE id = %(id)s
           '''
        else:
            sql = '''
                INSERT INTO security_group (
                    id, cloud, owner, inbound_rules, group_name, account_id
                ) VALUES (
                    %(id)s, %(cloud)s, %(owner)s, %(inbound_rules)s, %(group_name)s, %(account_id)s
                )
            '''
        self.u(sql, params)

    # sc assignments

    def get_rep_sc_pairs(self):
        sql = '''
            select
                geo, area, sub_area, region, sub_region, territory_name, sales_rep rep_name,
                c.name sc_name, c.employee_id sc_employee_id,
                lower(geo || ' ' || area || ' ' || sub_area || ' ' || region || ' ' || sub_region || ' ' ||
                      territory_name || ' ' || sales_rep || ' ' || coalesce(c.name, '')) filter_value
            from sales_reps r
            left join sc_rep_assignments a on a.rep_territory = r.territory_name
            left join sales_consultants c on c.employee_id = a.sc_employee_id
            order by geo, area, sub_area, region, sub_region, territory_name, rep_name
        '''
        return self.q(sql)

    def get_sales_consultants(self):
        sql = 'select name sc_name, employee_id from sales_consultants order by name'
        return self.q(sql)

    def set_rep_sc_pair(self, rep_territory, sc_employee_id):
        sql = '''
            select rep_territory, sc_employee_id
            from sc_rep_assignments
            where rep_territory = %(rep_territory)s
        '''
        params = {
            'rep_territory': rep_territory,
            'sc_employee_id': sc_employee_id
        }
        existing = self.q_one(sql, params)
        if existing is None:
            sql = '''
                insert into sc_rep_assignments (rep_territory, sc_employee_id)
                values (%(rep_territory)s, %(sc_employee_id)s)
            '''
        else:
            sql = '''
                update sc_rep_assignments
                set sc_employee_id = %(sc_employee_id)s
                where rep_territory = %(rep_territory)s
            '''
        self.u(sql, params)

    # opportunity debrief surveys

    def add_survey(self, opportunity_number: str, email: str, role: str) -> uuid.UUID:
        self.log.debug(f'Generating a survey for {opportunity_number} / {email}')
        sql = '''
            insert into op_debrief_surveys (id, opportunity_number, email, role, generated)
            values (%(id)s, %(opportunity_number)s, %(email)s, %(role)s, %(generated)s)
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

    def cancel_survey(self, survey_id: uuid.UUID):
        sql = '''
            update op_debrief_surveys
            set cancelled = true, completed = %(completed)s
            where id = %(id)s
        '''
        params = {'id': survey_id, 'completed': datetime.datetime.utcnow()}
        self.u(sql, params)

    def complete_survey(self, params: Dict):
        sql = '''
            update op_debrief_surveys
            set completed = %(completed)s,
                primary_loss_reason = %(primary_loss_reason)s,
                tg_runtime_performance = %(tg_runtime_performance)s,
                tg_runtime_stability = %(tg_runtime_stability)s,
                tg_runtime_missing_features = %(tg_runtime_missing_features)s,
                tg_runtime_compatibility = %(tg_runtime_compatibility)s,
                tg_runtime_ease_of_use = %(tg_runtime_ease_of_use)s,
                tg_design_time_performance = %(tg_design_time_performance)s,
                tg_design_time_stability = %(tg_design_time_stability)s,
                tg_design_time_missing_features = %(tg_design_time_missing_features)s,
                tg_design_time_compatibility = %(tg_design_time_compatibility)s,
                tg_design_time_ease_of_use = %(tg_design_time_ease_of_use)s,
                tg_connectivity_performance = %(tg_connectivity_performance)s,
                tg_connectivity_stability = %(tg_connectivity_stability)s,
                tg_connectivity_missing_features = %(tg_connectivity_missing_features)s,
                tg_connectivity_compatibility = %(tg_connectivity_compatibility)s,
                tg_connectivity_ease_of_use = %(tg_connectivity_ease_of_use)s,
                tg_install_performance = %(tg_install_performance)s,
                tg_install_stability = %(tg_install_stability)s,
                tg_install_missing_features = %(tg_install_missing_features)s,
                tg_install_compatibility = %(tg_install_compatibility)s,
                tg_install_ease_of_use = %(tg_install_ease_of_use)s,
                engaged_other_specialists = %(engaged_other_specialists)s,
                engaged_gcs = %(engaged_gcs)s,
                engaged_pm = %(engaged_pm)s,
                engaged_dev = %(engaged_dev)s,
                did_rfp = %(did_rfp)s,
                did_standard_demo = %(did_standard_demo)s,
                did_custom_demo = %(did_custom_demo)s,
                did_eval_trial = %(did_eval_trial)s,
                did_poc = %(did_poc)s,
                poc_outcome = %(poc_outcome)s,
                poc_failure_reason = %(poc_failure_reason)s,
                close_contacts = %(close_contacts)s
            where id = %(survey_id)s
        '''
        self.u(sql, params)

    def get_active_surveys(self, email: str) -> List[Dict]:
        sql = '''
            select
                s.id, s.opportunity_number, s.email, s.role, s.generated,
                o.name, o.close_date,
                lower(s.email || ' ' || s.opportunity_number || ' ' || o.name) filter_value
            from op_debrief_surveys s
            left join sf_opportunities o on s.opportunity_number = o.opportunity_number
            where s.completed is null
        '''
        if not self.has_permission(email, 'survey-admin'):
            sql = f'{sql} and email = %(email)s '
        sql = f'{sql} order by o.close_date desc, s.opportunity_number, s.email'
        params = {'email': email}
        return self.q(sql, params)

    def get_completed_surveys(self, email: str) -> List[Dict]:
        sql = '''
            select
                s.id, s.opportunity_number, s.email, s.role, s.generated, s.completed, s.cancelled,
                o.name, o.close_date,
                lower(s.email || ' ' || s.opportunity_number || ' ' || o.name) filter_value
            from op_debrief_surveys s
            left join sf_opportunities o on o.opportunity_number = s.opportunity_number
            where s.completed is not null
        '''
        if not self.has_permission(email, 'survey-admin'):
            sql = f'{sql} and email = %(email)s '
        sql = f'{sql} order by o.close_date desc, s.opportunity_number, s.email'
        params = {'email': email}
        return self.q(sql, params)

    def get_last_op_debrief_check(self) -> datetime.datetime:
        sql = 'select last_check from op_debrief_tracking'
        return self.q_val(sql)

    def get_modified_opportunities(self, since: datetime.datetime) -> List[Dict]:
        sql = '''
            select
                opportunity_key, id, opportunity_number, name, account_name, stage_name, close_date, last_modified_date,
                technology_ecosystem, sales_journey
            from sf_opportunities
            where last_modified_date > %(since)s
              and stage_name = 'Closed Lost'
              and close_date > current_date - interval '5' day
        '''
        params = {'since': since}
        return self.q(sql, params)

    def get_op_contacts(self, opportunity_number: str) -> List[Dict]:
        sql = '''
            select distinct c.opportunity_key, c.contact_key, c.name, c.title, c.phone, c.email, c.is_primary
            from sf_opportunity_contacts c
            join sf_opportunities o on o.opportunity_key = c.opportunity_key
            where o.opportunity_number = %(opportunity_number)s
        '''
        params = {'opportunity_number': opportunity_number}
        return self.q(sql, params)

    def get_op_numbers_for_existing_surveys(self) -> Set[str]:
        sql = 'select distinct opportunity_number from op_debrief_surveys'
        return set([r.get('opportunity_number') for r in self.q(sql)])

    def get_op_team_members(self, opportunity_key: int) -> List[Dict]:
        sql = '''
            select distinct opportunity_key, name, email, role
            from sf_opportunity_team_members
            where opportunity_key = %(opportunity_key)s
        '''
        params = {'opportunity_key': opportunity_key}
        return self.q(sql, params)

    def get_roles(self):
        sql = 'select distinct role from sf_opportunity_team_members where role is not null'
        current_sf_roles = [r.get('role') for r in self.q(sql)]
        sql = 'select id, role_name, generate_survey, ignore from op_debrief_roles'
        known_roles = {r.get('role_name'): r for r in self.q(sql)}
        for sf_role in current_sf_roles:
            if sf_role not in known_roles:
                sql = 'insert into op_debrief_roles (id, role_name) values (%(id)s, %(role_name)s)'
                params = {'id': uuid.uuid4(), 'role_name': sf_role}
                self.u(sql, params)
        sql = 'select id, role_name, generate_survey, ignore from op_debrief_roles'
        return self.q(sql)

    def get_survey(self, survey_id: uuid.UUID) -> Optional[Dict]:
        sql = '''
            select
                s.id, s.opportunity_number, s.email, s.generated, s.completed, s.role, s.primary_loss_reason,
                s.tg_runtime_performance, s.tg_runtime_stability, s.tg_runtime_missing_features,
                s.tg_runtime_compatibility, s.tg_runtime_ease_of_use, s.tg_design_time_performance,
                s.tg_design_time_stability, s.tg_design_time_missing_features, s.tg_design_time_compatibility,
                s.tg_design_time_ease_of_use, s.tg_connectivity_performance, s.tg_connectivity_stability,
                s.tg_connectivity_missing_features, s.tg_connectivity_compatibility, s.tg_connectivity_ease_of_use,
                s.tg_install_performance, s.tg_install_stability, s.tg_install_missing_features,
                s.tg_install_compatibility, s.tg_install_ease_of_use, s.engaged_other_specialists, s.engaged_gcs,
                s.engaged_pm, s.engaged_dev, s.did_rfp, s.did_standard_demo, s.did_custom_demo, s.did_eval_trial,
                s.did_poc, s.poc_outcome, s.poc_failure_reason, s.close_contacts, s.cancelled,
                o.name opportunity_name, o.account_name, o.close_date, o.technology_ecosystem, o.sales_journey,
                o.competitors, o.id opportunity_id
            from op_debrief_surveys s
            left join sf_opportunities o on o.opportunity_number = s.opportunity_number
            where s.id = %(survey_id)s
        '''
        params = {'survey_id': survey_id}
        return self.q_one(sql, params)

    def get_surveys_for_reminding(self, generated_before: datetime.datetime = None) -> List[Dict]:
        if generated_before is None:
            generated_before = datetime.datetime.utcnow() - datetime.timedelta(days=7)
        params = {'generated_before': generated_before}
        sql = '''
            select o.account_name, o.name, o.opportunity_number, s.role, s.id, s.email
            from op_debrief_surveys s
            left join sf_opportunities o on o.opportunity_number = s.opportunity_number
            where s.generated < %(generated_before)s
            and s.completed is null
            and s.reminder_sent is false
        '''
        return self.q(sql, params)

    def search_for_survey(self, email: str, opportunity_number: str) -> uuid.UUID:
        sql = '''
            select id from op_debrief_surveys
            where opportunity_number = %(opportunity_number)s
            and email = %(email)s
        '''
        params = {
            'opportunity_number': opportunity_number,
            'email': email
        }
        return self.q_val(sql, params)

    def set_survey_reminder_sent(self, survey_id: uuid):
        sql = '''
            update op_debrief_surveys
            set reminder_sent = true
            where id = %(id)s
        '''
        params = {'id': survey_id}
        self.u(sql, params)

    def update_op_debrief_tracking(self, last_check: datetime.datetime):
        sql = 'update op_debrief_tracking set last_check = %(last_check)s where only_row is true'
        params = {'last_check': last_check}
        self.u(sql, params)

    def update_roles(self, selected_roles: List):
        sql = 'update op_debrief_roles set generate_survey = false where generate_survey is true'
        self.u(sql)
        sql = 'update op_debrief_roles set generate_survey = true where id = %(id)s'
        for role_id in selected_roles:
            self.u(sql, {'id': role_id})

    # cost reporting

    def add_cost_data(self, resource_identifier: str, unblended_cost: str):
        sql = '''
            insert into cost_data (resource_id, unblended_cost, synced)
            values (%(resource_id)s, %(unblended_cost)s, true)
            on conflict (resource_id) do update set unblended_cost = %(unblended_cost)s, synced = true
        '''
        params = {
            'resource_id': resource_identifier,
            'unblended_cost': unblended_cost
        }
        self.u(sql, params)

    def cost_data_pre_sync(self):
        sql = 'update cost_data set synced = false where synced is true'
        self.u(sql)

    def cost_data_post_sync(self):
        sql = 'delete from cost_data where synced is false'
        self.u(sql)

    def get_cost_for_resource(self, resource_id: str) -> decimal.Decimal:
        sql = '''
            select coalesce(sum(unblended_cost), '0')::numeric
            from cost_data
            where position(lower(%(resource_id)s) in lower(resource_id)) > 0
        '''
        params = {'resource_id': resource_id}
        return self.q_val(sql, params)

    # environment usage events

    def add_environment_usage_event(self, params: Dict):
        sql = '''
            insert into environment_usage_events (
                id, environment_name, event_name, user_name, event_time
            ) values (
                %(id)s, %(environment_name)s, %(event_name)s, %(user_name)s, %(event_time)s
            )
        '''
        params.update({
            'id': uuid.uuid4(),
            'event_time': datetime.datetime.utcnow()
        })
        self.u(sql, params)

    # settings

    def get_setting(self, setting_id: str) -> Optional[str]:
        sql = '''select setting_value from settings where setting_id = %(setting_id)s'''
        params = {'setting_id': setting_id}
        return self.q_val(sql, params)

    def set_setting(self, setting_id: str, setting_value: str):
        sql = '''
            insert into settings (setting_id, setting_value)
            values (%(setting_id)s, %(setting_value)s)
            on conflict (setting_id) do update set setting_value = %(setting_value)s
        '''
        params = {'setting_id': setting_id, 'setting_value': setting_value}
        self.u(sql, params)

    # migrations and metadata

    def add_schema_version(self, schema_version: int):
        self._version = schema_version
        sql = '''
            insert into schema_versions (schema_version, migration_timestamp)
            values (%(schema_version)s, %(migration_timestamp)s)
        '''
        params = {
            'migration_timestamp': datetime.datetime.utcnow(),
            'schema_version': schema_version
        }
        self.u(sql, params)

    def reset(self):
        self.log.warning('Database reset requested, dropping all tables')
        for table in ('cloud_credentials', 'cost_data', 'cost_tracking', 'environment_usage_events', 'images',
                      'log_entries', 'op_debrief_roles', 'op_debrief_surveys', 'op_debrief_tracking', 'permissions',
                      'sales_consultants', 'sales_reps', 'sc_rep_assignments', 'schema_versions', 'security_group',
                      'settings', 'sf_opportunities', 'sf_opportunity_contacts', 'sf_opportunity_team_members',
                      'sync_tracking', 'virtual_machines'):
            self.u(f'drop table if exists {table} cascade ')

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
        if self.version < 16:
            self.log.info('Migrating database to schema version 16')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN vpc text
            ''')
            self.u('''
               CREATE TABLE security_group (
                   id text,
                   cloud text,
                   owner text,
                   inbound_rules text,
                   group_name text,
                   account_id uuid 
               )
           ''')
            self.add_schema_version(16)
        if self.version < 17:
            self.log.info('Migrating database to schema version 17')
            self.u('''
                CREATE TABLE sf_opportunity_contacts (
                    opportunity_contact_key integer primary key,
                    opportunity_key integer,
                    contact_key integer,
                    name text,
                    title text,
                    phone text,
                    email text,
                    is_primary boolean
                )
            ''')
            self.u('''
                ALTER TABLE op_debrief_surveys
                DROP COLUMN competitive_loss_reason,
                DROP COLUMN technology_gap_type,
                DROP COLUMN perceived_poor_fit_reason,
                ADD COLUMN tg_runtime_performance boolean,
                ADD COLUMN tg_runtime_stability boolean,
                ADD COLUMN tg_runtime_missing_features boolean,
                ADD COLUMN tg_runtime_compatibility boolean,
                ADD COLUMN tg_runtime_ease_of_use boolean,
                ADD COLUMN tg_design_time_performance boolean,
                ADD COLUMN tg_design_time_stability boolean,
                ADD COLUMN tg_design_time_missing_features boolean,
                ADD COLUMN tg_design_time_compatibility boolean,
                ADD COLUMN tg_design_time_ease_of_use boolean,
                ADD COLUMN tg_connectivity_performance boolean,
                ADD COLUMN tg_connectivity_stability boolean,
                ADD COLUMN tg_connectivity_missing_features boolean,
                ADD COLUMN tg_connectivity_compatibility boolean,
                ADD COLUMN tg_connectivity_ease_of_use boolean,
                ADD COLUMN tg_install_performance boolean,
                ADD COLUMN tg_install_stability boolean,
                ADD COLUMN tg_install_missing_features boolean,
                ADD COLUMN tg_install_compatibility boolean,
                ADD COLUMN tg_install_ease_of_use boolean,
                ADD COLUMN engaged_other_specialists boolean,
                ADD COLUMN engaged_gcs boolean,
                ADD COLUMN engaged_pm boolean,
                ADD COLUMN engaged_dev boolean,
                ADD COLUMN did_rfp boolean,
                ADD COLUMN did_standard_demo boolean,
                ADD COLUMN did_custom_demo boolean,
                ADD COLUMN did_eval_trial boolean,
                ADD COLUMN did_poc boolean,
                ADD COLUMN poc_outcome text,
                ADD COLUMN close_contacts text
            ''')
            self.add_schema_version(17)
        if self.version < 18:
            self.log.info('Migrating database to schema version 18')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN disable_termination text
            ''')
            self.add_schema_version(18)
        if self.version < 19:
            self.log.info('Migrating database to schema version 19')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN cost text
            ''')
            self.add_schema_version(19)
        if self.version < 20:
            self.log.info('Migrating database to schema version 20')
            self.u('''
                CREATE TABLE cost_tracking (
                    only_row boolean PRIMARY KEY DEFAULT TRUE CONSTRAINT only_row_constraint CHECK (only_row),
                    last_check timestamp,
                    report_id text
                )
            ''')
            self.add_schema_version(20)
        if self.version < 21:
            self.log.info('Migrating database to schema version 21')
            self.u('''
                ALTER TABLE virtual_machines
                DROP COLUMN disable_termination
            ''')
            self.u('''
                ALTER TABLE virtual_machines
                ADD COLUMN termination_protection boolean
            ''')
            self.add_schema_version(21)
        if self.version < 22:
            self.log.info('Migrating database to schema version 22')
            self.u('''
                CREATE TABLE environment_usage_events (
                    id uuid primary key,
                    environment_name text,
                    event_name text,
                    user_name text,
                    event_time timestamp
                )
            ''')
            self.add_schema_version(22)
        if self.version < 23:
            self.log.info('Migrating database to schema version 23')
            self.u('''
                CREATE TABLE op_debrief_roles (
                    id uuid primary key,
                    role_name text,
                    generate_survey boolean DEFAULT FALSE,
                    ignore boolean DEFAULT FALSE
                )
            ''')
            self.add_schema_version(23)
        if self.version < 24:
            self.log.info('Migrating database to schema version 24')
            self.u('''
                alter table sales_consultants
                add column employee_id text
            ''')
            self.u('''
                alter table sales_reps
                add column employee_id text,
                add column employee_email text
            ''')
            self.add_schema_version(24)
        if self.version < 25:
            self.log.info('Migrating database to schema version 25')
            self.u('''
                create table sc_region_assignments (
                    sc_employee_id text primary key,
                    region text
                )
            ''')
            self.u('''
                create table sf_regions (
                    geo text,
                    area text,
                    sub_area text,
                    region text
                )
            ''')
            self.add_schema_version(25)
        if self.version < 26:
            self.log.info('Migrating to database schema version 26')
            self.u('''
                drop table sc_region_assignments
            ''')
            self.u('''
                drop table sf_regions
            ''')
            self.add_schema_version(26)
        if self.version < 27:
            self.log.info('Migrating to database schema version 27')
            self.u('''
                create table sc_rep_assignments (
                    rep_territory text,
                    sc_employee_id text
                )
            ''')
            self.u('''
                insert into sc_rep_assignments
                select r.territory_name rep_territory, c.employee_id sc_employee_id
                from sales_reps r
                join sales_consultants c on c.name = r.assigned_sc
            ''')
            self.add_schema_version(27)
        if self.version < 28:
            self.log.info('Migrating to database schema version 28')
            self.u('''
                alter table sales_consultants
                add column sc_email text
            ''')
            self.u('''
                alter table sales_consultants
                drop constraint sales_consultants_pkey
            ''')
            self.u('''
                alter table sales_consultants
                add constraint sales_consultants_pkey primary key (employee_id)
            ''')
            self.add_schema_version(28)
        if self.version < 29:
            self.log.info('Migrating to database schema version 29')
            self.u('''
                alter table op_debrief_surveys
                add column poc_failure_reason text
            ''')
            self.add_schema_version(29)
        if self.version < 30:
            self.log.info('Migrating to database schema version 30')
            self.u('''
                alter table op_debrief_surveys
                add column reminder_sent boolean not null default false
            ''')
            self.add_schema_version(30)
        if self.version < 31:
            self.log.info('Migrating to database schema version 31')
            self.u('''
                alter table op_debrief_surveys
                add column cancelled boolean not null default false
            ''')
            self.add_schema_version(31)
        if self.version < 32:
            self.log.info('Migrating to database schema version 32')
            self.u('''
                create table cost_data (
                    resource_id text primary key,
                    unblended_cost money,
                    synced boolean
                )
            ''')
            self.add_schema_version(32)
        if self.version < 33:
            self.log.info('Migrating to database schema version 33')
            self.u('''
                create table settings (
                    setting_id text primary key,
                    setting_value text
                )
            ''')
            self.add_schema_version(33)
        if self.version < 34:
            self.log.info('Migrating to database schema version 34')
            self.u('''
                alter table images
                add column cost money
            ''')
            self.add_schema_version(34)
        if self.version < 35:
            self.log.info('Migrating to database schema version 35')
            self.u('''
                alter table virtual_machines
                alter column cost type money using cost::money
            ''')
            self.add_schema_version(35)

    def _table_exists(self, table_name: str) -> bool:
        sql = 'select count(*) table_count from information_schema.tables where table_name = %(table_name)s'
        for record in self.q(sql, {'table_name': table_name}):
            if record['table_count'] == 0:
                return False
        return True

    @property
    def version(self) -> int:
        if self._version is None:
            self._version = 0
            if self._table_exists('schema_versions'):
                sql = 'select max(schema_version) current_version from schema_versions'
                current_version: int = self.q_val(sql)
                if current_version is not None:
                    self._version = current_version
        return self._version
