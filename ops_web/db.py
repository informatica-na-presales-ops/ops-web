import collections
import datetime
import decimal
import fort
import ops_web.config
import statistics
import uuid

from typing import Optional


class Settings(dict):
    def __init__(self, db: 'Database'):
        super().__init__()
        self.db = db
        self.update(self.db.get_all_settings())

    @property
    def allow_users_to_delete_images(self) -> bool:
        return self.get('allow-users-to-delete-images', 'false') == 'true'

    @allow_users_to_delete_images.setter
    def allow_users_to_delete_images(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'allow-users-to-delete-images': str_value})
        self.db.set_setting('allow-users-to-delete-images', str_value)

    @property
    def app_env_values(self) -> list:
        default = (
            'DEMO',
            'DEV',
            'ENABLEMENT',
            'EVENT',
            'POC',
            'PROD',
            'QA',
            'TEST',
            'WORKSHOP'
        )
        str_default = '\n'.join(default)
        return sorted(set(self.get('app-env-values', str_default).splitlines()))

    @app_env_values.setter
    def app_env_values(self, value: list):
        str_value = '\n'.join(sorted(set(value)))
        self.update({'app-env-values': str_value})
        self.db.set_setting('app-env-values', str_value)

    @property
    def cloudability_auth_token(self) -> str:
        return self.get('cloudability-auth-token', '')

    @cloudability_auth_token.setter
    def cloudability_auth_token(self, value: str):
        self.update({'cloudability-auth-token': value})
        self.db.set_setting('cloudability-auth-token', value)

    @property
    def cloudability_vendor_account_ids(self) -> set:
        return set(self.get('cloudability-vendor-account-ids', '').split())

    @cloudability_vendor_account_ids.setter
    def cloudability_vendor_account_ids(self, value: set):
        str_value = ' '.join(value)
        self.update({'cloudability-vendor-account-ids': str_value})
        self.db.set_setting('cloudability-vendor-account-ids', str_value)

    @property
    def image_name_display_length(self) -> int:
        return int(self.get('image-name-display-length', 255))

    @image_name_display_length.setter
    def image_name_display_length(self, value: int):
        self.update({'image-name-display-length': str(value)})
        self.db.set_setting('image-name-display-length', str(value))

    @property
    def unity_support_group_id(self):
        return int(self.get('unity-support-group-id', 0))

    @unity_support_group_id.setter
    def unity_support_group_id(self, value):
        self.update({'unity-support-group-id': str(value)})
        self.db.set_setting('unity-support-group-id', str(value))

    @property
    def seas_support_group_id(self):
        return int(self.get('seas-support-group-id', 0))

    @seas_support_group_id.setter
    def seas_support_group_id(self, value):
        self.update({'seas-support-group-id': str(value)})
        self.db.set_setting('seas-support-group-id', str(value))

    @property
    def show_account_for_images(self) -> bool:
        return self.get('show-account-for-images', 'false') == 'true'

    @show_account_for_images.setter
    def show_account_for_images(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-account-for-images': str_value})
        self.db.set_setting('show-account-for-images', str_value)

    @property
    def show_all_images(self) -> bool:
        return self.get('show-all-images', 'false') == 'true'

    @show_all_images.setter
    def show_all_images(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-account-for-images': str_value})
        self.db.set_setting('show-all-images', str_value)

    @property
    def show_competency_link(self) -> bool:
        return self.get('show-competency-link', 'false') == 'true'

    @show_competency_link.setter
    def show_competency_link(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-competency-link': str_value})
        self.db.set_setting('show-competency-link', str_value)

    @property
    def show_op_debrief_survey_link(self) -> bool:
        return self.get('show-op-debrief-survey-link', 'false') == 'true'

    @show_op_debrief_survey_link.setter
    def show_op_debrief_survey_link(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-op-debrief-survey-link': str_value})
        self.db.set_setting('show-op-debrief-survey-link', str_value)

    @property
    def show_sap_access_link(self) -> bool:
        return self.get('show-sap-access-link', 'false') == 'true'

    @show_sap_access_link.setter
    def show_sap_access_link(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-sap-access-link': str_value})
        self.db.set_setting('show-sap-access-link', str_value)

    @property
    def show_sc_assignments_link(self) -> bool:
        return self.get('show-sc-assignments-link', 'false') == 'true'

    @show_sc_assignments_link.setter
    def show_sc_assignments_link(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-sc-assignments-link': str_value})
        self.db.set_setting('show-sc-assignments-link', str_value)

    @property
    def show_seas_request_link(self) -> bool:
        return self.get('show-seas-request-link', 'false') == 'true'

    @show_seas_request_link.setter
    def show_seas_request_link(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-seas-request-link': str_value})
        self.db.set_setting('show-seas-request-link', str_value)

    @property
    def show_security_groups_link(self) -> bool:
        return self.get('show-security-groups-link', 'false') == 'true'

    @show_security_groups_link.setter
    def show_security_groups_link(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-security-groups-link': str_value})
        self.db.set_setting('show-security-groups-link', str_value)

    @property
    def show_unity_request_link(self) -> bool:
        return self.get('show-unity-request-link', 'false') == 'true'

    @show_unity_request_link.setter
    def show_unity_request_link(self, value: bool):
        str_value = 'true' if value else 'false'
        self.update({'show-unity-request-link': str_value})
        self.db.set_setting('show-unity-request-link', str_value)

    @property
    def zendesk_api_token(self):
        return self.get('zendesk-api-token', '')

    @zendesk_api_token.setter
    def zendesk_api_token(self, value):
        self.update({'zendesk-api-token': value})
        self.db.set_setting('zendesk-api-token', value)

    @property
    def zendesk_company(self):
        return self.get('zendesk-company', '')

    @zendesk_company.setter
    def zendesk_company(self, value):
        self.update({'zendesk-company': value})
        self.db.set_setting('zendesk-company', value)

    @property
    def zendesk_email_address(self):
        return self.get('zendesk-email-address', '')

    @zendesk_email_address.setter
    def zendesk_email_address(self, value):
        self.update({'zendesk-email-address': value})
        self.db.set_setting('zendesk-email-address', value)

    @property
    def zendesk_widget_key(self):
        return self.get('zendesk-widget-key', '')

    @zendesk_widget_key.setter
    def zendesk_widget_key(self, value):
        self.update({'zendesk-widget-key': value})
        self.db.set_setting('zendesk-widget-key', value)


class Database(fort.PostgresDatabase):
    _version: int = None

    def __init__(self, config: ops_web.config.Config):
        super().__init__(config.db, maxconn=config.db_max_connections)
        self.config = config

    # users and permissions

    def bootstrap_admin(self):
        if self.config.bootstrap_admin in (None, ''):
            return
        self.log.info(f'Adding a bootstrap admin: {self.config.bootstrap_admin}')
        self.add_permission(self.config.bootstrap_admin, 'admin')

    def get_all_permissions(self) -> dict[str, set]:
        sql = 'select email, permissions from permissions order by email'
        return {r.get('email'): set(r.get('permissions').split()) for r in self.q(sql)}

    def add_permission(self, email: str, permission: str):
        current_permissions = self.get_permissions(email)
        if permission in current_permissions:
            return
        current_permissions.add(permission)
        self.set_permissions(email, current_permissions)

    def get_permissions(self, email: str) -> set[str]:
        _all_permissions = self.get_all_permissions()
        return _all_permissions.get(email, set())

    def set_permissions(self, email: str, permissions: set[str]):
        current_permissions = self.get_permissions(email)
        if current_permissions == permissions:
            return
        if permissions:
            sql = '''
                insert into permissions (email, permissions) values (%(email)s, %(permissions)s)
                on conflict (email) do update set permissions = %(permissions)s
            '''
        else:
            sql = 'delete from permissions where email = %(email)s'
        params = {'email': email, 'permissions': ' '.join(sorted(permissions))}
        self.u(sql, params)

    def has_permission(self, email: str, permission: str) -> bool:
        return permission in self.get_permissions(email)

    def is_manager(self, email: str) -> bool:
        sql = 'select is_manager from employees where employee_email = %(email)s'
        params = {'email': email}
        val = self.q_val(sql, params)
        if val is None:
            return False
        return val

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

    def add_cloud_credentials(self, params: dict) -> uuid.UUID:
        sql = '''
            insert into cloud_credentials (
                id, cloud, description, username, password, azure_tenant_id, default_environment_name
            ) values (
                %(id)s, %(cloud)s, %(description)s, %(username)s, %(password)s, %(azure_tenant_id)s,
                %(default_environment_name)s
            )
        '''
        params['id'] = uuid.uuid4()
        if params.get('cloud') in ('aws', 'gcp'):
            params['azure_tenant_id'] = 'n/a'
        self.u(sql, params)
        return params['id']

    def delete_cloud_credentials(self, cred_id: uuid.UUID):
        params = {'id': cred_id}
        for sql in ['delete from cloud_credentials where id = %(id)s',
                    'update images set visible = false where account_id = %(id)s',
                    'update virtual_machines set visible = false where account_id = %(id)s',
                    'update security_group set visible = false where account_id = %(id)s']:
            self.u(sql, params)

    def get_cloud_credentials(self):
        sql = '''
            select id, cloud, description, username, azure_tenant_id, default_environment_name
            from cloud_credentials
            order by cloud, description
        '''
        return self.q(sql)

    def get_all_credentials_for_use(self, cloud: str) -> list[dict]:
        sql = '''
            select id, username, password, azure_tenant_id, default_environment_name
            from cloud_credentials
            where cloud = %(cloud)s
        '''
        params = {'cloud': cloud}
        return self.q(sql, params)

    def get_one_credential_for_use(self, account_id: uuid.UUID) -> dict:
        sql = '''
            select id, username, password, azure_tenant_id, default_environment_name
            from cloud_credentials
            where id = %(id)s
        '''
        params = {'id': account_id}
        return self.q_one(sql, params)

    def update_cloud_credentials(self, params: dict):
        if 'password' in params:
            sql = '''
                update cloud_credentials
                set cloud = %(cloud)s, description = %(description)s, username = %(username)s, password = %(password)s,
                    azure_tenant_id = %(azure_tenant_id)s, default_environment_name = %(default_environment_name)s
                where id = %(id)s
            '''
        else:
            sql = '''
                update cloud_credentials
                set cloud = %(cloud)s, description = %(description)s, username = %(username)s,
                    azure_tenant_id = %(azure_tenant_id)s, default_environment_name = %(default_environment_name)s
                where id = %(id)s
            '''
        self.u(sql, params)

    # environments and machines

    def get_env_list(self) -> list[str]:
        sql = '''
            select distinct env_group
            from virtual_machines
            where visible is true
            order by env_group
        '''
        return [r['env_group'] for r in self.q(sql)]

    def get_environments(self) -> list[dict]:
        sql = '''
            select
                cloud,
                env_group,
                owner,
                sum(cost) as cost,
                sum(cost)::numeric cost_n,
                count(*) instance_count,
                bool_or(state = 'running') running,
                max(case when state = 'running' then now() - created end) running_time,
                lower(env_group || ' ' || owner || string_agg(id, ', ') ) filter_value
            from virtual_machines
            where visible is true
            group by cloud, env_group, owner
            order by env_group
        '''
        return self.q(sql)

    def get_own_environments(self, email: str) -> list[dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                select
                    cloud,
                    env_group,
                    owner,
                    sum(cost) as cost,
                    sum(cost)::numeric cost_n,
                    count(*) instance_count,
                    bool_or(state = 'running') running,
                    max(case when state = 'running' then now() - created end) running_time,
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
                    sum(cost) as cost,
                    sum(cost)::numeric cost_n,
                    count(*) instance_count,
                    bool_or(state = 'running') running,
                    max(case when state = 'running' then now() - created end) running_time,
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
        sql = 'select region from virtual_machines where id = %(id)s'
        return self.q_one(sql, {'id': machine_id})

    def get_all_visible_machines(self) -> list[dict]:
        sql = '''
            select account_id, cloud, region, id
            from virtual_machines
            where visible is true
        '''
        return self.q(sql)

    def get_machines_for_env(self, email: str, env_group: str) -> list[dict]:
        if self.has_permission(email, 'admin'):
            sql = '''
                select
                    cc.description, vm.id, vm.cloud, region, env_group, name, owner, contributors, state, private_ip,
                    public_ip, type, running_schedule, state_transition_time,application_env, application_role, business_unit, dns_names,
                    whitelist, vpc, termination_protection, cost, cost::numeric cost_n, account_id,
                    lower(concat_ws(' ', vm.id, name, owner)) filter_value,
                    case when state = 'stopped' then CAST(CAST(now() as DATE) - CAST(state_transition_time as DATE) as INTEGER ) end transition_time,
                    case when state = 'running' then now() - created end running_time,
                    true can_control, true can_modify
                from virtual_machines vm
                join cloud_credentials cc on vm.account_id = cc.id
                where visible is true
                and env_group = %(env_group)s
                order by name
            '''
        else:
            sql = '''
                select
                    cc.description, vm.id, vm.cloud, region, env_group, name, owner, contributors, state, private_ip,
                    public_ip, type, running_schedule, state_transition_time, application_env, application_role, business_unit, dns_names,
                    whitelist, vpc, termination_protection, cost, cost::numeric cost_n, account_id,
                    lower(concat_ws(' ', vm.id, name, owner)) filter_value,
                    case when state = 'stopped' then CAST(CAST(now() as DATE) - CAST(state_transition_time as DATE) as INTEGER ) end transition_time,
                    case when state = 'running' then now() - created end running_time,
                    owner = %(email)s or position(%(email)s in contributors) > 0 can_control,
                    owner = %(email)s can_modify
                from virtual_machines vm
                join cloud_credentials cc on vm.account_id = cc.id
                where visible is true
                and env_group = %(env_group)s
                order by name
            '''
        return self.q(sql, {'email': email, 'env_group': env_group})

    def get_machine(self, machine_id: str, email: str = None) -> dict:
        if email is None or self.has_permission(email, 'admin'):
            sql = '''
                select
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    visible, synced, created, state_transition_time, application_env, application_role, business_unit,
                    contributors, dns_names, whitelist, vpc, termination_protection, cost, cost::numeric cost_n,
                    account_id, case when state = 'stopped' then CAST(CAST(now() as DATE) - CAST(state_transition_time as DATE) as INTEGER ) end transition_time, case when state = 'running' then now() - created end running_time, true can_control,
                    true can_modify
                from virtual_machines
                where id = %(id)s
            '''
        else:
            sql = '''
                select
                    id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                    visible, synced, created, state_transition_time, application_env, application_role, business_unit,
                    contributors, dns_names, whitelist, vpc, termination_protection, cost, cost::numeric cost_n,
                    account_id, case when state = 'stopped' then CAST(CAST(now() as DATE) - CAST(state_transition_time as DATE) as INTEGER ) end transition_time, case when state = 'running' then now() - created end running_time,
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

    def set_machine_tags(self, params: dict):
        sql = '''
            update virtual_machines
            set running_schedule = %(running_schedule)s, name = %(name)s, owner = %(owner)s,
                contributors = %(contributors)s, application_env = %(application_env)s,
                application_role = %(application_role)s, business_unit = %(business_unit)s, env_group = %(environment)s,
                dns_names = %(dns_names)s
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

    # security groups

    def can_modify_security_group(self, email: str, group_id: str) -> bool:
        if self.has_permission(email, 'admin'):
            return True
        sg = self.get_security_group(group_id)
        if email == sg.get('email'):
            return True
        return False

    def delete_security_group_rule(self, group_id: str, ip_range: str):
        sql = 'delete from security_group_rules where sg_id = %(group_id)s and ip_range = %(ip_range)s'
        params = {
            'group_id': group_id,
            'ip_range': ip_range
        }
        self.u(sql, params)

    def get_security_group(self, group_id: str) -> Optional[dict]:
        sql = 'select id, cloud, owner, group_name, account_id, region from security_group where id = %(id)s'
        params = {'id': group_id}
        sg = self.q_one(sql, params)
        if sg is not None:
            sg: dict = dict(sg)
            group_id = sg.get('id')
            sg_rules = [dict(r) for r in self.get_security_group_rules(group_id)]
            sg['rules'] = sg_rules
        return sg

    def get_security_groups(self, email: str) -> list[dict]:
        rules_for_group = self.get_all_security_group_rules()
        if self.has_permission(email, 'admin'):
            sql = '''
                select
                    id, cloud, group_name, owner, account_id, region,
                    lower(concat_ws(' ', id, group_name, owner)) filter_value
                from security_group
                where visible is true
                '''
        else:
            sql = '''
                select
                    id, cloud, group_name, owner, account_id, region,
                    lower(concat_ws(' ', id, group_name, owner)) filter_value
                from security_group
                where visible is true
                and owner = %(email)s
            '''
        params = {'email': email}
        results = []
        for sg in self.q(sql, params):
            sg = dict(sg)
            sg['rules'] = rules_for_group.get(sg.get('id'), [])
            results.append(sg)
        return results

    def get_security_group_rules(self, group_id: str):
        sql = '''
            select sg_id, ip_range, description
            from security_group_rules
            where visible is true
            and sg_id = %(sg_id)s
        '''
        params = {
            'sg_id': group_id
        }
        return self.q(sql, params)

    def get_all_security_group_rules(self):
        results = {}
        sql = 'select sg_id, ip_range, description from security_group_rules where visible is true'
        for rule in self.q(sql):
            group_id = rule.get('sg_id')
            rules_for_group = results.get(group_id, [])
            rules_for_group.append(rule)
            results[group_id] = rules_for_group
        return results

    # images

    def get_image(self, image_id: str) -> dict:
        sql = '''
            select
                id, cloud, region, name, owner, public, state, created, visible, synced, instanceid, account_id, cost,
                business_unit, application_env, application_role
            from images
            where id = %(id)s
        '''
        return self.q_one(sql, {'id': image_id})

    def get_image_name_max_length(self) -> int:
        sql = 'select coalesce(max(length(name)), 0) from images where visible is true'
        return self.q_val(sql)

    def get_images(self, email: str) -> list[dict]:
        settings = Settings(self)
        if self.has_permission(email, 'admin'):
            sql = '''
                select
                    cc.description, i.id, i.cloud, region, name, owner, public, state, created, account_id, cost,
                    business_unit, application_env, application_role,
                    state = 'available' can_modify, state = 'available' and i.cloud in ('aws', 'gcp') can_launch,
                    left(name, %(name_limit)s) || case when length(name) > %(name_limit)s then '...' else '' end
                    as truncated_name,
                    coalesce(instanceid, '') as instanceid, delete_requested,
                    lower(concat_ws(' ', i.cloud, cc.description, name, owner)) filter_value 
                from images i
                join cloud_credentials cc on i.account_id = cc.id
                where visible is true
                order by name
            '''
        else:
            sql = '''
                select
                    cc.description, i.id, i.cloud, region, name, owner, public, state, created, account_id, cost,
                    business_unit, application_env, application_role,
                    state = 'available' and owner = %(email)s can_modify,
                    state = 'available' and i.cloud in ('aws', 'gcp') can_launch,
                    left(name, %(name_limit)s) || case when length(name) > %(name_limit)s then '...' else '' end
                    as truncated_name,
                    coalesce(instanceid, '') as instanceid, delete_requested,
                    lower(concat_ws(' ', i.cloud, cc.description, name, owner)) filter_value 
                from images i
                join cloud_credentials cc on cc.id = i.account_id
                where visible is true
                and delete_requested is false
            '''
            if not settings.show_all_images:
                sql = f'{sql} and (owner = %(email)s or public is true)'
        params = {'email': email, 'name_limit': settings.image_name_display_length}
        return self.q(sql, params)

    def get_images_to_delete(self) -> list[dict]:
        name_limit = Settings(self).image_name_display_length
        sql = '''
            select
                cc.description, i.id, i.cloud, region, name, owner, state, created,
                left(name, %(name_limit)s) || case when length(name) > %(name_limit)s then '...' else '' end
                as truncated_name
            from images i
            join cloud_credentials cc on cc.id = i.account_id
            where visible is true and delete_requested is true
            order by name
        '''
        params = {
            'name_limit': name_limit
        }
        return self.q(sql, params)

    def set_image_delete_requested(self, image_id: str, delete_requested: bool = True):
        sql = '''
            update images
            set delete_requested = %(delete_requested)s
            where id = %(id)s
        '''
        params = {
            'id': image_id,
            'delete_requested': delete_requested
        }
        self.u(sql, params)

    def set_image_state(self, image_id: str, state: str):
        sql = 'update images set state = %(state)s where id = %(id)s'
        params = {'id': image_id, 'state': state}
        self.u(sql, params)

    def set_image_tags(self, params: dict):
        sql = '''
            update images
            set name = %(name)s, owner = %(owner)s, application_env = %(application_env)s,
                application_role = %(application_role)s, business_unit = %(business_unit)s, public = %(public)s
            where id = %(id)s
        '''
        self.u(sql, params)

    # syncing

    def start_sync(self):
        sql = '''
            update sync_tracking
            set syncing_now = true, last_sync_start = %(last_sync_start)s, last_sync_end = null
            where only_row is true
        '''
        self.u(sql, {'last_sync_start': datetime.datetime.utcnow()})

    def end_sync(self):
        sql = '''
            update sync_tracking
            set syncing_now = false, last_sync_end = %(last_sync_end)s
            where only_row is true
        '''
        self.u(sql, {'last_sync_end': datetime.datetime.utcnow()})

    def get_sync_data(self):
        sql = 'select syncing_now, last_sync_start, last_sync_end from sync_tracking'
        for row in self.q(sql):
            return row

    def pre_sync(self, cloud: str):
        params = {'cloud': cloud}
        for table in ('images', 'security_group', 'security_group_rules', 'virtual_machines'):
            # noinspection SqlResolve
            sql = f'update {table} set synced = false where (synced is true or synced is null) and cloud = %(cloud)s'
            self.u(sql, params)

    def post_sync(self, cloud: str):
        params = {'cloud': cloud}
        for table in ('images', 'security_group', 'security_group_rules', 'virtual_machines'):
            # noinspection SqlResolve
            sql = f'update {table} set visible = false where synced is false and cloud = %(cloud)s'
            self.u(sql, params)

    def add_machine(self, params: dict):
        sql = '''
            insert into virtual_machines (
                id, cloud, region, env_group, name, owner, state, private_ip, public_ip, type, running_schedule,
                created, state_transition_time, application_env, application_role, business_unit, contributors,
                dns_names, whitelist, vpc, cost, account_id, visible, synced
            ) values (
                %(id)s, %(cloud)s, %(region)s, %(environment)s, %(name)s, %(owner)s, %(state)s, %(private_ip)s,
                %(public_ip)s, %(type)s, %(running_schedule)s, %(created)s, %(state_transition_time)s,
                %(application_env)s, %(application_role)s, %(business_unit)s, %(contributors)s, %(dns_names)s,
                %(whitelist)s, %(vpc)s, %(cost)s, %(account_id)s, true, true
            ) on conflict (id) do update set
                cloud = %(cloud)s, region = %(region)s, env_group = %(environment)s, name = %(name)s, owner = %(owner)s,
                state = %(state)s, private_ip = %(private_ip)s, public_ip = %(public_ip)s, type = %(type)s,
                running_schedule = %(running_schedule)s, created = %(created)s,
                state_transition_time = %(state_transition_time)s, application_env = %(application_env)s,
                application_role = %(application_role)s, business_unit = %(business_unit)s,
                contributors = %(contributors)s, dns_names = %(dns_names)s, whitelist = %(whitelist)s, vpc = %(vpc)s,
                cost = %(cost)s, account_id = %(account_id)s, visible = true, synced = true
        '''
        self.u(sql, params)

    def add_image(self, params: dict):
        sql = '''
            insert into images (
                id, cloud, region, name, owner, public, state, created, instanceid, account_id, cost, business_unit,
                application_env, application_role, visible, synced
            ) values (
                %(id)s, %(cloud)s, %(region)s, %(name)s, %(owner)s, %(public)s, %(state)s, %(created)s, %(instanceid)s,
                %(account_id)s, %(cost)s, %(business_unit)s, %(application_env)s, %(application_role)s, true, true
            ) on conflict (id) do update set
                cloud = %(cloud)s, region = %(region)s, name = %(name)s, owner = %(owner)s, state = %(state)s,
                public = %(public)s, created = %(created)s, instanceid = %(instanceid)s, account_id = %(account_id)s,
                cost = %(cost)s, business_unit = %(business_unit)s, application_env = %(application_env)s,
                application_role = %(application_role)s, visible = true, synced = true
        '''
        self.u(sql, params)

    def add_security_group(self, params: dict):
        sql = '''
            insert into security_group (
                id, cloud, region, owner, group_name, account_id, visible, synced
            ) values (
                %(id)s, %(cloud)s, %(region)s, %(owner)s, %(group_name)s, %(account_id)s, true, true
            ) on conflict (id) do update set
                cloud = %(cloud)s, region = %(region)s, owner = %(owner)s, group_name = %(group_name)s,
                account_id = %(account_id)s, visible = true, synced = true
        '''
        self.u(sql, params)
        for rule in params.get('sg_rules'):
            self.add_security_group_rule({
                'cloud': params.get('cloud'),
                'sg_id': params.get('id'),
                'ip_range': rule.get('ip_range'),
                'description': rule.get('description')
            })

    def add_security_group_rule(self, params: dict):
        sql = 'select sg_id from security_group_rules where sg_id = %(sg_id)s and ip_range = %(ip_range)s'
        if self.q(sql, params):
            sql = '''
                update security_group_rules
                set cloud = %(cloud)s, description = %(description)s, visible = true, synced = true
                where sg_id = %(sg_id)s and ip_range = %(ip_range)s
            '''
        else:
            sql = '''
                insert into security_group_rules (
                    cloud, sg_id, ip_range, description, visible, synced
                ) values (
                    %(cloud)s, %(sg_id)s, %(ip_range)s, %(description)s, true, true
                )
            '''
        self.u(sql, params)

    # sc assignments

    def get_rep_sc_pairs(self):
        sql = '''
            select
                r.geo, r.area, r.sub_area, r.region, r.sub_region, r.territory_name, r.sales_rep rep_name,
                coalesce(e.employee_name, '') sc_name, e.employee_id  as sc_employee_id,
                lower(concat_ws(
                    ' ', r.geo, r.area, r.sub_area, r.region, r.sub_region, r.territory_name, r.sales_rep,
                    coalesce(e.employee_name, '')
                )) filter_value
            from sales_reps r
            left join sc_rep_assignments a on a.rep_territory = r.territory_name
            left join employees e on e.employee_id = a.sc_employee_id and e.is_sc is true and e.visible is true
            order by geo, area, sub_area, region, sub_region, territory_name, rep_name
        '''
        return self.q(sql)

    def get_sales_consultants(self):
        sql = '''
            select employee_name sc_name, employee_id
            from employees
            where is_sc is true
            and visible is true
            order by employee_name
        '''
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

    def get_regional_advisors(self):
        sql = '''
            select employee_id, employee_name
            from employees
            where is_ra is true and visible is true
            order by employee_name
        '''
        return self.q(sql)

    def get_sc_ra_assignments(self):
        sql = '''
            select
                sc.employee_id as sc_employee_id, sc.employee_name sc_employee_name, sc.manager_name sc_manager_name,
                ra.employee_id as ra_employee_id, ra.employee_name ra_employee_name,
                lower(concat_ws(' ', sc.employee_name, sc.manager_name, ra.employee_name)) filter_value
            from employees sc
            left join sc_ra_assignments a on a.sc_employee_id = sc.employee_id
            left join employees ra on ra.employee_id = a.ra_employee_id and ra.is_ra is true and ra.visible is true
            where sc.is_sc is true
            and sc.visible is true
            order by ra_employee_name, sc_manager_name, sc_employee_name
        '''
        return self.q(sql)

    def set_sc_ra_assignment(self, sc_employee_id: str, ra_employee_id: str):
        sql = '''
            insert into sc_ra_assignments (sc_employee_id, ra_employee_id)
            values (%(sc_employee_id)s, %(ra_employee_id)s)
            on conflict (sc_employee_id) do update
            set ra_employee_id = %(ra_employee_id)s
        '''
        params = {
            'sc_employee_id': sc_employee_id,
            'ra_employee_id': ra_employee_id
        }
        self.u(sql, params)

    # competency

    def add_competency_scores(self, params_list: list):
        sql = '''
            insert into competency_employee_scores (id, employee_id, competency_id, timestamp, score)
            values (%(id)s, %(employee_id)s, %(competency_id)s, %(timestamp)s, %(score)s)
        '''
        for params in params_list:
            self.u(sql, params)

    def get_competency_scores(self, employee_id: str, track_id: uuid.UUID):
        ts_groups = {}
        sql = '''
            select s.timestamp, s.competency_id, s.score
            from competency_employee_scores s
            join competency_competencies c on c.id = s.competency_id
            where s.employee_id = %(employee_id)s
            and c.track_id = %(track_id)s
        '''
        params = {
            'employee_id': employee_id,
            'track_id': track_id
        }
        for row in self.q(sql, params):
            group = ts_groups.get(row.get('timestamp'), {})
            group.update({row.get('competency_id'): row.get('score')})
            ts_groups.update({row.get('timestamp'): group})
        return [
            {
                'timestamp': ts,
                'mean_score': round(statistics.mean(map(decimal.Decimal, comps.values())), 1)
            } | comps
            for ts, comps in ts_groups.items()
        ]

    def add_competency_plans(self, params_list: list[dict]):
        sql = '''
            insert into competency_employee_plans (employee_id, competency_id, plan)
            values (%(employee_id)s, %(competency_id)s, %(plan)s)
            on conflict (employee_id, competency_id) do update set plan = %(plan)s
        '''
        for params in params_list:
            self.u(sql, params)

    def get_competency_plans(self, employee_id: str, track_id: uuid.UUID):
        sql = '''
            select competency_id, plan
            from competency_employee_plans p
            join competency_competencies c on c.id = p.competency_id
            where employee_id = %(employee_id)s
            and track_id = %(track_id)s
        '''
        params = {
            'employee_id': employee_id,
            'track_id': track_id
        }
        return self.q(sql, params)

    def get_subordinates(self, manager_email: str) -> list:
        sql = '''
            with recursive subordinates as (
                select
                    e.employee_id, e.employee_name, e.employee_email, e.job_code, e.job_title, e.business_title,
                    e.visible
                from employees e
                left join employees m on m.employee_id = e.manager_id
                where m.employee_email = %(manager_email)s
                union
                select
                    e.employee_id, e.employee_name, e.employee_email, e.job_code, e.job_title, e.business_title,
                    e.visible
                from employees e
                join subordinates s on s.employee_id = e.manager_id
            )
            select
                s.employee_id, employee_name, employee_email, job_code, job_title, business_title, t.id track_id,
                t.name track_name
            from subordinates s
            left join competency_employee_track et on et.employee_id = s.employee_id
            left join competency_tracks t on t.id = et.track_id
            where visible is true
        '''
        params = {'manager_email': manager_email}
        return self.q(sql, params)

    def choose_track(self, employee_id: str, track_id: uuid.UUID):
        sql = '''
            insert into competency_employee_track (employee_id, track_id) values (%(employee_id)s, %(track_id)s)
            on conflict (employee_id) do update set track_id = %(track_id)s
        '''
        params = {
            'employee_id': employee_id,
            'track_id': track_id
        }
        self.u(sql, params)

    ## competency tracks

    def get_all_tracks(self):
        sql = '''
            select t.id, t.name, t.description, array_remove(array_agg(l.title order by l.score), null) levels
            from competency_tracks t
            left join competency_levels l on l.track_id = t.id
            group by t.id, t.name, t.description
            order by t.name
        '''
        return self.q(sql)

    def create_track(self, name: str, description: str) -> uuid.UUID:
        sql = '''
            insert into competency_tracks (id, name, description) values (%(id)s, %(name)s, %(description)s)
        '''
        params = {
            'id': uuid.uuid4(),
            'name': name,
            'description': description
        }
        self.u(sql, params)
        return params.get('id')

    def delete_track(self, track_id: uuid.UUID):
        sql = '''
            delete from competency_tracks
            where id = %(id)s
        '''
        params = {
            'id': track_id
        }
        self.u(sql, params)

    def update_track(self, params: dict):
        sql = '''
            update competency_tracks
            set name = %(name)s, description = %(description)s
            where id = %(id)s
        '''
        self.u(sql, params)

    def get_track_details(self, track_id: uuid.UUID):
        sql = '''
            select id, name, description
            from competency_tracks
            where id = %(id)s
        '''
        params = {
            'id': track_id
        }
        return self.q_one(sql, params)

    def get_level_comp_details_for_track(self, track_id: uuid.UUID):
        sql = '''
            select d.level_id, d.competency_id, d.description, d.details, l.track_id
            from competency_level_comp_details d
            join competency_levels l on l.id = d.level_id
            where l.track_id = %(track_id)s
        '''
        params = {
            'track_id': track_id
        }
        result = collections.defaultdict(dict)
        for r in self.q(sql, params):
            result[r.get('level_id')][r.get('competency_id')] = {
                'description': r.get('description'),
                'details':  r.get('details').splitlines()
            }
        return result

    ## competency competencies

    def create_competency(self, track_id: uuid.UUID, name: str, definition: str = None):
        sql = '''
            insert into competency_competencies (id, track_id, name, definition)
            values (%(id)s, %(track_id)s, %(name)s, %(definition)s)
        '''
        params = {
            'id': uuid.uuid4(),
            'track_id': track_id,
            'name': name,
            'definition': definition
        }
        self.u(sql, params)
        return params.get('id')

    def delete_competency(self, competency_id: uuid.UUID):
        sql = '''
            delete from competency_competencies where id = %(id)s
        '''
        params = {
            'id': competency_id
        }
        self.u(sql, params)

    def update_competency(self, competency_id: uuid.UUID, name: str, definition: str):
        sql = '''
            update competency_competencies
            set name = %(name)s, definition = %(definition)s
            where id = %(id)s
        '''
        params = {
            'id': competency_id,
            'name': name,
            'definition': definition
        }
        self.u(sql, params)

    def get_track_competencies(self, track_id: uuid.UUID):
        sql = '''
            select id, track_id, name, definition
            from competency_competencies
            where track_id = %(track_id)s
        '''
        params = {'track_id': track_id}
        return self.q(sql, params)

    def get_competency_details(self, competency_id: uuid.UUID):
        sql = '''
            select c.id, track_id, c.name, definition, t.name track_name
            from competency_competencies c
            left join competency_tracks t on t.id = c.track_id
            where c.id = %(id)s
        '''
        params = {
            'id': competency_id
        }
        return self.q_one(sql, params)

    def get_levels_for_competency(self, competency_id: uuid.UUID):
        sql = '''
            select id, title, score, description, details
            from competency_levels l
            left join competency_level_comp_details d on d.level_id = l.id and competency_id = %(id)s
            where track_id = (select track_id from competency_competencies where id = %(id)s)
        '''
        params = {
            'id': competency_id
        }
        return self.q(sql, params)

    ## competency levels

    def create_level(self, track_id: uuid.UUID, title: str, score: int) -> uuid.UUID:
        sql = '''
            insert into competency_levels (id, track_id, title, score)
            values (%(id)s, %(track_id)s, %(title)s, %(score)s)
        '''
        params = {
            'id': uuid.uuid4(),
            'track_id': track_id,
            'title': title,
            'score': score
        }
        self.u(sql, params)
        return params.get('id')

    def delete_level(self, level_id: uuid.UUID):
        sql = '''
            delete from competency_levels where id = %(id)s
        '''
        params = {
            'id': level_id
        }
        self.u(sql, params)

    def update_level(self, level_id: uuid.UUID, title: str, score: int):
        sql = '''
            update competency_levels
            set title = %(title)s, score = %(score)s
            where id = %(id)s
        '''
        params = {
            'id': level_id,
            'title': title,
            'score': score
        }
        self.u(sql, params)

    def get_track_levels(self, track_id: uuid.UUID):
        sql = '''
            select id, title, score
            from competency_levels
            where track_id = %(track_id)s
            order by score
        '''
        params = {'track_id': track_id}
        return self.q(sql, params)

    def get_level_details(self, level_id: uuid.UUID):
        sql = '''
            select l.id, track_id, title, score, t.name track_name
            from competency_levels l
            left join competency_tracks t on t.id = l.track_id
            where l.id = %(id)s
        '''
        params = {
            'id': level_id
        }
        return self.q_one(sql, params)

    def get_competencies_for_level(self, level_id: uuid.UUID):
        sql = '''
            select id, name, description, details
            from competency_competencies c
            left join competency_level_comp_details d on d.competency_id = c.id and level_id = %(id)s
            where track_id = (select track_id from competency_levels where id = %(id)s)
        '''
        params = {
            'id': level_id
        }
        return self.q(sql, params)

    def update_level_comp_details(self, level_id: uuid.UUID, competency_id: uuid.UUID, description: str, details: str):
        sql = '''
            insert into competency_level_comp_details (level_id, competency_id, description, details)
            values (%(level_id)s, %(competency_id)s, %(description)s, %(details)s)
            on conflict (level_id, competency_id) do update
            set description = %(description)s, details = %(details)s
        '''
        params = {
            'level_id': level_id,
            'competency_id': competency_id,
            'description': description,
            'details': details
        }
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

    def complete_survey(self, params: dict):
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

    def get_active_surveys(self, email: str) -> list[dict]:
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

    def get_completed_surveys(self, email: str) -> list[dict]:
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

    def get_modified_opportunities(self, since: datetime.datetime) -> list[dict]:
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

    def get_op_contacts(self, opportunity_number: str) -> list[dict]:
        sql = '''
            select distinct c.opportunity_key, c.contact_key, c.name, c.title, c.phone, c.email, c.is_primary
            from sf_opportunity_contacts c
            join sf_opportunities o on o.opportunity_key = c.opportunity_key
            where o.opportunity_number = %(opportunity_number)s
        '''
        params = {'opportunity_number': opportunity_number}
        return self.q(sql, params)

    def get_op_numbers_for_existing_surveys(self) -> set[str]:
        sql = 'select distinct opportunity_number from op_debrief_surveys'
        return set([r.get('opportunity_number') for r in self.q(sql)])

    def get_op_team_members(self, opportunity_key: int) -> list[dict]:
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

    def get_survey(self, survey_id: uuid.UUID) -> Optional[dict]:
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

    def get_surveys_for_reminding(self, generated_before: datetime.datetime = None) -> list[dict]:
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

    def update_roles(self, selected_roles: list):
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

    def add_environment_usage_event(self, params: dict):
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

    # external links

    def add_external_link(self, url: str, title: str, description: str):
        sql = '''
            insert into external_links (id, url, title, description)
            values (%(id)s, %(url)s, %(title)s, %(description)s)
        '''
        params = {
            'id': uuid.uuid4(),
            'url': url,
            'title': title,
            'description': description
        }
        self.u(sql, params)

    def delete_external_link(self, link_id: uuid.UUID):
        sql = 'delete from external_links where id = %(id)s'
        params = {'id': link_id}
        self.u(sql, params)

    def get_external_links(self):
        sql = 'select id, url, title, description from external_links order by title'
        return self.q(sql)

    # settings

    def get_all_settings(self):
        sql = 'select setting_id, setting_value from settings'
        settings = self.q(sql)
        return {s.get('setting_id'): s.get('setting_value') for s in settings}

    def get_setting(self, setting_id: str) -> Optional[str]:
        settings = self.get_all_settings()
        return settings.get(setting_id)

    def set_setting(self, setting_id: str, setting_value: str):
        if setting_value == self.get_setting(setting_id):
            return
        sql = '''
            insert into settings (setting_id, setting_value)
            values (%(setting_id)s, %(setting_value)s)
            on conflict (setting_id) do update set setting_value = %(setting_value)s
        '''
        params = {'setting_id': setting_id, 'setting_value': setting_value}
        self.u(sql, params)

    # ecosystem certification

    def add_ecosystem_certification(self, params: dict):
        sql = '''
            insert into ecosystem_certification (
                id, user_login, ecosystem, title, certification_date, expiration_date, aws_partner_portal_updated,
                document_name, document_size, document_data, created_at
            ) values (
                %(id)s, %(user_login)s, %(ecosystem)s, %(title)s, %(certification_date)s, %(expiration_date)s,
                %(aws_partner_portal_updated)s, %(document_name)s, %(document_size)s, %(document_data)s, %(created_at)s
            )
        '''
        params.update({
            'id': uuid.uuid4(),
            'created_at': datetime.datetime.utcnow()
        })
        self.u(sql, params)

    def approve_ecosystem_certification(self, cert_id: uuid.UUID, approver: str):
        sql = '''
            update ecosystem_certification
            set approved_at = %(approved_at)s, approved_by = %(approved_by)s
            where id = %(id)s
        '''
        params = {
            'id': cert_id,
            'approved_at': datetime.datetime.utcnow(),
            'approved_by': approver
        }
        self.u(sql, params)

    def delete_ecosystem_certification(self, cert_id: uuid.UUID):
        sql = 'delete from ecosystem_certification where id = %(id)s'
        params = {'id': cert_id}
        self.u(sql, params)

    def get_ecosystem_certification_document(self, document_id: uuid.UUID):
        sql = '''
            select document_name, document_data
            from ecosystem_certification
            where id = %(document_id)s
            limit 1
        '''
        params = {'document_id': document_id}
        return self.q_one(sql, params)

    def get_ecosystem_certifications_for_approval(self):
        sql = '''
            select
                id, user_login, ecosystem, title, certification_date, expiration_date, aws_partner_portal_updated,
                document_name, document_size, created_at, approved_at, approved_by
            from ecosystem_certification
            where approved_at is null
            order by user_login, ecosystem, certification_date
        '''
        return self.q(sql)

    def get_ecosystem_certifications_for_user(self, user_login: str):
        sql = '''
            select
                id, user_login, ecosystem, title, certification_date, expiration_date, aws_partner_portal_updated,
                document_name, document_size, created_at, approved_at, approved_by
            from ecosystem_certification
            where user_login = %(user_login)s
            order by ecosystem, certification_date
        '''
        params = {'user_login': user_login}
        return self.q(sql, params)

    # scheduled tasks

    def add_scheduled_task(self, task_name: str, task_interval: datetime.timedelta, task_active: bool = False):
        sql = '''
            insert into scheduled_tasks (task_id, task_name, task_interval, task_active)
            values (%(task_id)s, %(task_name)s, %(task_interval)s, %(task_active)s)
        '''
        params = {
            'task_id': uuid.uuid4(),
            'task_name': task_name,
            'task_interval': task_interval,
            'task_active': task_active
        }
        self.u(sql, params)

    def get_scheduled_task_with_name(self, task_name: str) -> Optional[dict]:
        sql = '''
            select task_id, task_name, task_interval, task_last_run, task_active
            from scheduled_tasks
            where task_name = %(task_name)s
        '''
        params = {
            'task_name': task_name
        }
        return self.q_one(sql, params)

    def get_scheduled_tasks(self):
        sql = '''
            select task_id, task_name, task_interval, task_last_run, task_active
            from scheduled_tasks
            order by task_name
        '''
        return self.q(sql)

    def get_scheduled_tasks_to_run(self):
        sql = '''
            select task_id, task_name
            from scheduled_tasks
            where task_active is true
            and (task_last_run is null or task_last_run + task_interval < current_timestamp)
        '''
        return self.q(sql)

    def set_scheduled_task_active(self, task_name: str, task_active: bool):
        sql = '''
            update scheduled_tasks
            set task_active = %(task_active)s
            where task_name = %(task_name)s
        '''
        params = {
            'task_name': task_name,
            'task_active': task_active
        }
        self.u(sql, params)

    def update_scheduled_task_last_run(self, task_name: str):
        sql = '''
            update scheduled_tasks
            set task_last_run = current_timestamp
            where task_name = %(task_name)s
        '''
        params = {
            'task_name': task_name
        }
        self.u(sql, params)

    # games

    def add_step(self, params: dict):
        sql = '''
            select max(step_number) from game_steps where game_id = %(game_id)s
        '''
        max_step_number = self.q_val(sql, params)
        if max_step_number is None:
            max_step_number = 0
        sql = '''
            insert into game_steps (
                step_id, game_id, step_number, step_text, step_answer
            ) values (
                %(step_id)s, %(game_id)s, %(step_number)s, %(step_text)s, %(step_answer)s
            )
        '''
        params.update({
            'step_id': uuid.uuid4(),
            'step_number': max_step_number + 1
        })
        self.u(sql, params)

    def add_game_player(self, params: dict):
        # record team number and team name for this player
        sql = '''
            insert into game_players (
                game_player_id, game_id, player_email, team_number, team_name
            ) values (
                %(game_player_id)s, %(game_id)s, %(player_email)s, %(team_number)s, %(team_name)s
            )
        '''
        params.update({
            'game_player_id': uuid.uuid4()
        })
        self.u(sql, params)

    def create_game(self, params: dict) -> uuid.UUID:
        sql = '''
            insert into game_details (
                game_id, game_name, game_intro, game_outro, skip_code, game_points_per_step
            ) values (
                %(game_id)s, %(game_name)s, %(game_intro)s, %(game_outro)s, %(skip_code)s, %(game_points_per_step)s
            )
        '''
        game_id = uuid.uuid4()
        params.update({'game_id': game_id})
        self.u(sql, params)
        return game_id

    def delete_game(self, game_id: uuid.UUID):
        params = {'game_id': game_id}
        sql = '''
            delete from game_step_results
            where step_id in (select step_id from game_steps where game_id = %(game_id)s)
        '''
        self.u(sql, params)

        sql = '''
            delete from game_players
            where game_id = %(game_id)s
        '''
        self.u(sql, params)

        sql = '''
            delete from game_steps
            where game_id = %(game_id)s
        '''
        self.u(sql, params)

        sql = '''
            delete from game_details
            where game_id = %(game_id)s
        '''
        self.u(sql, params)

    def get_game(self, game_id: uuid.UUID) -> dict:
        sql = '''
            select game_id, game_name, game_intro, game_outro, skip_code, game_points_per_step
            from game_details
            where game_id = %(game_id)s
        '''
        params = {
            'game_id': game_id
        }
        return self.q_one(sql, params)

    def get_games(self):
        sql = '''
            select game_id, game_name, lower(game_name) filter_value from game_details order by game_name
        '''
        return self.q(sql)

    def get_player_team(self, game_id: uuid.UUID, player_email: str) -> dict:
        sql = '''
            select team_name, team_number
            from game_players
            where game_id = %(game_id)s
            and player_email = %(player_email)s
        '''
        params = {
            'game_id': game_id,
            'player_email': player_email
        }
        return self.q_one(sql, params)

    def get_progress(self, game_id: uuid.UUID, player_email: str):
        sql = '''
            select
                s.game_id, s.step_id, s.step_number, s.step_text, s.step_answer, r.step_result_id, r.step_start_time,
                r.step_stop_time, r.step_skipped,
                coalesce(r.step_stop_time - r.step_start_time, '0 seconds') step_elapsed_time,
                case when r.step_skipped then 0 else g.game_points_per_step end step_score
            from game_steps s
            left join game_step_results r on r.step_id = s.step_id and r.player_email = %(player_email)s
            left join game_details g on g.game_id = s.game_id
            where s.game_id = %(game_id)s
            order by s.step_number
        '''
        params = {
            'game_id': game_id,
            'player_email': player_email
        }
        return self.q(sql, params)

    def get_progress_all(self, game_id: uuid.UUID):
        sql = '''
            select team_number, team_name, r.player_email, max(step_number) current_step_number,
                max(greatest(step_start_time, step_stop_time)) last_activity,
                sum(coalesce(r.step_stop_time, now()) - r.step_start_time) total_elapsed_time,
                bool_and(step_stop_time is not null) done,
                sum(case when step_skipped or step_stop_time is null then 0 else 1 end) correct_count,
                sum(case when step_skipped then 1 else 0 end) skip_count,
                sum(
                    case
                        when step_stop_time is null then 0
                        when step_skipped then 0
                        else g.game_points_per_step
                    end
                ) total_score
            from game_step_results r
            join game_steps s on s.step_id = r.step_id
            join game_players p on p.game_id = s.game_id and p.player_email = r.player_email
            left join game_details g on g.game_id = s.game_id
            where s.game_id = %(game_id)s
            group by team_number, team_name, r.player_email
            order by total_score desc, total_elapsed_time
        '''
        params = {
            'game_id': game_id
        }
        return self.q(sql, params)

    def get_step(self, step_id: uuid.UUID) -> dict:
        sql = '''
            select step_id, game_id, step_number, step_text, step_answer
            from game_steps
            where step_id = %(step_id)s
        '''
        params = {
            'step_id': step_id
        }
        return self.q_one(sql, params)

    def get_steps(self, game_id: uuid.UUID) -> list[dict]:
        sql = '''
            select step_id, step_number, step_text, step_answer
            from game_steps
            where game_id = %(game_id)s
            order by step_number
        '''
        params = {
            'game_id': game_id
        }
        return self.q(sql, params)

    def reset_progress(self, params: dict):
        sql = '''
            delete from game_step_results
            where player_email = %(player_email)s
            and step_id in (select step_id from game_steps where game_id = %(game_id)s)
        '''
        self.u(sql, params)
        sql = '''
            delete from game_players
            where player_email = %(player_email)s
            and game_id = %(game_id)s
        '''
        self.u(sql, params)

    def start_step(self, step_id: uuid.UUID, player_email: str) -> uuid.UUID:
        sql = '''
            insert into game_step_results (
                step_result_id, step_id, player_email, step_start_time
            ) values (
                %(step_result_id)s, %(step_id)s, %(player_email)s, %(step_start_time)s
            )
        '''
        params = {
            'step_result_id': uuid.uuid4(),
            'step_id': step_id,
            'player_email': player_email,
            'step_start_time':datetime.datetime.utcnow()
        }
        self.u(sql, params)
        return params.get('step_result_id')

    def stop_step(self, step_result_id: uuid.UUID, step_skipped: bool = False):
        # record stop time and whether step was skipped
        sql = '''
            update game_step_results
            set step_stop_time = %(step_stop_time)s, step_skipped = %(step_skipped)s
            where step_result_id = %(step_result_id)s
        '''
        params = {
            'step_stop_time': datetime.datetime.utcnow(),
            'step_skipped': step_skipped,
            'step_result_id': step_result_id
        }
        self.u(sql, params)

    def update_game_overview(self, params: dict):
        sql = '''
            update game_details
            set game_name = %(game_name)s, game_intro = %(game_intro)s, game_outro = %(game_outro)s,
                skip_code = %(skip_code)s, game_points_per_step = %(game_points_per_step)s
            where game_id = %(game_id)s
        '''
        self.u(sql, params)

    def update_step(self, params: dict):
        sql = '''
            update game_steps
            set step_text = %(step_text)s, step_answer = %(step_answer)s
            where step_id = %(step_id)s 
        '''
        self.u(sql, params)

    # seas request

    def get_seas_request_activities(self):
        sql = '''
            select activity, zd_activity from seas_request_activity
            order by activity
        '''
        return {r.get('activity'): r.get('zd_activity') for r in self.q(sql)}

    def get_seas_request_departments(self):
        sql = '''
            select name from seas_request_department
            order by name
        '''
        return [r.get('name') for r in self.q(sql)]

    def get_seas_request_ecosystems(self):
        sql = '''
            select code, name from seas_request_ecosystem
            order by name
        '''
        return {r.get('name'): r.get('code') for r in self.q(sql)}

    def get_seas_request_primary_products(self):
        sql = '''
            select tag, value from seas_request_primary_product
            order by value
        '''
        return {r.get('value'): r.get('tag') for r in self.q(sql)}

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
        sql = '''
            select table_name
            from information_schema.tables
            where table_schema = %(table_schema)s;
        '''
        params = {
            'table_schema': 'public'
        }
        for table in self.q(sql, params):
            table_name = table.get('table_name')
            self.u(f'drop table if exists {table_name} cascade')

    def migrate(self):
        self.log.info(f'Database schema version is {self.version}')
        if self.version < 1:
            self.log.info('Migrating database to schema version 1')
            self.u('''
                create table schema_versions (
                    schema_version integer primary key,
                    migration_timestamp timestamp
                )
            ''')
            self.u('''
                create table virtual_machines (
                    id text primary key,
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
                create table permissions (
                    email text primary key,
                    permissions text
                )
            ''')
            self.add_schema_version(1)
        if self.version < 2:
            self.log.info('Migrating database to schema version 2')
            # noinspection SqlResolve
            self.u('''
                alter table virtual_machines
                rename column active to visible
            ''')
            self.u('''
                alter table virtual_machines
                add column synced boolean
            ''')
            self.u('''
                create table sync_tracking (
                    only_row boolean primary key default true constraint only_row_constraint check (only_row),
                    syncing_now boolean,
                    last_sync_start timestamp,
                    last_sync_end timestamp
                )
            ''')
            self.u('insert into sync_tracking (syncing_now) values (false)')
            self.add_schema_version(2)
        if self.version < 3:
            self.log.info('Migrating database to schema version 3')
            self.u('''
                alter table virtual_machines
                add column created timestamp,
                add column state_transition_time timestamp
            ''')
            self.add_schema_version(3)
        if self.version < 4:
            self.log.info('Migrating database to schema version 4')
            self.u('''
                create table images (
                    id text primary key,
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
                alter table virtual_machines
                add column application_env text,
                add column business_unit text
            ''')
            self.add_schema_version(5)
        if self.version < 6:
            self.log.info('Migrating database to schema version 6')
            self.u('''
                alter table virtual_machines
                add column contributors text
            ''')
            self.u('''
                alter table images
                add column instanceid text
            ''')
            self.add_schema_version(6)
        if self.version < 7:
            self.log.info('Migrating database to schema version 7')
            self.u('''
                create table log_entries (
                    id uuid primary key,
                    log_time timestamp,
                    actor text,
                    action text
                )
            ''')
            self.add_schema_version(7)
        if self.version < 8:
            self.log.info('Migrating database to schema version 8')
            self.u('''
                update virtual_machines set env_group = %(environment)s where env_group is null or env_group = ''
            ''', {'environment': 'default-environment'})
            self.add_schema_version(8)
        if self.version < 9:
            self.log.info('Migrating database to schema version 9')
            self.u('''
                alter table virtual_machines
                add column dns_names text
            ''')
            self.add_schema_version(9)
        if self.version < 10:
            self.log.info('Migrating database to schema version 10')
            self.u('''
                alter table images
                add column public boolean
            ''')
            self.add_schema_version(10)
        if self.version < 11:
            self.log.info('Migrating database to schema version 11')
            self.u('''
                create table sf_opportunities (
                    opportunity_key integer primary key,
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
                create table sf_opportunity_team_members (
                    opportunity_team_member_key integer primary key,
                    opportunity_key integer,
                    name text,
                    email text,
                    role text
                )
            ''')
            self.u('''
                create table op_debrief_surveys (
                    id uuid primary key,
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
                create table op_debrief_tracking (
                    only_row boolean primary key default true constraint only_row_constraint check (only_row),
                    last_check timestamp
                )
            ''')

            params = {'last_check': datetime.datetime.utcnow()}
            self.u('insert into op_debrief_tracking (last_check) values (%(last_check)s)', params)
            self.add_schema_version(11)
        if self.version < 12:
            self.log.info('Migrating database to schema version 12')
            self.u('''
                create table sales_reps (
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
                create table sales_consultants (
                    name text primary key
                )
            ''')
            self.add_schema_version(12)
        if self.version < 13:
            self.log.info('Migrating database to schema version 13')
            self.u('''
                update sales_reps set territory_name = '(DSG)' where territory_name is null
            ''')
            self.u('''
                alter table sales_reps add primary key (territory_name, sales_rep)
            ''')
            self.add_schema_version(13)
        if self.version < 14:
            self.log.info('Migrating database to schema version 14')
            self.u('''
                alter table virtual_machines
                add column whitelist text
            ''')
            self.add_schema_version(14)
        if self.version < 15:
            self.log.info('Migrating database to schema version 15')
            self.u('''
                create table cloud_credentials (
                    id uuid primary key,
                    cloud text not null,
                    description text not null,
                    username text not null,
                    password text not null,
                    azure_tenant_id text
                )
            ''')
            self.u('''
                alter table virtual_machines
                add column account_id uuid
            ''')
            self.u('''
                alter table images
                add column account_id uuid
            ''')
            self.add_schema_version(15)
        if self.version < 16:
            self.log.info('Migrating database to schema version 16')
            self.u('''
                alter table virtual_machines
                add column vpc text
            ''')
            self.u('''
               create table security_group (
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
                create table sf_opportunity_contacts (
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
            # noinspection SqlResolve
            self.u('''
                alter table op_debrief_surveys
                drop column competitive_loss_reason,
                drop column technology_gap_type,
                drop column perceived_poor_fit_reason,
                add column tg_runtime_performance boolean,
                add column tg_runtime_stability boolean,
                add column tg_runtime_missing_features boolean,
                add column tg_runtime_compatibility boolean,
                add column tg_runtime_ease_of_use boolean,
                add column tg_design_time_performance boolean,
                add column tg_design_time_stability boolean,
                add column tg_design_time_missing_features boolean,
                add column tg_design_time_compatibility boolean,
                add column tg_design_time_ease_of_use boolean,
                add column tg_connectivity_performance boolean,
                add column tg_connectivity_stability boolean,
                add column tg_connectivity_missing_features boolean,
                add column tg_connectivity_compatibility boolean,
                add column tg_connectivity_ease_of_use boolean,
                add column tg_install_performance boolean,
                add column tg_install_stability boolean,
                add column tg_install_missing_features boolean,
                add column tg_install_compatibility boolean,
                add column tg_install_ease_of_use boolean,
                add column engaged_other_specialists boolean,
                add column engaged_gcs boolean,
                add column engaged_pm boolean,
                add column engaged_dev boolean,
                add column did_rfp boolean,
                add column did_standard_demo boolean,
                add column did_custom_demo boolean,
                add column did_eval_trial boolean,
                add column did_poc boolean,
                add column poc_outcome text,
                add column close_contacts text
            ''')
            self.add_schema_version(17)
        if self.version < 18:
            self.log.info('Migrating database to schema version 18')
            self.u('''
                alter table virtual_machines
                add column disable_termination text
            ''')
            self.add_schema_version(18)
        if self.version < 19:
            self.log.info('Migrating database to schema version 19')
            self.u('''
                alter table virtual_machines
                add column cost text
            ''')
            self.add_schema_version(19)
        if self.version < 20:
            self.log.info('Migrating database to schema version 20')
            self.u('''
                create table cost_tracking (
                    only_row boolean primary key default true constraint only_row_constraint check (only_row),
                    last_check timestamp,
                    report_id text
                )
            ''')
            self.add_schema_version(20)
        if self.version < 21:
            self.log.info('Migrating database to schema version 21')
            # noinspection SqlResolve
            self.u('''
                alter table virtual_machines
                drop column disable_termination
            ''')
            self.u('''
                alter table virtual_machines
                add column termination_protection boolean
            ''')
            self.add_schema_version(21)
        if self.version < 22:
            self.log.info('Migrating database to schema version 22')
            self.u('''
                create table environment_usage_events (
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
                create table op_debrief_roles (
                    id uuid primary key,
                    role_name text,
                    generate_survey boolean default false,
                    ignore boolean default false
                )
            ''')
            self.add_schema_version(23)
        if self.version < 24:
            self.log.info('Migrating database to schema version 24')
            # noinspection SqlResolve
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
            # noinspection SqlResolve
            self.u('''
                drop table sc_region_assignments, sf_regions
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
            # noinspection SqlResolve
            self.u('''
                insert into sc_rep_assignments
                select r.territory_name rep_territory, c.employee_id sc_employee_id
                from sales_reps r
                join sales_consultants c on c.name = r.assigned_sc
            ''')
            self.add_schema_version(27)
        if self.version < 28:
            self.log.info('Migrating to database schema version 28')
            # noinspection SqlResolve
            self.u('''
                alter table sales_consultants
                add column sc_email text
            ''')
            # noinspection SqlResolve
            self.u('''
                alter table sales_consultants
                drop constraint sales_consultants_pkey
            ''')
            # noinspection SqlResolve
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
        if self.version < 36:
            self.log.info('Migrating to database schema version 36')
            self.u('''
                create table security_group_rules (
                    cloud text,
                    sg_id text,
                    ip_range cidr,
                    description text,
                    visible boolean,
                    synced boolean
                )
            ''')
            # noinspection SqlResolve
            self.u('''
                alter table security_group
                drop column inbound_rules,
                add column region text,
                add column visible boolean,
                add column synced boolean
            ''')
            self.add_schema_version(36)
        if self.version < 37:
            self.log.info('Migrating to database schema version 37')
            self.u('''
                alter table virtual_machines
                add column application_role text
            ''')
            self.add_schema_version(37)
        if self.version < 38:
            self.log.info('Migrating to database schema version 38')
            self.u('''
                create table external_links (
                    id uuid primary key,
                    url text,
                    description text
                )
            ''')
            self.add_schema_version(38)
        if self.version < 39:
            self.log.info('Migrating to database schema version 39')
            self.u('''
                alter table security_group
                add constraint security_group_pkey primary key (id)
            ''')
            self.add_schema_version(39)
        if self.version < 40:
            self.log.info('Migrating to database schema version 40')
            self.u('''
                create table ecosystem_certification (
                    id uuid primary key,
                    user_login text not null,
                    ecosystem text not null,
                    title text not null,
                    certification_date date,
                    expiration_date date,
                    aws_partner_portal_updated boolean,
                    document_name text,
                    document_size int,
                    document_data bytea,
                    created_at timestamp
                )
            ''')
            self.add_schema_version(40)
        if self.version < 41:
            self.log.info('Migrating to database schema version 41')
            self.u('''
                alter table ecosystem_certification
                add column approved_at timestamp,
                add column approved_by text
            ''')
            self.add_schema_version(41)
        if self.version < 42:
            self.log.info('Migrating to database schema version 42')
            self.u('''
                create table employees (
                    employee_id text primary key,
                    employee_name text,
                    employee_email text,
                    manager_name text,
                    is_sc boolean,
                    is_ra boolean,
                    visible boolean,
                    synced boolean
                )
            ''')
            self.add_schema_version(42)
        if self.version < 43:
            self.log.info('Migrating to database schema version 43')
            # noinspection SqlResolve
            self.u('''
                drop table cost_tracking, sales_consultants
            ''')
            self.add_schema_version(43)
        if self.version < 44:
            self.log.info('Migrating to database schema version 44')
            self.u('''
                create table sc_ra_assignments (
                    sc_employee_id text primary key,
                    ra_employee_id text
                )
            ''')
            self.add_schema_version(44)
        if self.version < 45:
            self.log.info('Migrating to database schema version 45')
            self.u('''
                alter table employees
                add column employee_status text,
                add column region text,
                add column is_manager boolean
            ''')
            self.add_schema_version(45)
        if self.version < 46:
            self.log.info('Migrating to database schema version 46')
            self.u('''
                alter table external_links
                add column title text
            ''')
            # noinspection SqlWithoutWhere
            self.u('''
                update external_links
                set title = description, description = null
            ''')
            self.add_schema_version(46)
        if self.version < 47:
            self.log.info('Migrating to database schema version 47')
            self.u('''
                create table sc_competency_scores (
                    id uuid primary key,
                    sc_employee_id text not null,
                    score_timestamp timestamp not null,
                    technical_acumen integer not null,
                    domain_knowledge integer not null,
                    discovery_and_qualification integer not null,
                    teamwork_and_collaboration integer not null,
                    leadership_skills integer not null,
                    communicative integer not null,
                    planning_and_prioritization integer not null,
                    customer_advocacy integer not null,
                    attitude integer not null,
                    corporate_citizenship integer not null
                )
            ''')
            self.add_schema_version(47)
        if self.version < 48:
            self.log.info('Migrating to database schema version 48')
            # noinspection SqlResolve
            self.u('''
                alter table sc_competency_scores
                rename column communicative to communication
            ''')
            self.add_schema_version(48)
        if self.version < 49:
            self.log.info('Migrating to database schema version 49')
            self.u('''
                alter table employees
                add column business_title text,
                add column job_code text,
                add column job_title text
            ''')
            self.add_schema_version(49)
        if self.version < 50:
            self.log.info('Migrating to database schema version 50')
            self.u('''
                alter table images
                add column delete_requested boolean default false
            ''')
            self.add_schema_version(50)
        if self.version < 51:
            self.log.info('Migrating to database schema version 51')
            self.u('''
                create table scheduled_tasks (
                    task_id uuid primary key,
                    task_name text,
                    task_interval interval,
                    task_last_run timestamp,
                    task_active boolean
                )
            ''')
            self.add_schema_version(51)
        if self.version < 52:
            self.log.info('Migrating to database schema version 52')
            self.u('''
                alter table cloud_credentials
                add column default_environment_name text default 'default-environment'
            ''')
            self.add_schema_version(52)
        if self.version < 53:
            self.log.info('Migrating to database schema version 53')
            self.u('''
                alter table images
                add column business_unit text,
                add column application_env text,
                add column application_role text
            ''')
            self.add_schema_version(53)
        if self.version < 54:
            self.log.info('Migrating to database schema version 54')
            self.u('''
                create table sc_competency_plans (
                    sc_employee_id text primary key,
                    technical_acumen text,
                    domain_knowledge text,
                    discovery_and_qualification text,
                    teamwork_and_collaboration text,
                    leadership_skills text,
                    communication text,
                    planning_and_prioritization text,
                    customer_advocacy text,
                    attitude text,
                    corporate_citizenship text
                )
            ''')
            self.add_schema_version(54)
        if self.version < 55:
            self.log.info('Migrating to database schema version 55')
            self.u('''
                create table game_details (
                    game_id uuid primary key,
                    game_name text not null,
                    game_intro text,
                    game_outro text,
                    skip_code text
                )
            ''')
            self.u('''
                create table game_steps (
                    step_id uuid primary key,
                    game_id uuid not null,
                    step_number int not null,
                    step_text text not null,
                    step_answer text not null
                )
            ''')
            self.u('''
                create table game_step_results (
                    step_result_id uuid primary key,
                    step_id uuid not null,
                    player_email text not null,
                    step_start_time timestamp,
                    step_stop_time timestamp,
                    step_skipped boolean not null default false
                )
            ''')
            self.u('''
                create table game_players (
                    game_player_id uuid primary key,
                    game_id uuid not null,
                    player_email text not null,
                    team_number integer not null,
                    team_name text not null
                )
            ''')
            self.add_schema_version(55)
        if self.version < 56:
            self.log.info('Migrating to database schema version 56')
            self.u('''
                create table seas_request_department (
                    name text primary key
                )
            ''')
            self.u('''
                create table seas_request_ecosystem (
                    code text primary key,
                    name text not null
                )
            ''')
            self.u('''
                create table seas_request_activity (
                    code text primary key,
                    description text not null
                )
            ''')
            self.u('''
                create table seas_request_primary_product (
                    tag text primary key,
                    value text not null
                )
            ''')
            self.u('''
                create table seas_request_initial_activity (
                    tag text primary key,
                    value text not null
                )
            ''')
            self.add_schema_version(56)
        if self.version < 57:
            self.log.info('Migrating to database schema version 57')
            # noinspection SqlResolve
            self.u('''
                alter table seas_request_activity
                rename description to zd_activity
            ''')
            # noinspection SqlResolve
            self.u('''
                alter table seas_request_activity
                rename code to activity
            ''')
            # noinspection SqlResolve
            self.u('''
                drop table seas_request_initial_activity
            ''')
            self.add_schema_version(57)
        if self.version < 58:
            self.log.info('Migrating to database schema version 58')
            self.u('''
                alter table game_details
                add game_points_per_step int not null default 100
            ''')
            self.add_schema_version(58)
        if self.version < 59:
            self.log.info('Migrating to database schema version 59')
            self.u('''
                update settings
                set setting_id = 'show-competency-link'
                where setting_id = 'show-sc-competency-link'
            ''')
            self.add_schema_version(59)
        if self.version < 60:
            self.log.info('Migrating to database schema version 60')
            self.u('''
                update settings
                set setting_id = 'show-unity-request-link'
                where setting_id = 'show-monolith-request-link'
            ''')
            self.u('''
                update settings
                set setting_id = 'unity-support-group-id'
                where setting_id = 'monolith-support-group-id'
            ''')
            self.add_schema_version(60)
        if self.version < 61:
            self.log.info('Migrating to database schema version 61')
            # noinspection SqlResolve
            self.u('''
                alter table sc_competency_plans
                rename to competency_plans
            ''')
            # noinspection SqlResolve
            self.u('''
                alter table sc_competency_scores
                rename to competency_scores
            ''')
            self.add_schema_version(61)
        if self.version < 62:
            self.log.info('Migrating to database schema version 62')
            self.u('''
                create table competency_tracks (
                    id uuid primary key,
                    name text not null,
                    description text,
                    ta_description text,
                    dk_description text,
                    dq_description text,
                    tc_description text,
                    ls_description text,
                    co_description text,
                    pp_description text,
                    ca_description text,
                    at_description text,
                    cc_description text
                )
            ''')
            self.u('''
                create table competency_levels (
                    id uuid primary key,
                    track_id uuid not null references competency_tracks on delete cascade,
                    title text not null,
                    score integer not null,
                    ta_description text,
                    dk_description text,
                    dq_description text,
                    tc_description text,
                    ls_description text,
                    co_description text,
                    pp_description text,
                    ca_description text,
                    at_description text,
                    cc_description text
                )
            ''')
            self.u('''
                create table competency_level_details (
                    id uuid primary key,
                    level_id uuid not null references competency_levels on delete cascade,
                    detail text not null
                )
            ''')
            self.add_schema_version(62)
        if self.version < 63:
            self.log.info('Migrating to database schema version 63')
            # noinspection SqlResolve
            self.u('''
                drop table competency_level_details;
            ''')
            self.u('''
                alter table employees
                add manager_id text
            ''')
            self.u('''
                create table competency_competencies (
                    id uuid primary key,
                    track_id uuid not null references competency_tracks on delete cascade,
                    name text not null,
                    definition text
                )
            ''')
            # noinspection SqlResolve
            self.u('''
                alter table competency_tracks
                drop ta_description,
                drop dk_description,
                drop dq_description,
                drop tc_description,
                drop ls_description,
                drop co_description,
                drop pp_description,
                drop ca_description,
                drop at_description,
                drop cc_description
            ''')
            # noinspection SqlResolve
            self.u('''
                alter table competency_levels
                drop ta_description,
                drop dk_description,
                drop dq_description,
                drop tc_description,
                drop ls_description,
                drop co_description,
                drop pp_description,
                drop ca_description,
                drop at_description,
                drop cc_description
            ''')
            self.u('''
                create table competency_level_comp_details (
                    level_id uuid references competency_levels on delete cascade,
                    competency_id uuid references competency_competencies on delete cascade,
                    description text,
                    details text,
                    primary key (level_id, competency_id)
                )
            ''')
            self.u('''
                create table competency_employee_track (
                    employee_id text primary key references employees,
                    track_id uuid references competency_tracks on delete cascade
                )
            ''')
            self.u('''
                create table competency_employee_scores (
                    id uuid primary key,
                    employee_id text not null references employees,
                    competency_id uuid not null references competency_competencies on delete cascade,
                    timestamp timestamp not null,
                    score integer not null
                )
            ''')
            self.u('''
                create table competency_employee_plans (
                    employee_id text not null references employees,
                    competency_id uuid not null references competency_competencies on delete cascade,
                    plan text,
                    primary key (employee_id, competency_id)
                )
            ''')
            self.add_schema_version(63)
        if self.version < 64:
            self.log.info('Migrating to database schema version 64')
            self.u('''
                create extension if not exists tablefunc
            ''')
            self.add_schema_version(64)
        if self.version < 65:
            self.log.info('Migrating to database schema version 65')
            # noinspection SqlResolve
            self.u('''
                drop table competency_plans
            ''')
            # noinspection SqlResolve
            self.u('''
                drop table competency_scores
            ''')
            self.u('''
                alter table competency_employee_plans
                add column modified_at timestamp not null default current_timestamp
            ''')
            self.add_schema_version(65)

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
