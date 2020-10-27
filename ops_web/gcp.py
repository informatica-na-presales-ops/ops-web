import datetime
import decimal
import google.auth.exceptions
import google.oauth2.service_account
import googleapiclient.discovery
import json
import logging
import ops_web.config
import time

log = logging.getLogger(__name__)


class GCPClient:
    def __init__(self, config: ops_web.config.Config, project_id: str, service_account_info: str):
        self.config = config
        self.project_id = project_id
        self.service_account_info = json.loads(service_account_info)
        self.cred = google.oauth2.service_account.Credentials.from_service_account_info(self.service_account_info)
        self.compute = googleapiclient.discovery.build('compute', 'v1', credentials=self.cred, cache_discovery=False)

    def get_all_instances(self):
        log.info(f'Getting all compute instances for GCP project {self.project_id}')
        result = self.compute.instances().aggregatedList(project=self.project_id).execute()
        for zone_name, zone_data in result.get('items', {}).items():
            log.info(f'Getting all GCP instances in {zone_name}')
            if 'instances' in zone_data:
                for instance in zone_data.get('instances'):
                    params = {
                        'application_env': None,
                        'application_role': None,
                        'business_unit': None,
                        'cloud': 'gcp',
                        'contributors': None,
                        'cost': decimal.Decimal('0'),
                        'created': instance.get('creationTimestamp'),
                        'dns_names': None,
                        'id': instance.get('id'),
                        'name': instance.get('name'),
                        'owner': None,
                        'private_ip': None,
                        'public_ip': None,
                        'region': zone_name[6:],
                        'running_schedule': None,
                        'state': instance.get('status').lower(),
                        'state_transition_time': instance.get('lastStartTimestamp'),
                        'type': instance.get('machineType').split('/')[-1],
                        'vpc': None,
                        'whitelist': None,
                    }
                    for item in instance.get('metadata', {}).get('items', []):
                        item_key = item.get('key')
                        item_value = item.get('value')
                        if item_key == 'OWNEREMAIL':
                            params.update({'owner': item_value})
                        if item_key == 'APPLICATIONENV':
                            params.update({'application_env': item_value})
                        if item_key == 'APPLICATIONROLE':
                            params.update({'application_role': item_value})
                        if item_key == 'BUSINESSUNIT':
                            params.update({'business_unit': item_value})
                        if item_key == 'RUNNINGSCHEDULE':
                            params.update({'running_schedule': item_value})
                        if item_key == 'image__dns_names_private':
                            params.update({'dns_names': item_value})
                    for network_interface in instance.get('networkInterfaces'):
                        params.update({'private_ip': network_interface.get('networkIP')})
                        for access_config in network_interface.get('accessConfigs'):
                            params.update({'public_ip': access_config.get('natIP')})
                    yield params


c = ops_web.config.Config()

PROJECT_ID = c.gcp_project_id

try:
    compute = googleapiclient.discovery.build('compute', 'v1', cache_discovery=False)
    computebeta = googleapiclient.discovery.build('compute', 'beta', cache_discovery=False)
except google.auth.exceptions.DefaultCredentialsError as e:
    log.critical('Could not find GCP credentials in environment')


def create_machine_image(souceinstance, zone, name):
    instance = compute.instances().get(project=PROJECT_ID, zone=zone, instance=souceinstance).execute()
    machinetype = instance['machineType']
    log.info(machinetype)
    operations = computebeta.machineImages().insert(project=PROJECT_ID,
                                                    sourceInstance=f'projects/{PROJECT_ID}/zones/{zone}/instances/{souceinstance}',
                                                    body={"name": name,
                                                          "sourceInstanceProperties.machineType": machinetype}).execute()


def create_instance(region, name, sourceimage, environment, owner):
    sourceImage = f'projects/{PROJECT_ID}/global/machineImages/{sourceimage}'
    image = computebeta.machineImages().get(project=PROJECT_ID, machineImage=sourceimage).execute()
    log.info(image)
    instancetype = image['sourceInstanceProperties']['machineType']
    machinetype_url = f'zones/{region}/machineTypes/{instancetype}'
    computebeta.instances().insert(project=PROJECT_ID, sourceMachineImage=sourceImage, zone=region,
                                   body={"name": name, "machineType": machinetype_url}).execute()
    params = {
        'id': 'pending',
        'cloud': 'gcp',
        'region': region,
        'environment': environment,
        'name': name,
        'owner': owner,
        'private_ip': None,
        'public_ip': None,
        'type': instancetype,
        'running_schedule': None,
        'state': 'pending',
        'state_transition_time': None,
        'application_env': None,
        'business_unit': None,
        'created': datetime.datetime.utcnow(),
        'dns_names': None,
        'whitelist': None,
        'vpc': None,
        'disable_termination': None,
        'cost': 0,
        'contributors': None,
        'account_id': None
    }
    return params


def get_all_images():
    images = computebeta.machineImages().list(project=PROJECT_ID).execute()
    image2 = images['items']
    result = []

    for image in image2:
        params = {
            'id': image['id'],
            'name': image['name'],
            'public': None,
            'state': 'available' if (image['status'] == 'READY') else 'pending',
            'created': image['creationTimestamp'],
            'instanceid': image['sourceInstance'].split('/')[-1],
            'owner': image['sourceInstanceProperties']['labels']['owneremail'] + '@informatica.com',
            'region': image['sourceInstance'].split('/')[-3],
            'cloud': 'gcp',
            'cost': '0'
        }
        log.info(params)
        result.append(params)
    return result


def get_all_virtual_machines():
    result = []
    request = compute.zones().list(project=PROJECT_ID).execute()
    for zone in request['items']:
        for i in checkInstancesInZone(zone['description']):
            result.append(i)
    print(result)
    return result


def list_instances(compute, project, zone):
    result = compute.instances().list(project=project, zone=zone).execute()
    return result['items'] if 'items' in result else None


def checkInstancesInZone(ZONE):
    instances = list_instances(compute, PROJECT_ID, ZONE)
    if instances is not None:
        for instance in instances:
            log.info('Instance name: ' + instance['name'] + "\nInstnace ID: " + instance['id'] + '\nZone: ' + ZONE)
            conributors_tag = instance['labels']['contributors'].split('-')
            contributors_tag = list(filter(None, conributors_tag))
            contributor = [s + "@informatica.com" for s in contributors_tag]
            contributors = " ".join(contributor)
            params = {
                'id': instance['id'],
                'cloud': 'gcp',
                'region': instance['zone'].split('/')[-1],
                'environment': instance['labels']['machine__environment_group'],
                'name': instance['name'],
                'owner': instance['labels']['owneremail'] + '@informatica.com',
                'private_ip': instance['networkInterfaces'][0]['networkIP'],
                'public_ip': None if ('natIP' not in instance['networkInterfaces'][0]['accessConfigs'][0]) else
                instance['networkInterfaces'][0]['accessConfigs'][0]['natIP'],
                'type': instance['machineType'].split('/')[-1],
                'running_schedule': None,
                'state': 'stopped' if (instance['status'] == 'TERMINATED') else instance['status'].lower(),
                'state_transition_time': None,
                'application_env': instance['labels']['applicationenv'],
                'application_role': instance['labels']['applicationrole'],
                'business_unit': instance['labels']['business_unit'],
                'created': None,
                'dns_names': None,
                'whitelist': None,
                'vpc': None,
                'disable_termination': None,
                'cost': 0,
                'contributors': contributors
            }
            yield params


def start_machine(machine_id, zone):
    operation = compute.instances().start(project=PROJECT_ID, zone=zone, instance=machine_id).execute()
    # wait_for_operation(compute, PROJECT_ID, zone, operation['name'])
    # instance = compute.instances().get(project=PROJECT_ID, zone=zone, instance=machine_id).execute()
    # public_ip = instance['networkInterfaces'][0]['accessConfigs'][0]['natIP']
    # return public_ip
    return operation


def stop_machine(machine_id, zone):
    operation = compute.instances().stop(project=PROJECT_ID, zone=zone, instance=machine_id).execute()
    return operation
    # wait_for_operation(compute,PROJECT_ID,zone,machine_id)
    # wait_for_operation(compute, PROJECT_ID, zone,operation['name'])
    # instance = compute.instances().get(project=PROJECT_ID, zone=zone, instance=machine_id).execute()
    # return instance


def get_publicip(machine_id, zone):
    instance = compute.instances().get(project=PROJECT_ID, zone=zone, instance=machine_id).execute()
    return instance['networkInterfaces'][0]['accessConfigs'][0]['natIP']


def update_machine_tags(machine_id, zone, tags):
    log.info(tags)
    tags2 = {}
    instance_info = compute.instances().get(project=PROJECT_ID, zone=zone, instance=machine_id).execute()
    fingerprint = instance_info['labelFingerprint']
    tags2['labels'] = tags
    tags2['labelFingerprint'] = str(fingerprint)
    compute.instances().setLabels(project=PROJECT_ID, zone=zone, instance=machine_id, body=tags2).execute()


def wait_for_operation(compute, project, zone, operation):
    print('Waiting for operation to finish...')
    while True:
        result = compute.zoneOperations().get(
            project=project,
            zone=zone,
            operation=operation).execute()

        if result['status'] == 'DONE':
            print("done.")
            if 'error' in result:
                raise Exception(result['error'])
            return result

        time.sleep(1)
