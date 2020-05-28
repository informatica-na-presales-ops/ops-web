import time

import googleapiclient.discovery
from oauth2client.client import GoogleCredentials
import logging

log = logging.getLogger(__name__)
import ops_web.config
config = ops_web.config.Config()

PROJECT_ID = config.gcp_project_id
compute = googleapiclient.discovery.build('compute', 'v1', cache_discovery=False)

def get_all_virtual_machines():
    request = compute.zones().list(project=PROJECT_ID)

    result = []
    while request is not None:
        response = request.execute()

        for zone in response['items']:
            rest = checkInstancesInZone(zone['description'])
            if rest is not None:
                result.append(checkInstancesInZone(zone['description']))

        request = compute.zones().list_next(previous_request=request, previous_response=response)
    print(result)
    return result


def list_instances(compute, project, zone):
    result = compute.instances().list(project=project, zone=zone).execute()
    return result['items'] if 'items' in result else None


def checkInstancesInZone(ZONE):
    instances = list_instances(compute, PROJECT_ID, ZONE)
    if instances is not None:
        for instance in instances:
            print('Instance name: ' + instance['name'] + "\nInstnace ID: " + instance['id'] + '\nZone: ' + ZONE)
            conributors_tag = instance['labels']['contributors'].split('-')
            contributors_tag = list(filter(None,conributors_tag))
            contributor = [s + "@informatica.com" for s in contributors_tag]
            contributors = " ".join(contributor)
            params = {
                'id': instance['id'],
                'cloud': 'gcp',
                'region': instance['zone'].split('/')[-1],
                'environment': instance['labels']['machine__environment_group'],
                'name': instance['labels']['name'],
                'owner': instance['labels']['owneremail'] + '@informatica.com',
                'private_ip': instance['networkInterfaces'][0]['networkIP'],
                'public_ip': None if ('natIP' not in instance['networkInterfaces'][0]['accessConfigs'][0]) else
                instance['networkInterfaces'][0]['accessConfigs'][0]['natIP'],
                'type': instance['machineType'].split('/')[-1],
                'running_schedule': None,
                'state': 'stopped' if (instance['status'] == 'TERMINATED') else instance['status'].lower(),
                'state_transition_time': None,
                'application_env': instance['labels']['applicationenv'],
                'business_unit': instance['labels']['business_unit'],
                'created': None,
                'dns_names': None,
                'whitelist': None,
                'vpc': None,
                'disable_termination': None,
                'cost': 0,
                'contributors': contributors

            }
            return params


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


def wait_for_operation(compute,project, zone, operation):
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
