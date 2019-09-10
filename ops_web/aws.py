import boto3
import botocore.exceptions
import ops_web.config
import logging

from typing import Dict

log = logging.getLogger(__name__)


def resource_tags_as_dict(resource) -> Dict:
    if resource.tags is None:
        return {}
    return {tag['Key']: tag['Value'] for tag in resource.tags}


def get_instance_tag(instance, tag_key):
    if instance.tags is None:
        return ''
    for tag in instance.tags:
        if tag['Key'] == tag_key:
            return tag['Value']
    return ''


def get_image_tag(tagset, tag_key):
    if tagset is None:
        return ''
    for tag in tagset:
        if tag['Key'] == tag_key:
            return tag['Value']
    return ''


def delete_machine(region: str, machine_id: str):
    log.debug(f'Delete machine: {machine_id}')
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(machine_id)
    instance.terminate()


def start_machine(region: str, machine_id: str):
    log.debug(f'Start machine: {machine_id}')
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(machine_id)
    instance.start()


def stop_machine(region: str, machine_id: str):
    log.debug(f'Stop machine: {machine_id}')
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(machine_id)
    instance.stop()


def update_tags(region: str, resource_id: str, tags: Dict):
    log.debug(f'Update tags: {resource_id}')
    ec2 = boto3.resource('ec2', region_name=region)
    ec2.create_tags(
        Resources=[resource_id],
        Tags=[{'Key': k, 'Value': v} for k, v in tags.items()]
    )


def get_instance_tags(machine_id):
    ec2 = boto3.client('ec2')
    response = ec2.describe_instances(InstanceIds=[machine_id])
    for r in response['Reservations']:
        for i in r['Instances']:
            return i['Tags']


def create_images(machine_id: str, name: str):
    ec2 = boto3.client('ec2')
    response = ec2.create_image(InstanceId=machine_id, Name=name)
    tags = get_instance_tags(machine_id)
    t = []
    for i in tags:
        t.append(i['Key'])
    log.info(t)
    if 'machine__description' in t:
        log.info('present')
    else:
        tags.append({'Key': 'machine__description'})

    for i in tags:
        log.info(i)
        if i['Key'] == 'machine__description':
            i['Value'] = machine_id
    image_id = response['ImageId']
    ec2.create_tags(Resources=[image_id], Tags=tags)
    image_details = ec2.describe_images(ImageIds=[image_id])
    log.info(image_details['Images'])
    log.info(image_details['Images'][0]['Name'])
    return image_details['Images'][0]['Name']


class AWSClient:
    def __init__(self, config: ops_web.config.Config):
        self.config = config

    def get_available_regions(self):
        session = boto3.session.Session(aws_access_key_id=self.config.aws_access_key_id,
                                        aws_secret_access_key=self.config.aws_secret_access_key)
        return session.get_available_regions('ec2')

    def get_all_images(self):
        for region in self.get_available_regions():
            log.info(f'Getting all EC2 images in {region}')
            ec2 = boto3.resource('ec2', region_name=region)
            try:
                for image in ec2.images.filter(Owners=['self']):
                    tags = resource_tags_as_dict(image)
                    params = {
                        'id': image.id,
                        'cloud': 'aws',
                        'region': region,
                        'name': tags.get('NAME', image.name),
                        'owner': tags.get('OWNEREMAIL', ''),
                        'state': image.state,
                        'created': image.creation_date
                    }
                    yield params
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')

    def get_all_instances(self):
        for region in self.get_available_regions():
            log.info(f'Getting all EC2 instances in {region}')
            ec2 = boto3.resource('ec2', region_name=region, aws_access_key_id=self.config.aws_access_key_id,
                                 aws_secret_access_key=self.config.aws_secret_access_key)
            try:
                for instance in ec2.instances.all():
                    params = {
                        'id': instance.id,
                        'cloud': 'aws',
                        'region': region,
                        'env_group': get_instance_tag(instance, 'machine__environment_group'),
                        'name': get_instance_tag(instance, 'Name'),
                        'owner': get_instance_tag(instance, 'OWNEREMAIL'),
                        'private_ip': instance.private_ip_address,
                        'public_ip': instance.public_ip_address,
                        'type': instance.instance_type,
                        'running_schedule': get_instance_tag(instance, 'RUNNINGSCHEDULE'),
                        'state': instance.state['Name'],
                        'created': instance.launch_time,
                        'state_transition_time': None
                    }
                    if instance.state_transition_reason.endswith('GMT)'):
                        _, _, state_transition_time = instance.state_transition_reason.partition('(')
                        state_transition_time, _, _ = state_transition_time.partition(')')
                        params['state_transition_time'] = state_transition_time
                    yield params

            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')
