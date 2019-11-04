import boto3
import botocore.exceptions
import ops_web.config
import logging
import time

from typing import Dict

log = logging.getLogger(__name__)


def resource_tags_as_dict(resource) -> Dict:
    if resource.tags is None:
        return {}
    return {tag['Key']: tag['Value'] for tag in resource.tags}


def delete_image(region: str, image_id: str):
    log.debug(f'Delete image: {image_id}')
    ec2 = boto3.resource('ec2', region_name=region)
    image = ec2.Image(image_id)
    snapshots = [ec2.Snapshot(m['Ebs']['SnapshotId']) for m in image.block_device_mappings if 'Ebs' in m]
    log.debug(f'Deregistering image: {image.id}')
    image.deregister()
    for snapshot in snapshots:
        log.debug(f'Deleting snapshot {snapshot.id}')
        snapshot.delete()


def delete_machine(region: str, machine_id: str):
    """Terminate an EC2 instance in AWS.

    This will terminate the instance and delete all volumes that were attached to the instance, even if the volume was
    not set to delete on termination.

    Do not call this function during a web request. Use a scheduled job instead."""

    log.debug(f'Delete machine: {machine_id}')
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(machine_id)
    log.info(f'Looking up volumes for machine {machine_id}')
    delete_after = []
    for m in instance.block_device_mappings:
        volume_id = m.get('Ebs').get('VolumeId')
        delete_on_termination: bool = m.get('Ebs', {}).get('DeleteOnTermination', False)
        if delete_on_termination:
            log.info(f'Volume {volume_id} will delete on termination')
        else:
            log.info(f'Volume {volume_id} must be explicitly deleted')
            delete_after.append(volume_id)
    instance.terminate()
    instance.wait_until_terminated()
    for v in delete_after:
        delete_volume(region, v)


def delete_volume(region: str, volume_id: str):
    ec2 = boto3.resource('ec2', region_name=region)
    volume = ec2.Volume(volume_id)
    if volume.state == 'in-use':
        log.info(f'Volume {volume_id} is {volume.state}, waiting 10 seconds ...')
        time.sleep(10)
    log.info(f'Deleting volume {volume_id}')
    volume.delete()


def start_machine(region: str, machine_id: str):
    log.debug(f'Start machine: {machine_id}')
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(machine_id)
    instance.start()
    return instance


def stop_machine(region: str, machine_id: str):
    log.debug(f'Stop machine: {machine_id}')
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(machine_id)
    instance.stop()
    return instance


def update_resource_tags(region: str, resource_id: str, tags: Dict):
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


def create_image(region: str, machine_id: str, name: str, owner: str, public: bool = False) -> str:
    log.debug(f'Creating image from {machine_id} for {owner}')
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(machine_id)
    image = instance.create_image(Name=name)
    image_tags = {
        'NAME': name,
        'OWNEREMAIL': owner,
        'machine__description': machine_id,
        'image_public': str(public)
    }
    image.create_tags(Tags=[{'Key': k, 'Value': v} for k, v in image_tags.items()])
    return image.id


def create_instance(region: str, imageid: str, instanceid: str, name: str, owner: str, environment: str):
    ec2 = boto3.resource('ec2', region_name=region)
    instance = ec2.Instance(instanceid)

    security_group_ids = []
    security_groups = instance.security_groups
    for i in security_groups:
        for t, v in i.items():
            if t == 'GroupId':
                security_group_ids.append(v)

    for t in instance.tags:
        if t.get('Key').lower() == 'name':
            t['Value'] = name
        elif t.get('Key').lower() == 'owneremail':
            t['Value'] = owner
        elif t.get('Key').lower() == 'machine__environment_group':
            t['Value'] = environment

    response = ec2.create_instances(
        ImageId=imageid,
        InstanceType=instance.instance_type,
        KeyName=instance.key_name,
        MaxCount=1,
        MinCount=1,
        SecurityGroupIds=security_group_ids,
        SubnetId=instance.subnet_id,
        TagSpecifications=[
            {
                'ResourceType': 'instance',
                'Tags': instance.tags
            },
            {
                'ResourceType': 'volume',
                'Tags': instance.tags
            }
        ]
    )
    return response


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
                        'public': ops_web.config.as_bool(tags.get('image_public', '')),
                        'state': image.state,
                        'created': image.creation_date,
                        'instanceid': tags.get('machine__description', '')
                    }
                    yield params
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')

    def get_instance_dict(self, region, instance) -> Dict:
        tags = resource_tags_as_dict(instance)
        params = {
            'id': instance.id,
            'cloud': 'aws',
            'region': region,
            'environment': tags.get('machine__environment_group', ''),
            'name': tags.get('NAME', ''),
            'owner': tags.get('OWNEREMAIL', ''),
            'private_ip': instance.private_ip_address,
            'public_ip': instance.public_ip_address,
            'type': instance.instance_type,
            'running_schedule': tags.get('RUNNINGSCHEDULE', ''),
            'state': instance.state['Name'],
            'created': instance.launch_time,
            'state_transition_time': None,
            'application_env': tags.get('APPLICATIONENV', ''),
            'business_unit': tags.get('BUSINESSUNIT', ''),
            'dns_names': tags.get('image__dns_names_private', '')
        }
        if params['environment'] == '':
            params['environment'] = 'default-environment'
        if params['dns_names'] == '':
            params['dns_names'] = params.get('name')
        if instance.state_transition_reason.endswith('GMT)'):
            _, _, state_transition_time = instance.state_transition_reason.partition('(')
            state_transition_time, _, _ = state_transition_time.partition(')')
            params['state_transition_time'] = state_transition_time

        # Convert power_control tag value to contributors
        contributors = set()
        power_control = tags.get('power_control', '')
        power_control = power_control.replace(';', ' ')
        power_control_list = power_control.strip().split()
        contributors.update([f'{i}@{self.config.power_control_domain}' for i in power_control_list])
        contributors_tag = tags.get('CONTRIBUTORS', '')
        contributors.update(contributors_tag.strip().split())
        params['contributors'] = ' '.join(sorted(contributors))
        return params

    def get_all_instances(self):
        for region in self.get_available_regions():
            log.info(f'Getting all EC2 instances in {region}')
            ec2 = boto3.resource('ec2', region_name=region, aws_access_key_id=self.config.aws_access_key_id,
                                 aws_secret_access_key=self.config.aws_secret_access_key)
            try:
                for instance in ec2.instances.all():
                    yield self.get_instance_dict(region, instance)
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')

    def get_single_instance(self, region: str, instanceid: str):
        ec2 = boto3.resource('ec2')
        instance = ec2.Instance(instanceid)
        return self.get_instance_dict(region, instance)
