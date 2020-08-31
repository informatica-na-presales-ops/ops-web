import boto3
import botocore
import botocore.config
import botocore.exceptions
import decimal
import datetime
import logging
import ops_web.config
import ops_web.db
import os
import subprocess
import time

from paramiko import RSAKey, SSHClient, AutoAddPolicy
from typing import Dict, List

log = logging.getLogger(__name__)


def tag_list_to_dict(tags: List[dict]) -> dict:
    if tags is None:
        return {}
    return {tag['Key']: tag['Value'] for tag in tags}


def tag_dict_to_list(tags: dict) -> List[dict]:
    return [{'Key': k, 'Value': v} for k, v in tags.items()]


class AWSClient:
    def __init__(self, config: ops_web.config.Config, access_key_id: str, secret_access_key: str):
        self.config = config
        self.db = ops_web.db.Database(config)
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session = boto3.session.Session(access_key_id, secret_access_key)
        self.boto_config = botocore.config.Config(retries={'max_attempts': 10})

    def get_service_client(self, service_name: str, region_name: str):
        return self.session.client(service_name, region_name, config=self.boto_config)

    def get_service_resource(self, service_name: str, region_name: str):
        return self.session.resource(service_name, region_name, config=self.boto_config)

    def create_image(self, region: str, machine_id: str, name: str, owner: str, public: bool = False) -> str:
        log.debug(f'Creating image from {machine_id} for {owner}')
        ec2 = self.get_service_resource('ec2', region)
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

    def workshop_images(self, ws: str):
        Filters = [
            {'Name': 'tag:workshop', 'Values': [ws]}
        ]
        ec2 = self.get_service_resource('ec2', 'us-west-2')
        img = []
        try:
            for image in ec2.images.filter(Filters=Filters):
                tags = tag_list_to_dict(image.tags)
                log.info(image.id)
                img.append(image.id)
                params = {
                    'id': image.id,
                    'cloud': 'aws',
                    'primary_product': tags.get('primary_product', ''),
                    'created': image.creation_date,
                    'ssh_user': tags.get('machine__ssh_user', ''),
                    'host_name': tags.get('host_name', ''),
                    'Instance_Type': tags.get('instance_type', '')

                }
                yield params
        except botocore.exceptions.ClientError as e:
            log.critical(e)

    def getimage_tags(self, region: str, imageid: str, key: str):
        ec2 = self.get_service_resource('ec2', region)
        image_details = ec2.Image(imageid)
        x = 0
        for tags in image_details.tags:
            if tags["Key"] == key:
                value = tags["Value"]
                x = 1
        if x == 0:
            value = "N/A"
        return value

    def create_instances(self, wsdetails: list, info_dict: dict):
        securitygrp = (info_dict['securitygrp']).split(',')
        whitelistid = info_dict['whitelist']
        if whitelistid:
            securitygrp.append(whitelistid)
            self.addtag_WSecuritygrps(whitelistid, info_dict['owneremail'])
        wsst = wsdetails[1:]
        wsdetails2 = wsst[:-1]
        new_str = wsdetails2.replace("\'", "")
        new_str2 = new_str.replace(' ', '')
        ws = new_str2.split(',')
        shrtowner = (info_dict['owneremail']).split('@')[0]
        datetime2 = datetime.datetime.utcnow().strftime('%Y%m%d%H')
        ec2 = self.get_service_resource('ec2', 'us-west-2')
        qu = int(info_dict['quantity'])
        instanceid = []
        region = 'us-west-2'
        for q in range(qu):
            for i in ws:
                name = shrtowner + "-" + datetime2 + "-" + info_dict['customer'] + "-" + self.getimage_tags(region, i,
                                                                                                            'primary_product') + "-" + str(
                    q)
                machine_group = shrtowner + "-" + datetime2 + "-" + "workshop" + "-" + info_dict[
                    'customer'] + "-" + "ENV" + "-" + str(q)

                if self.getimage_tags(region, i, 'host_name') is None:
                    dnsname = "workshop"
                else:
                    dnsname = self.getimage_tags(region, i, 'host_name')
                if self.getimage_tags(region, i, 'machine__ssh_user') is None:
                    sshuser = "N/A"
                else:
                    sshuser = self.getimage_tags(region, i, 'machine__ssh_user')
                if info_dict['envrole'] == 'Production':
                    schedule = '00:00:23:59:1-5'
                else:
                    schedule = '04:00:21:00:1-5'
                response = ec2.create_instances(
                    ImageId=i,
                    InstanceType=self.getimage_tags(region, i, 'instance_type'),
                    MinCount=1,
                    MaxCount=1,
                    SecurityGroupIds=securitygrp,
                    SubnetId=info_dict['subnet'],
                    KeyName="keyPresalesNA_Prod_Demo_2020",
                    TagSpecifications=[
                        {
                            'ResourceType': 'instance',
                            'Tags': [
                                {
                                    'Key': 'OWNEREMAIL',
                                    'Value': info_dict['owneremail']
                                },
                                {
                                    'Key': 'Name',
                                    'Value': name
                                },
                                {
                                    'Key': 'NAME',
                                    'Value': name
                                },
                                {
                                    'Key': 'machine__environment_group',
                                    'Value': machine_group
                                },
                                {
                                    'Key': 'BUSINESSUNIT',
                                    'Value': 'presales'
                                },
                                {
                                    'Key': 'APPLICATIONENV',
                                    'Value': 'PROD'
                                },
                                {
                                    'Key': 'APPLICATIONROLE',
                                    'Value': 'APPSVR'
                                },
                                {
                                    'Key': 'machine__ssh_user',
                                    'Value': sshuser
                                },
                                {
                                    'Key': 'machine__name',
                                    'Value': self.getimage_tags(region, i, 'primary_product')
                                },
                                {
                                    'Key': 'image__dns_names_private',
                                    'Value': dnsname
                                },
                                {
                                    'Key': 'RUNNINGSCHEDULE',
                                    'Value': schedule
                                },

                            ]
                        }
                    ]

                )
                instanceid.append(response[0].id)
        return instanceid

    def get_instance_attr(self, region: str, instanceid: str, value: str):
        ec2 = self.get_service_resource('ec2', region)
        instance = ec2.Instance(instanceid)
        return getattr(instance, value)

    def add_sap_sg(self,region,machine_id,vpc):
        ec2 = self.get_service_resource('ec2', region)
        instance=ec2.Instance(machine_id)
        log.info(instance.security_groups)
        all_sg_ids = [sg['GroupId'] for sg in instance.security_groups]
        if vpc == 'vpc-22e59a44':
            sg='sg-057b81ca90704379e'
        elif vpc =='vpc-81e798e7':
            sg='sg-0d43b43dc43d087e1'
        elif vpc =='vpc-09f621890d284a70c':
            sg='sg-0d034eeb85e2f65a1'
        else :
            return "Unsuccessful"
        if sg not in all_sg_ids:
            all_sg_ids.append(sg)
            log.info(all_sg_ids)
            instance.modify_attribute(Groups=all_sg_ids)
            return "Successful"
        else:
            return "Unsuccessful"

    def remove_sap_sg(self,region,machine_id,vpc):
        ec2 = self.get_service_resource('ec2', region)
        instance=ec2.Instance(machine_id)
        log.info(instance.security_groups)
        all_sg_ids = [sg['GroupId'] for sg in instance.security_groups]
        if vpc == 'vpc-22e59a44':
            sg='sg-057b81ca90704379e'
        elif vpc =='vpc-81e798e7':
            sg='sg-0d43b43dc43d087e1'
        elif vpc =='vpc-09f621890d284a70c':
            sg='sg-0d034eeb85e2f65a1'
        else :
            return "Unsuccessful"
        if sg in all_sg_ids:
            all_sg_ids.remove(sg)
            log.info(all_sg_ids)
            instance.modify_attribute(Groups=all_sg_ids)
            return "Successful"
        else:
            return "Unsuccessful"

    def describe_instance_attribute(self, region: str, instance_id: str, attribute: str) -> Dict:
        ec2 = self.get_service_resource('ec2', region)
        instance = ec2.Instance(instance_id)
        return instance.describe_attribute(Attribute=attribute)

    def get_termination_protection(self, region: str, instance_id: str) -> bool:
        tp = self.describe_instance_attribute(region, instance_id, 'disableApiTermination')
        return tp.get('DisableApiTermination').get('Value')

    def get_instance_tag(self, region: str, instanceid: str, tagkey: str):
        ec2 = self.get_service_resource('ec2', region)
        instance = ec2.Instance(instanceid)
        tags = tag_list_to_dict(instance.tags)
        tag_value = tags.get(tagkey, '')
        return tag_value

    def addtag_WSecuritygrps(self, securitygrpid: str, owneremail: str):
        """Adds owner email tag to the workshop specific security group"""
        ec2 = self.get_service_resource('ec2', 'us-west-2')
        security_group = ec2.SecurityGroup(securitygrpid)
        security_group.create_tags(Tags=[{'Key': 'OWNEREMAIL', 'Value': owneremail}, ])

    def convert_instanceidstr_list(self, instancestr):
        id_list = instancestr
        id_list2 = id_list[1:]
        id_list3 = id_list2[:-1]
        id_list4 = id_list3[1:]
        id_list5 = id_list4[:-1]
        id_list6 = id_list5.replace("\'", "")
        id_list8 = id_list6.replace(' ', '')
        id_list7 = id_list8.split(',')
        return id_list7

    def get_instance_of_envgrp(self, envgrp):
        """ Returns the list of instances inside an environment group"""
        ec2 = self.get_service_resource('ec2', 'us-west-2')
        log.info(envgrp)
        instances = ec2.instances.filter(

            Filters=[{
                'Name': 'tag:machine__environment_group',
                'Values': [envgrp]
            },
                {
                    'Name': 'instance-state-name',
                    'Values': ['running']
                }]
        )
        idl = []
        for instance in instances:
            idl.append(instance.id)
        log.info(idl)
        return idl

    def update_hosts(self, instancelist: list):
        """ Gets the list of instances inside an environment group , forms a string with host file information ,
        connects to the machine and updates the host file with the new host file string """
        hostfile_dictnry = {}
        host_name_list = []
        region = 'us-west-2'
        for i in instancelist:
            privateip = self.get_instance_attr(region, i, 'private_ip_address')
            hostname = self.get_instance_tag(region, i, 'image__dns_names_private')
            hostfile_dictnry[privateip] = hostname
        strfinl = ""
        strfinl2 = ""
        for key, value in hostfile_dictnry.items():
            host_name_list.append(value)
            strfinl2 = strfinl2 + '\n' + key + ' ' + value
            if value == 'modulabs.master.infa.world':
                strfinl = strfinl + '\n' + key + ' ' + value + " " + "node01.modulabs.master.infa.world node01 sandbox.modulabs.master.infa.world sandbox sandbox-hdp sandbox-hdp.hortonworks.com ora_xe1.modulabs.master.infa.world ora_xe1 activemq.modulabs.master.infa.world activemq elasticsearch.modulabs.master.infa.world elasticsearch kibana.modulabs.master.infa.world kibana quickstart.modulabs.master.infa.world quickstart greenplum.modulabs.master.infa.world greenplum mssqlserver.modulabs.master.infa.world  mssqlserver"
            elif value == 'axon.infa.world':
                strfinl = strfinl + '\n' + key + ' ' + value + " " + "axon axon-dg-demo axon-template-dg-demo axon.localdomain.com axon.localdomain axon"
            elif value == 'ec2eicemea.infacloud.eu':
                strfinl = strfinl + '\n' + key + ' ' + value + " \n " + "ec2eicemea.infacloud ec2eicemea edc.infa.com"
                strfinl2 = strfinl2 + "ec2eicemea.infacloud ec2eicemea edc.infa.com"
            else:
                strfinl = strfinl + '\n' + key + ' ' + value
        strfinl3 = strfinl2

        for i in instancelist:
            log.info(i)
            ami_id = self.get_instance_attr(region, i, 'image_id')
            password = self.getimage_tags(region, ami_id, 'rdp_admin')
            platform = self.get_instance_attr(region, i, 'platform')
            public_ip = self.get_instance_attr(region, i, 'public_ip_address')
            host_name = self.get_instance_tag(region, i, 'image__dns_names_private')
            if platform != 'windows':
                if host_name == 'modulabs.master.infa.world':
                    try:
                        key = RSAKey.from_private_key_file('/ops-web/data/keyPresalesNA_Prod_Demo_2020.pem')
                        time.sleep(10)
                        client = SSHClient()
                        client.set_missing_host_key_policy(AutoAddPolicy())
                        log.debug("connecting to" + public_ip)
                        client.connect(hostname=public_ip, username="centos", pkey=key)
                        client.exec_command(
                            'sudo chown centos: /etc/hosts  && echo \"%s\" >> /etc/hosts' % strfinl3)
                    except Exception as e:
                        return "Host file has not been updated. Please check if the instance is running or wait sometime till the instance loads properly." + str(e)
            else:
                try:
                    subprocess.check_output([
                        "smbclient -U Administrator%{0} //{1}/c$ --directory Windows\\\System32\\\drivers\\\etc -c 'get hosts'".format(
                            password, public_ip)],
                        shell='True')
                    os.system("> /hosts ")
                    subprocess.Popen(['echo "{}" > /hosts'.format(strfinl)], shell='True')
                    result_updatehosts = subprocess.check_output([
                        "smbclient -U Administrator%{0} //{1}/c$ --directory Windows\\\System32\\\drivers\\\etc -c 'put hosts'".format(
                            password, public_ip)],
                        shell='True')
                    log.info(result_updatehosts)
                except Exception as e:
                    return "Failed updating hosts instances might still be loading please try again after sometime." + str(
                        e)

    def sync_hosts(self, instanceid: list):

        """Grabs the list of instances inside an environment group and updates hosts"""

        region = 'us-west-2'
        id_list = self.convert_instanceidstr_list(instanceid)
        env_grp_list = []
        for i in id_list:
            env_group = self.get_instance_tag(region, i, 'machine__environment_group')
            if env_group not in env_grp_list:
                env_grp_list.append(env_group)
        for env in env_grp_list:
            instance_list = self.get_instance_of_envgrp(env)
            host_result = self.update_hosts(instance_list)
        return host_result

    def allocate_elasticip(self, instanceid: list):
        """Allocates elastic Ip's to only the windows machines """

        ec2 = self.get_service_resource('ec2', 'us-west-2')
        idlist = self.convert_instanceidstr_list(instanceid)
        region = 'us-west-2'
        ec2_client = self.get_service_client('ec2', region)
        for i in idlist:
            log.info(i)
            platform = self.get_instance_attr(region, i, 'platform')
            if platform == 'windows':
                instance = ec2.Instance(i)
                state = instance.state['Name']
                if state == 'running':
                    eip = ec2_client.allocate_address(Domain='vpc')
                    ec2_client.associate_address(
                        InstanceId=i,
                        AllocationId=eip["AllocationId"])
            else:
                log.info("not allocating elastic IP as it is not a windows machine")

    def add_security_group_rule(self, region: str, sg_id: str, ip: str, description: str):
        log.debug(f'Adding {ip} to {region}:{sg_id}')
        ec2 = self.get_service_resource('ec2', region)
        sg = ec2.SecurityGroup(sg_id)
        try:
            sg.authorize_ingress(
                IpPermissions=[
                    {
                        'FromPort': -1,
                        'ToPort': -1,
                        'IpProtocol': '-1',
                        'IpRanges': [{
                            'CidrIp': f'{ip}/32',
                            'Description': description
                        }]
                    }
                ]
            )
            return "successful"
        except Exception as e:
            log.exception(e)
            return e

    def delete_security_group_rule(self, region: str, sg_id: str, ip_range: str):
        log.debug(f'Removing {ip_range} from {region}:{sg_id}')
        ec2 = self.get_service_resource('ec2', region)
        sg = ec2.SecurityGroup(sg_id)
        sg.revoke_ingress(
            IpPermissions=[{
                'FromPort': -1,
                'ToPort': -1,
                'IpProtocol': '-1',
                'IpRanges': [{'CidrIp': ip_range}]
            }]
        )

    def create_instance_defaultspecs(self, region: str, imageid: str, name: str, owner: str, environment: str,
                                     vpc: str):
        ec2 = self.get_service_resource('ec2', region)
        if vpc == 'mdmdemo':
            security_group_ids = ['sg-0bfbf3dc3c4ea981d', 'sg-02525e6c6a426c479']
            SubnetId = 'subnet-0962f22cded669d8d'
        elif vpc == 'presalesdemo':
            security_group_ids = ['sg-ffaf0082', 'sg-4dae0130']
            SubnetId = 'subnet-c5f77ba3'
        else:
            security_group_ids = ['sg-0bfbf3dc3c4ea981d', 'sg-02525e6c6a426c479']
            SubnetId = 'subnet-04544424c9710f760'
        response = ec2.create_instances(
            ImageId=imageid,
            InstanceType='m4.2xlarge',
            KeyName="keyPresalesNA_Prod_Demo",
            MaxCount=1,
            MinCount=1,
            SecurityGroupIds=security_group_ids,
            SubnetId=SubnetId,

            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {
                            'Key': 'OWNEREMAIL',
                            'Value': owner
                        },
                        {
                            'Key': 'Name',
                            'Value': name
                        },
                        {
                            'Key': 'NAME',
                            'Value': name
                        },
                        {
                            'Key': 'machine__environment_group',
                            'Value': environment
                        },
                        {
                            'Key': 'BUSINESSUNIT',
                            'Value': 'presales'
                        },
                        {
                            'Key': 'APPLICATIONENV',
                            'Value': 'PROD'
                        },
                        {
                            'Key': 'APPLICATIONROLE',
                            'Value': 'APPSVR'
                        },

                        {
                            'Key': 'machine__name',
                            'Value': 'mdm'
                        },
                        {
                            'Key': 'image__dns_names_private',
                            'Value': 'windows'
                        },
                        {
                            'Key': 'RUNNINGSCHEDULE',
                            'Value': '00:00:23:59:1-4'
                        },

                    ]
                }
            ]
        )
        return response

    def create_instance(self, region: str, imageid: str, instanceid: str, name: str, owner: str, environment: str,
                        vpc: str):

        ec2_client = self.get_service_client('ec2', region)
        try:
            response = ec2_client.describe_instances(InstanceIds=[instanceid])
        except:
            return "Unsuccessful"

        log.info(response['Reservations'])

        if not response['Reservations']:
            return "Unsuccessful"
        else:
            ec2 = self.get_service_resource('ec2', region)
            instance = ec2.Instance(instanceid)
            if vpc == 'mdmdemo':
                security_group_ids = ['sg-0bfbf3dc3c4ea981d', 'sg-02525e6c6a426c479']
                SubnetId = 'subnet-0962f22cded669d8d'
            elif vpc == 'presalesdemo':
                security_group_ids = ['sg-ffaf0082', 'sg-4dae0130']
                SubnetId = 'subnet-c5f77ba3'
            else:
                SubnetId = instance.subnet_id
                security_group_ids = []
                security_groups = instance.security_groups
                for i in security_groups:
                    for t, v in i.items():
                        if t == 'GroupId':
                            security_group_ids.append(v)
                            break

            instance_tags = tag_list_to_dict(instance.tags)
            instance_tags['Name'] = name
            instance_tags['NAME'] = name
            instance_tags['OWNEREMAIL'] = owner
            instance_tags['machine__environment_group'] = environment

            try:
                response = ec2.create_instances(
                    ImageId=imageid,
                    InstanceType=instance.instance_type,
                    KeyName=instance.key_name,
                    MaxCount=1,
                    MinCount=1,
                    SecurityGroupIds=security_group_ids,
                    SubnetId=SubnetId,

                    TagSpecifications=[
                        {
                            'ResourceType': 'instance',
                            'Tags': tag_dict_to_list(instance_tags)
                        },
                        {
                            'ResourceType': 'volume',
                            'Tags': tag_dict_to_list(instance_tags)
                        }
                    ]
                )
                return response
            except:
                return "launch_error"

    def delete_image(self, region: str, image_id: str):
        log.debug(f'Delete image: {image_id}')
        ec2 = self.get_service_resource('ec2', region)
        image = ec2.Image(image_id)
        snapshots = [ec2.Snapshot(m['Ebs']['SnapshotId']) for m in image.block_device_mappings if 'Ebs' in m]
        log.debug(f'Deregistering image: {image.id}')
        image.deregister()
        for snapshot in snapshots:
            log.debug(f'Deleting snapshot {snapshot.id}')
            snapshot.delete()

    def delete_machine(self, region: str, machine_id: str):
        """Terminate an EC2 instance in AWS.

        This will terminate the instance and delete all volumes that were attached to the instance, even if the volume
        was not set to delete on termination.

        Do not call this function during a web request. Use a scheduled job instead."""

        log.debug(f'Delete machine: {machine_id}')
        ec2 = self.get_service_resource('ec2', region)
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
            self.delete_volume(region, v)

    def delete_volume(self, region: str, volume_id: str):
        ec2 = self.get_service_resource('ec2', region)
        volume = ec2.Volume(volume_id)
        if volume.state == 'in-use':
            log.info(f'Volume {volume_id} is {volume.state}, waiting 10 seconds ...')
            time.sleep(10)
        log.info(f'Deleting volume {volume_id}')
        volume.delete()

    def get_all_images(self):
        for region in self.get_available_regions():
            log.info(f'Getting all EC2 images in {region}')
            ec2 = self.get_service_resource('ec2', region)
            try:
                for image in ec2.images.filter(Owners=['self']):
                    tags = tag_list_to_dict(image.tags)
                    params = {
                        'id': image.id,
                        'cloud': 'aws',
                        'region': region,
                        'name': tags.get('NAME', image.name),
                        'owner': tags.get('OWNEREMAIL', '').lower(),
                        'public': ops_web.config.as_bool(tags.get('image_public', '')),
                        'state': image.state,
                        'created': image.creation_date,
                        'instanceid': tags.get('machine__description', '')
                    }
                    cost = decimal.Decimal('0')
                    for b in image.block_device_mappings:
                        if 'Ebs' in b:
                            cost += self.db.get_cost_for_resource(b.get('Ebs').get('SnapshotId'))
                    params['cost'] = cost
                    yield params
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')

    def get_all_security_groups(self):
        for region in self.get_available_regions():
            log.info(f'Getting all security groups in {region}')
            ec2 = self.session.resource('ec2', region_name=region)
            try:
                for sg in ec2.security_groups.all():
                    sg_rules = []
                    tags = tag_list_to_dict(sg.tags)
                    for ip_perm in sg.ip_permissions:
                        for ip_range in ip_perm.get('IpRanges', []):
                            sg_rules.append({
                                'ip_range': ip_range.get('CidrIp'),
                                'description': ip_range.get('Description')}
                            )
                    params = {
                        'region': region,
                        'owner': tags.get('OWNEREMAIL', '').lower(),
                        'cloud': 'aws',
                        'id': sg.group_id,
                        'sg_rules': sg_rules,
                        'group_name': sg.group_name
                    }
                    yield params
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')

    def get_all_instances(self):
        for region in self.get_available_regions():
            log.info(f'Getting all EC2 instances in {region}')
            ec2 = self.get_service_resource('ec2', region)
            try:
                for instance in ec2.instances.all():
                    yield self.get_instance_dict(region, instance)
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')

    def get_available_regions(self):
        return self.session.get_available_regions('ec2')

    def get_instance_dict(self, region, instance) -> Dict:
        tags = tag_list_to_dict(instance.tags)
        params = {
            'id': instance.id,
            'cloud': 'aws',
            'region': region,
            'environment': tags.get('machine__environment_group', ''),
            'name': tags.get('NAME', ''),
            'owner': tags.get('OWNEREMAIL', '').lower(),
            'private_ip': instance.private_ip_address,
            'public_ip': instance.public_ip_address,
            'type': instance.instance_type,
            'running_schedule': tags.get('RUNNINGSCHEDULE', ''),
            'state': instance.state['Name'],
            'created': instance.launch_time,
            'state_transition_time': None,
            'application_env': tags.get('APPLICATIONENV', ''),
            'application_role': tags.get('APPLICATIONROLE', ''),
            'business_unit': tags.get('BUSINESSUNIT', ''),
            'dns_names': tags.get('image__dns_names_private', ''),
            'whitelist': self.get_whitelist_for_instance(instance),
            'vpc': instance.vpc_id
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

        # Find cost of instance and all attached volumes and network interfaces
        cost = self.db.get_cost_for_resource(instance.id)
        for m in instance.block_device_mappings:
            volume_id = m.get('Ebs', {}).get('VolumeId')
            cost += self.db.get_cost_for_resource(volume_id)
        for n in instance.network_interfaces_attribute:
            network_interface_id = n.get('NetworkInterfaceId')
            cost += self.db.get_cost_for_resource(network_interface_id)
        params['cost'] = cost

        return params

    def get_single_instance(self, region: str, instanceid: str):
        ec2 = self.get_service_resource('ec2', region)
        instance = ec2.Instance(instanceid)
        return self.get_instance_dict(region, instance)

    def get_whitelist_for_instance(self, instance):
        whitelist = set()
        for sg in instance.security_groups:
            sg_id = sg.get('GroupId')
            if sg_id in self.config.aws_ignored_security_groups:
                continue
            whitelist.update([r.get('ip_range') for r in self.db.get_security_group_rules(sg_id)])
        return ' '.join(sorted(whitelist))

    def start_machine(self, region: str, machine_id: str):
        log.debug(f'Start machine: {machine_id}')
        ec2 = self.get_service_resource('ec2', region)
        instance = ec2.Instance(machine_id)
        instance.start()
        return instance

    def stop_machine(self, region: str, machine_id: str):
        log.debug(f'Stop machine: {machine_id}')
        ec2 = self.get_service_resource('ec2', region)
        instance = ec2.Instance(machine_id)
        instance.stop()
        return instance

    def update_resource_tags(self, region: str, resource_id: str, tags: Dict):
        log.debug(f'Update tags: {resource_id}')
        ec2 = self.get_service_resource('ec2', region)
        ec2.create_tags(
            Resources=[resource_id],
            Tags=tag_dict_to_list(tags)
        )
