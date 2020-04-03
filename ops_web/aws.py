import datetime

import boto3
import botocore.exceptions
from paramiko import RSAKey, SSHClient, AutoAddPolicy

import ops_web.config
import logging
import time
import botocore
import paramiko
import os
import subprocess
import requests

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
        self.access_key_id = access_key_id
        self.secret_access_key = secret_access_key
        self.session = boto3.session.Session(access_key_id, secret_access_key)

    def create_image(self, region: str, machine_id: str, name: str, owner: str, public: bool = False) -> str:
        log.debug(f'Creating image from {machine_id} for {owner}')
        ec2 = self.session.resource('ec2', region_name=region)
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
        ec2 = self.session.resource('ec2', region_name='us-west-2')
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
        ec2 = self.session.resource('ec2', region_name=region)
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
        ec2 = self.session.resource('ec2', region_name='us-west-2')
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
                    KeyName="keyPresalesNA_Prod_Demo",
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
        ec2 = self.session.resource('ec2', region_name=region)
        instance = ec2.Instance(instanceid)
        return getattr(instance, value)

    def describe_instance_attribute(self, region: str, instance_id: str, attribute: str) -> Dict:
        ec2 = self.session.resource('ec2', region_name=region)
        instance = ec2.Instance(instance_id)
        return instance.describe_attribute(Attribute=attribute)

    def get_termination_protection(self, region: str, instance_id: str) -> bool:
        tp = self.describe_instance_attribute(region, instance_id, 'disableApiTermination')
        return tp.get('DisableApiTermination').get('Value')

    def get_instance_tag(self, region: str, instanceid: str, tagkey: str):
        ec2 = self.session.resource('ec2', region_name=region)
        instance = ec2.Instance(instanceid)
        tags = tag_list_to_dict(instance.tags)
        tag_value = tags.get(tagkey, '')
        return tag_value

    def addtag_WSecuritygrps(self, securitygrpid: str, owneremail: str):
        """Adds owner email tag to the workshop specific security group"""
        ec2 = self.session.resource('ec2', region_name='us-west-2')
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
        ec2 = self.session.resource('ec2', region_name='us-west-2')
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
        strfinl3 = strfinl2 + " " + "127.0.0.1" + "  " + "localhost localhost.localdomain localhost4 localhost4.localdomain4" + "\n" + "::1" + "  " + "localhost localhost.localdomain localhost6 localhost6.localdomain6"

        for i in instancelist:
            log.info(i)
            ami_id = self.get_instance_attr(region, i, 'image_id')
            password = self.getimage_tags(region, ami_id, 'rdp_admin')
            platform = self.get_instance_attr(region, i, 'platform')
            public_ip = self.get_instance_attr(region, i, 'public_ip_address')
            host_name = self.get_instance_tag(region, i, 'image__dns_names_private')
            if platform != 'windows':
                if host_name != 'modulabs.master.infa.world':
                    # try:
                        key = RSAKey.from_private_key_file('/ops-web/data/keyPresalesNA_Prod_Demo.pem')
                        time.sleep(10)
                        client = SSHClient()
                        client.set_missing_host_key_policy(AutoAddPolicy())
                        log.debug("connecting to" + public_ip)
                        client.connect(hostname=public_ip, username="centos", pkey=key)
                        client.exec_command(
                            'sudo chown centos: /etc/hosts && >/etc/hosts && echo \"%s\" >> /etc/hosts' % strfinl3)
                    # except:
                    #     return "Host file has not been updated. Please check if the instance is running or wait sometime till the instance loads properly."
            else:
                # try:
                    subprocess.check_output([
                        "smbclient -U Administrator%{0} //{1}/c$ --directory Windows\\\System32\\\drivers\\\etc -c 'get hosts'".format(
                            password, public_ip)],
                        shell='True')
                    os.system("> /hosts ")
                    subprocess.Popen(['echo "{}" > /hosts'.format(strfinl)], shell='True')
                    subprocess.check_output([
                        "smbclient -U Administrator%{0} //{1}/c$ --directory Windows\\\System32\\\drivers\\\etc -c 'put hosts'".format(
                            password, public_ip)],
                        shell='True')
                # except:
                #     return "Failed updating hosts instances might still be loading please try again after sometime."

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

        ec2 = self.session.resource('ec2', region_name='us-west-2')
        idlist = self.convert_instanceidstr_list(instanceid)
        region = 'us-west-2'
        ec2Client = self.session.client('ec2', region)
        for i in idlist:
            log.info(i)
            platform = self.get_instance_attr(region, i, 'platform')
            if platform == 'windows':
                instance = ec2.Instance(i)
                state = instance.state['Name']
                if state == 'running':
                    eip = ec2Client.allocate_address(Domain='vpc')
                    ec2Client.associate_address(
                        InstanceId=i,
                        AllocationId=eip["AllocationId"])
            else:
                log.info("not allocating elastic IP as it is not a windows machine")

    def add_inboundrule(self, sgid: str, ip: str):
        log.info(ip)
        ec2 = self.session.resource('ec2', region_name='us-west-2')
        sg = ec2.SecurityGroup(sgid)
        try:
            sg.authorize_ingress(
                IpPermissions=[
                    {
                        'FromPort': -1,
                        'IpProtocol': '-1',
                        'IpRanges': [
                            {
                                'CidrIp': ip,
                            },

                        ],
                        'ToPort': -1,
                    }
                ]
            )
            return "successful"
        except:
            return "exception!"

    def create_instance(self, region: str, imageid: str, instanceid: str, name: str, owner: str, environment: str):
        ec2 = self.session.resource('ec2', region_name=region)
        instance = ec2.Instance(instanceid)

        security_group_ids = []
        security_groups = instance.security_groups
        for i in security_groups:
            for t, v in i.items():
                if t == 'GroupId':
                    security_group_ids.append(v)

        instance_tags = tag_list_to_dict(instance.tags)
        instance_tags['Name'] = name
        instance_tags['NAME'] = name
        instance_tags['OWNEREMAIL'] = owner
        instance_tags['machine__environment_group'] = environment

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
                    'Tags': tag_dict_to_list(instance_tags)
                },
                {
                    'ResourceType': 'volume',
                    'Tags': tag_dict_to_list(instance_tags)
                }
            ]
        )
        return response

    def delete_image(self, region: str, image_id: str):
        log.debug(f'Delete image: {image_id}')
        ec2 = self.session.resource('ec2', region_name=region)
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
        ec2 = self.session.resource('ec2', region_name=region)
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
        ec2 = self.session.resource('ec2', region_name=region)
        volume = ec2.Volume(volume_id)
        if volume.state == 'in-use':
            log.info(f'Volume {volume_id} is {volume.state}, waiting 10 seconds ...')
            time.sleep(10)
        log.info(f'Deleting volume {volume_id}')
        volume.delete()

    def get_all_images(self):
        for region in self.get_available_regions():
            log.info(f'Getting all EC2 images in {region}')
            ec2 = self.session.resource('ec2', region_name=region)
            try:
                for image in ec2.images.filter(Owners=['self']):
                    tags = tag_list_to_dict(image.tags)
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

    def get_all_securitygrps(self):
        for region in self.get_available_regions():
            ec2 = self.session.resource('ec2', region_name=region)
            security_groups = ec2.security_groups.all()
            try:
                for sgid in security_groups:
                    inbound_address_list = []
                    tags = tag_list_to_dict(sgid.tags)
                    ip_permissions_list = sgid.ip_permissions
                    if (len(ip_permissions_list)) == 0:
                        inbound_address_list = []
                    else:
                        for i in ip_permissions_list:
                            if 'IpRanges' in i:
                                ips = i['IpRanges']
                        for s in ips:
                            if 'CidrIp' in s:
                                inbound_address_list.append(s['CidrIp'])
                    params = {
                        'owner': tags.get('OWNEREMAIL', ''),
                        'cloud': 'aws',
                        'id': sgid.group_id,
                        'inbound_rules': inbound_address_list,
                        'group_name': sgid.group_name
                    }
                    yield params
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')

    def get_all_instances(self,report_id):
        for region in self.get_available_regions():
            log.info(f'Getting all EC2 instances in {region}')
            url = f'https://app.cloudability.com/api/1/reporting/cost/reports/{report_id}/results?auth_token={self.config.cloudability_auth_token}'
            response = requests.get(url)
            dictr={}
            result = response.json()
            jsonresult=result['results']
            for i in jsonresult:
                for k, v in i.items():
                    if (k == 'resource_identifier'):
                        l = v
                        continue
                    elif (k == 'unblended_cost'):
                        g = v
                    else:
                        g = None
                    dictr[l] = g
            ec2 = self.session.resource('ec2', region_name=region)
            try:
                for instance in ec2.instances.all():
                    yield self.get_instance_dict(region, instance, dictr)
            except botocore.exceptions.ClientError as e:
                log.critical(e)
                log.critical(f'Skipping {region}')

    def get_available_regions(self):
        return self.session.get_available_regions('ec2')

    def get_unblendedcost(self,instanceid , result , volid):
        for i, f in result.items():
            if (i == instanceid):
                ic = f
                break
            else:
                ic= '$0'
        instance_cost = ic[1:]
        if ',' in instance_cost:
            instance_cost= instance_cost.replace(',','')
        else:
            instance_cost=instance_cost
        for i,f in result.items():
               if(i == volid):
                   vc=f
                   break
               else:
                    vc='$0'
        volume_cost = vc[1:]
        if ',' in volume_cost:
            volume_cost=volume_cost.replace(',','')
        else:
            volume_cost=volume_cost
        return float(instance_cost) + float(volume_cost)

    def get_volume(self,vol_list):
        for vol in vol_list:
            return vol['Ebs']['VolumeId']

    def get_instance_dict(self, region, instance, result) -> Dict:
        tags = tag_list_to_dict(instance.tags)
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
            'dns_names': tags.get('image__dns_names_private', ''),
            'whitelist': self.get_whitelist_for_instance(region, instance),
            'vpc': instance.vpc_id,
            'cost': self.get_unblendedcost(instance.id, result, self.get_volume(instance.block_device_mappings))
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

    def get_single_instance(self, region: str, instanceid: str , report_id):
        ec2 = self.session.resource('ec2', region_name=region)
        instance = ec2.Instance(instanceid)
        url = f'https://app.cloudability.com/api/1/reporting/cost/reports/{report_id}/results?auth_token={self.config.cloudability_auth_token}'
        response = requests.get(url)
        dictr = {}
        result = response.json()
        jsonresult = result['results']
        for i in jsonresult:
            for k, v in i.items():
                if (k == 'resource_identifier'):
                    l = v
                    continue
                elif (k == 'unblended_cost'):
                    g = v
                else:
                    g = None
                dictr[l] = g

        return self.get_instance_dict(region, instance , dictr)

    def get_whitelist_for_instance(self, region: str, instance):
        whitelist = set()
        ec2 = self.session.resource('ec2', region_name=region)
        for sg in instance.security_groups:
            sg_id = sg.get('GroupId')
            if sg_id in self.config.aws_ignored_security_groups:
                continue
            sg = ec2.SecurityGroup(sg_id)
            for p in sg.ip_permissions:
                whitelist.update([r.get('CidrIp') for r in p.get('IpRanges')])
        return ' '.join(sorted(whitelist))

    def start_machine(self, region: str, machine_id: str):
        log.debug(f'Start machine: {machine_id}')
        ec2 = self.session.resource('ec2', region_name=region)
        instance = ec2.Instance(machine_id)
        instance.start()
        return instance

    def stop_machine(self, region: str, machine_id: str):
        log.debug(f'Stop machine: {machine_id}')
        ec2 = self.session.resource('ec2', region_name=region)
        instance = ec2.Instance(machine_id)
        instance.stop()
        return instance

    def update_resource_tags(self, region: str, resource_id: str, tags: Dict):
        log.debug(f'Update tags: {resource_id}')
        ec2 = self.session.resource('ec2', region_name=region)
        ec2.create_tags(
            Resources=[resource_id],
            Tags=[{'Key': k, 'Value': v} for k, v in tags.items()]
        )
