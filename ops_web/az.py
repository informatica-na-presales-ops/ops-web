import azure.common.credentials
import azure.mgmt.compute
import azure.mgmt.network
import azure.mgmt.subscription
import logging
import msrestazure.azure_exceptions
import ops_web.config
import subprocess
from typing import Dict
import os
from azure.cli.core import get_default_cli
from paramiko import RSAKey, SSHClient, AutoAddPolicy

log = logging.getLogger(__name__)

IMAGE_STATE_MAP = {
    'Succeeded': 'available'
}

VM_STATE_MAP = {
    'stopped': 'suspended',
    'deallocated': 'stopped',
}


class AZClient:
    def __init__(self, config: ops_web.config.Config, client_id: str, secret: str, tenant: str):
        self.config = config
        self.credentials = azure.common.credentials.ServicePrincipalCredentials(
            client_id=client_id, secret=secret, tenant=tenant
        )
        self.subscriptions = {}
        with azure.mgmt.subscription.SubscriptionClient(self.credentials) as client:
            for sub in client.subscriptions.list():
                self.subscriptions[sub.subscription_id] = sub.display_name

    def get_compute_client(self, subscription_id: str) -> azure.mgmt.compute.ComputeManagementClient:
        return azure.mgmt.compute.ComputeManagementClient(credentials=self.credentials, subscription_id=subscription_id)

    def get_all_images(self):
        for subscription_id in self.subscriptions:
            log.info(f'Getting all images in subscription {subscription_id}')
            compute_client = self.get_compute_client(subscription_id)

            for image in compute_client.images.list():
                if image.tags is None:
                    image.tags = {}
                params = {
                    'id': image.id,
                    'cloud': 'az',
                    'region': image.location,
                    'name': image.tags.get('NAME', image.name),
                    'owner': image.tags.get('OWNEREMAIL', ''),
                    'public': ops_web.config.as_bool(image.tags.get('image_public', '')),
                    'state': IMAGE_STATE_MAP.get(image.provisioning_state, image.provisioning_state),
                    'created': None,
                    'instanceid': None
                }
                yield params
            compute_client.close()
    def get_unblendedcost(self,instanceid,result):
        id_lower = instanceid.lower()
        if id_lower in result:
            log.info(result.values())
            log.info(result[id_lower])
            cost = result[id_lower][1:]
            if ',' in cost:
                instance_cost = cost.replace(',', '')
                return instance_cost
            else:
                return cost

        else:
               return 0

    def get_all_virtual_machines(self):
        for subscription_id in self.subscriptions:

            log.info(f'Getting all virtual machines in subscription {subscription_id}')
            compute_client = self.get_compute_client(subscription_id)

            network_client = azure.mgmt.network.NetworkManagementClient(
                credentials=self.credentials, subscription_id=subscription_id
            )
            network_interfaces = {nic.id: nic for nic in network_client.network_interfaces.list_all()}
            log.debug(network_interfaces)
            public_ips = {public_ip.id: public_ip for public_ip in network_client.public_ip_addresses.list_all()}
            log.debug(public_ips)
            # dictr={}
            # jsonresult = result['results']
            # for i in jsonresult:
            #     for k, v in i.items():
            #         if (k == 'resource_identifier'):
            #             if('::' in v):
            #                 isy = v.split('/', 1)[1]
            #                 it = "/" + isy
            #                 l = it
            #                 continue
            #         elif (k == 'unblended_cost'):
            #             g = v
            #         else:
            #             g = None
            #         dictr[l] = g

            for vm in compute_client.virtual_machines.list_all():
                log.debug(f'Found a virtual machine: {vm.id}')
                vm_rg = vm.id.split('/')[4]
                if vm.tags is None:
                    vm.tags = {}
                params = {
                    'id': vm.id,
                    'cloud': 'az',
                    'region': vm.location,
                    'environment': vm.tags.get('machine__environment_group', 'default-environment'),
                    'name': vm.tags.get('NAME', vm.name),
                    'owner': vm.tags.get('OWNEREMAIL', ''),
                    'contributors': vm.tags.get('CONTRIBUTORS', ''),
                    'private_ip': None,
                    'public_ip': None,
                    'type': vm.hardware_profile.vm_size,
                    'running_schedule': vm.tags.get('RUNNINGSCHEDULE', ''),
                    'state': 'unknown',
                    'state_transition_time': None,
                    'application_env': vm.tags.get('APPLICATIONENV', ''),
                    'business_unit': vm.tags.get('BUSINESSUNIT', ''),
                    'created': None,
                    'dns_names': vm.tags.get('image__dns_names_private', ''),
                    'whitelist': None,
                    'vpc': None,
                    'disable_termination': None,
                    'cost': 0
                }
                #self.get_unblendedcost(vm.id, dictr)

                if params['dns_names'] == '':
                    params['dns_names'] = params.get('name')

                # request virtual machine creation date and status (is it stopped, running, &c.)
                iv = compute_client.virtual_machines.instance_view(vm_rg, vm.name)
                for status in iv.statuses:
                    log.debug(f'Found a status: {status.code} {status.time}')
                    if status.code == 'ProvisioningState/succeeded':
                        params['created'] = status.time
                    elif status.code.startswith('PowerState/'):
                        az_status = status.code.split('/')[-1]
                        params['state'] = VM_STATE_MAP.get(az_status, az_status)
                        break

                # request private and public ip addresses
                nic = network_interfaces.get(vm.network_profile.network_interfaces[0].id)
                for ip_config in nic.ip_configurations:
                    params['private_ip'] = ip_config.private_ip_address
                    if ip_config.public_ip_address is not None:
                        public_ip = public_ips.get(ip_config.public_ip_address.id)
                        params['public_ip'] = public_ip.ip_address

                yield params
            compute_client.close()
            network_client.close()

    def get_virtualmachine_info(self, vmname, resource_group_name):
        subscriptionId = '950a5f1a-97b6-4c9c-b79b-e32d951b5e66'
        vmname = str(vmname)
        log.info(vmname)
        compute_client = self.get_compute_client(subscriptionId)
        vm3 = vmname.rsplit("/", 1)[1]
        log.info(vm3)
        vm2 = vm3[:-1]
        vm = compute_client.virtual_machines.get(resource_group_name, vm2)
        log.info(vm)
        log.info(vm.id)
        network_client = azure.mgmt.network.NetworkManagementClient(
            credentials=self.credentials, subscription_id=subscriptionId
        )

        nic = vm2 + "_nic"
        public_ips = vm2 + '_public_ip'
        ip = (network_client.public_ip_addresses.get(resource_group_name, public_ips))
        private_ip = network_client.network_interfaces.get(resource_group_name, nic)
        log.debug(f'Found a virtual machine: {vm.id}')

        params = {
            'id': vm.id,
            'cloud': 'az',
            'region': vm.location,
            'environment': vm.tags.get('machine__environment_group', 'default-environment'),
            'name': vm.tags.get('NAME', vm.name),
            'owner': vm.tags.get('OWNEREMAIL', ''),
            'contributors': vm.tags.get('CONTRIBUTORS', ''),
            'private_ip': private_ip.ip_configurations[0].private_ip_address,
            'public_ip': ip.ip_address,
            'type': vm.hardware_profile.vm_size,
            'running_schedule': vm.tags.get('RUNNINGSCHEDULE', ''),
            'state': 'unknown',
            'state_transition_time': None,
            'application_env': vm.tags.get('APPLICATIONENV', ''),
            'business_unit': vm.tags.get('BUSINESSUNIT', ''),
            'created': None,
            'dns_names': vm.tags.get('image__dns_names_private', ''),
            'whitelist': None,
            'vpc': None,
            'cost':None
        }

        return params

    def update_image_tags(self, image_id: str, tags: Dict):
        log.debug(f'Update tags: {image_id}')
        tokens = image_id.split('/')
        subscription_id = tokens[2]
        resource_group_name = tokens[4]
        image_name = tokens[8]
        compute_client = self.get_compute_client(subscription_id)
        image = compute_client.images.get(resource_group_name, image_name)
        image.tags.update(tags)
        compute_client.images.update(resource_group_name, image_name, image)
        compute_client.close()

    def start_machine(self, machine_id: str):
        log.debug(f'Start machine: {machine_id}')
        tokens = machine_id.split('/')
        subscription_id = tokens[2]
        resource_group_name = tokens[4]
        vm_name = tokens[8]
        compute_client = self.get_compute_client(subscription_id)
        compute_client.virtual_machines.start(resource_group_name, vm_name)
        compute_client.close()

    def stop_machine(self, machine_id: str):
        log.debug(f'Stop machine: {machine_id}')
        tokens = machine_id.split('/')
        subscription_id = tokens[2]
        resource_group_name = tokens[4]
        vm_name = tokens[8]
        compute_client = self.get_compute_client(subscription_id)
        compute_client.virtual_machines.deallocate(resource_group_name, vm_name)
        compute_client.close()

    def update_machine_tags(self, machine_id: str, tags: Dict):
        log.debug(f'Update tags: {machine_id}')
        tokens = machine_id.split('/')
        subscription_id = tokens[2]
        resource_group_name = tokens[4]
        vm_name = tokens[8]
        compute_client = self.get_compute_client(subscription_id)
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name)
        if vm.tags is None:
            vm.tags = {}
        vm.tags.update(tags)
        vm.plan = None
        try:
            compute_client.virtual_machines.update(resource_group_name, vm_name, vm)
        except msrestazure.azure_exceptions.CloudError as e:
            log.critical(e.error)
        finally:
            compute_client.close()

    def sync_hosts(self, instance):
        log.info(instance)
        log.info(type(instance))
        resourceGroupName = 'rg-cdw-workshops-201904'
        env_grp_list = []
        id_list = instance
        id_list2 = id_list[1:]
        id_list3 = id_list2[:-1]
        id_list4 = id_list3[1:]
        id_list5 = id_list4[:-1]
        id_list6 = id_list5.replace("\'", "")
        id_list8 = id_list6.replace(' ', '')
        id_list7 = id_list8.split(',')
        log.info(id_list7)
        for s in id_list7:
            i = '"' + s + '"'
            log.info(i)
            infores = self.get_virtualmachine_info(i, resourceGroupName)
            log.info(infores)
            envgrp = infores['environment']
            if envgrp not in env_grp_list:
                env_grp_list.append(envgrp)

        log.info(env_grp_list)
        for i in env_grp_list:
            log.info(i)
            i = "'" + i + "'"
            log.info(i)
            result = subprocess.check_output([
                "az resource list  --resource-group rg-cdw-workshops-201904 --query \"[?type=='Microsoft.Compute/virtualMachines' && tags.machine__environment_group == {0}].id\" --output tsv".format(
                    i)],
                shell=True)
            instance_in_envgrp = result.decode("utf-8")
            id2 = instance_in_envgrp.split('\n')
            log.info(id2)
            log.info(type(id2))
            id2.pop()
            log.info(id2)
            result = self.update_hosts(id2)

    def update_hosts(self, id2):
        resourceGroupName = 'rg-cdw-workshops-201904'
        hostfile_dictnry = {}
        for i in id2:
            log.info(i)
            s = '"' + i + '"'
            rest = self.get_virtualmachine_info(s, resourceGroupName)
            private_ip = rest['private_ip']
            log.info(private_ip)
            name = rest['name']
            if "cdh" in name:
                dns = "hadoopsvc hadoopsvc"
                hostfile_dictnry[private_ip] = dns
            elif "infa" in name:
                dns = "tttinfasvc tttinfasvc"
                hostfile_dictnry[private_ip] = dns
            else:
                dns = ""

        log.info(hostfile_dictnry)
        strfinl = ""
        strfinl2 = ""
        for key, value in hostfile_dictnry.items():
            log.info(key)
            strfinl2 = strfinl2 + '\n' + key + ' ' + value
        strfinl3 = strfinl2 + " " + "\n" + "127.0.0.1" + "  " + "localhost localhost.localdomain localhost4 localhost4.localdomain4" + "\n" + "::1" + "  " + "localhost localhost.localdomain localhost6 localhost6.localdomain6"
        log.info(strfinl3)
        for i in id2:
            s = '"' + i + '"'
            rest = self.get_virtualmachine_info(s, resourceGroupName)
            log.info(rest)
            if "jumpbox" in rest['name']:
                # rest = self.get_virtualmachine_info(s, resourceGroupName)
                log.info(subprocess.check_output([
                    "smbclient -U Administrator%{0} //{1}/c$ --directory Windows\\\System32\\\drivers\\\etc -c 'get hosts'".format(
                        "Infaworld2018", rest['public_ip'])],
                    shell='True'))
                os.system("> /hosts ")
                subprocess.Popen(['echo "{}" > /hosts'.format(strfinl3)], shell='True')
                subprocess.check_output([
                    "smbclient -U Administrator%{0} //{1}/c$ --directory Windows\\\System32\\\drivers\\\etc -c 'put hosts'".format(
                        "Infaworld2018", rest['public_ip'])],
                    shell='True')
            elif "cdh" in rest['name']:
                key = RSAKey.from_private_key_file('/ops-web/data/keyPresalesNA_Prod_Demo.pem')

                client = SSHClient()
                client.set_missing_host_key_policy(AutoAddPolicy())
                log.debug("connecting to" + rest['public_ip'])
                client.connect(hostname=rest['public_ip'], username="az-user", pkey=key)
                client.exec_command(
                    'sudo chown az-user: /etc/hosts && >/etc/hosts && echo \"%s\" >> /etc/hosts' % strfinl3)
            else:
                continue

    def launch_cdh_instance(self, user, password, tenantid, vmbase, owner):

        k = vmbase.rfind('-')
        virtual_machine_name = vmbase[:k] + "-cdh-" + vmbase[k + 1:]
        log.info(virtual_machine_name)
        owner = owner
        subscriptionId = '950a5f1a-97b6-4c9c-b79b-e32d951b5e66'
        resourceGroupName = 'rg-cdw-workshops-201904'
        virtualNetworkName = 'vnet-cdw-workshops-201904'
        snapshotName_os = 'cdwinfa_master_os'
        snapshotName_data = 'cdwinfa_master_data'
        osDiskName = virtual_machine_name + '_os'
        DiskName_data = virtual_machine_name + '_data'
        tags = "APPLICATIONENV=PROD APPLICATIONROLE=APPSVR BUSINESSUNIT=NA-Presales OWNEREMAIL=" + owner + " RUNNINGSCHEDULE=00:03:20:00:1-7 NAME=" + virtual_machine_name + " machine__environment_group=" + vmbase
        nicName = virtual_machine_name + "_nic"
        storageType = 'Standard_LRS'
        osType = 'Linux'

        compute_client = self.get_compute_client(subscriptionId)
        network_client = azure.mgmt.network.NetworkManagementClient(
            credentials=self.credentials, subscription_id=subscriptionId
        )
        subprocess.check_output(
            ["az login --service-principal -u {0} -p {1} --tenant {2}".format(user, password, tenantid)], shell=True)
        mypublic_ip = virtual_machine_name + '_public_ip'
        subprocess.check_output(["az network public-ip create -g {0} -n {1} --allocation-method Static".format(
            resourceGroupName, mypublic_ip)], shell=True)
        subnet_id = subprocess.check_output([
                                                "az network vnet show --name {0} --resource-group {1} --query subnets[0].id -o tsv".format(
                                                    virtualNetworkName, resourceGroupName)], shell=True)
        subnet_id = subnet_id.decode("utf-8")
        subnetid2 = subnet_id.replace('\n', '')
        subnet_id2 = "'{0}'".format(subnetid2)
        nsgName = 'nsg-cdw-workshops-201904'
        subnetName = subprocess.check_output([
                                                 "az network vnet show --name {0} --resource-group {1}  --query subnets[0].name -o tsv".format(
                                                     virtualNetworkName, resourceGroupName)], shell=True)
        subprocess.check_output([
                                    "az network nic create  --resource-group {0} --name {1} --subnet {2} --network-security-group {3} --public-ip-address {4} -l {5}".format(
                                        resourceGroupName, nicName, subnet_id2, nsgName, mypublic_ip, 'westus')],
                                shell=True)
        snapshotId_os = subprocess.check_output([
                                                    "az snapshot show --name {0} --resource-group {1} --query [id] -o tsv".format(
                                                        snapshotName_os, resourceGroupName)], shell=True)
        s3 = snapshotId_os.decode("utf-8")
        snapshotId_data = subprocess.check_output([
                                                      "az snapshot show --name {0} --resource-group {1} --query [id] -o tsv".format(
                                                          snapshotName_data, resourceGroupName)], shell=True)
        l3 = snapshotId_data.decode("utf-8")
        compute_client.disks.create_or_update(resourceGroupName, osDiskName, {
            'location': 'westus',
            'storage_profile': {
                'os_disk': {
                    'os_type': 'Linux'
                }
            },
            'sku': {
                'name': storageType,

            },
            'creation_data': {
                'create_option': 'Copy',
                'source_resource_id': s3
            }
        })

        compute_client.disks.create_or_update(resourceGroupName, DiskName_data, {
            'location': 'westus',
            'storage_profile': {
                'os_disk': {
                    'os_type': 'Linux'
                }
            },
            'sku': {
                'name': storageType,

            },
            'creation_data': {
                'create_option': 'Copy',
                'source_resource_id': l3
            }
        })

        virtualMachineSize = 'Standard_B16ms'
        result = subprocess.check_output([
                                             "az vm create --name {0} --resource-group {1} --attach-os-disk {2} --os-type {3} --nics {4} --attach-data-disks {5} --size {6} --tags {7}".format(
                                                 virtual_machine_name, resourceGroupName, osDiskName, osType, nicName,
                                                 DiskName_data, virtualMachineSize, tags)], shell=True)
        result = result.decode("utf-8")
        result_split = result.split(',')[1]
        result_dict = result_split.split(":")
        instance_id = result_dict[1]
        return instance_id

    def launch_windows(self, user, password, tenantid, vmbase, owner):
        k = vmbase.rfind('-')
        virtual_machine_name = vmbase[:k] + "-jumpbox-" + vmbase[k + 1:]
        log.info(virtual_machine_name)
        subscriptionId = '950a5f1a-97b6-4c9c-b79b-e32d951b5e66'
        compute_client = self.get_compute_client(subscriptionId)
        # subprocess.check_output(["az login --service-principal -u {0} -p {1} --tenant {2}".format(user,password,tenantid)],shell=True)

        tags = "APPLICATIONENV=PROD APPLICATIONROLE=APPSVR BUSINESSUNIT=NA-Presales OWNEREMAIL=" + owner + " RUNNINGSCHEDULE=00:03:20:00:1-7 NAME=" + virtual_machine_name + " machine__environment_group=" + vmbase
        osDiskName = virtual_machine_name + "_os"
        # DiskName_data = virtual_machine_name + "_data"

        storageType = 'Standard_LRS'
        osType = 'windows'
        nicName = virtual_machine_name + "_nic"
        myPublicIP = virtual_machine_name + '_public_ip'
        resourceGroupName = 'rg-cdw-workshops-201904'
        virtualNetworkName = 'vnet-cdw-workshops-201904'
        snapshotName_os = 'cdwjumpbox_os_master'
        subprocess.check_output(["az network public-ip create -g {0} -n {1} --allocation-method Static".format(
            resourceGroupName, myPublicIP)], shell=True)
        SubnetId = subprocess.check_output([
                                               "az network vnet show --name {0} --resource-group {1} --query subnets[0].id -o tsv".format(
                                                   virtualNetworkName, resourceGroupName)], shell=True)
        subnet_id = SubnetId.decode("utf-8")
        subnetid2 = subnet_id.replace('\n', '')
        subnet_id2 = "'{0}'".format(subnetid2)
        nsgName = "nsg-cdw-workshops-201904"
        subprocess.check_output([
                                    "az network nic create  --resource-group {0} --name {1} --subnet {2} --network-security-group {3} --public-ip-address {4} -l {5}".format(
                                        resourceGroupName, nicName, subnet_id2, nsgName, myPublicIP, 'westus')],
                                shell=True)
        snapshotId_os = subprocess.check_output(
            ["az snapshot show --name {0} --resource-group {1} --query [id] -o tsv".format(
                snapshotName_os, resourceGroupName)], shell=True)
        s3 = snapshotId_os.decode("utf-8")
        compute_client.disks.create_or_update(resourceGroupName, osDiskName, {
            'location': 'westus',
            'storage_profile': {
                'os_disk': {
                    'os_type': 'windows'
                }
            },
            'sku': {
                'name': storageType,

            },
            'creation_data': {
                'create_option': 'Copy',
                'source_resource_id': s3
            }
        })
        virtualMachineSize = 'Standard_B2s'
        result = subprocess.check_output([
            "az vm create --name {0} --resource-group {1} --attach-os-disk {2} --os-type {3} --nics {4} --size {5} --tags {6}".format(
                virtual_machine_name,
                resourceGroupName, osDiskName, osType, nicName, virtualMachineSize,
                tags)], shell=True)
        result = result.decode("utf-8")
        result_split = result.split(',')[1]
        result_dict = result_split.split(":")
        instance_id = result_dict[1]
        return instance_id

    def launch_infa(self, user, password, tenantid, vmbase, owner):
        k = vmbase.rfind('-')
        virtual_machine_name = vmbase[:k] + "-infa-" + vmbase[k + 1:]
        log.info(virtual_machine_name)
        subscriptionId = '950a5f1a-97b6-4c9c-b79b-e32d951b5e66'
        resourceGroupName = 'rg-cdw-workshops-201904'
        virtualNetworkName = 'vnet-cdw-workshops-201904'
        snapshotName_os = 'cdwinfa_master_os'
        snapshotName_data = 'cdwinfa_master_data'
        compute_client = self.get_compute_client(subscriptionId)

        # subprocess.check_output(["az login --service-principal -u {0} -p {1} --tenant {2}".format(user, password, tenantid)], shell=True)
        osDiskName = virtual_machine_name + '_os'
        DiskName_data = virtual_machine_name + '_data'
        tags = "APPLICATIONENV=PROD APPLICATIONROLE=APPSVR BUSINESSUNIT=NA-Presales OWNEREMAIL=" + owner + " RUNNINGSCHEDULE=00:03:20:00:1-7 NAME=" + virtual_machine_name + " machine__environment_group=" + vmbase
        storageType = 'Standard_LRS'
        osType = 'linux'
        nicName = virtual_machine_name + "_nic"
        myPublicIP = virtual_machine_name + '_public_ip'
        subprocess.check_output(["az network public-ip create -g {0} -n {1} --allocation-method Static".format(
            resourceGroupName, myPublicIP)], shell=True)
        SubnetId = subprocess.check_output([
                                               "az network vnet show --name {0} --resource-group {1} --query subnets[0].id -o tsv".format(
                                                   virtualNetworkName, resourceGroupName)], shell=True)
        subnet_id = SubnetId.decode("utf-8")
        subnetid2 = subnet_id.replace('\n', '')
        subnet_id2 = "'{0}'".format(subnetid2)
        nsgName = "nsg-cdw-workshops-201904"
        subprocess.check_output([
                                    "az network nic create  --resource-group {0} --name {1} --subnet {2} --network-security-group {3} --public-ip-address {4} -l {5}".format(
                                        resourceGroupName, nicName, subnet_id2, nsgName, myPublicIP, 'westus')],
                                shell=True)
        snapshotId_os = subprocess.check_output(
            ["az snapshot show --name {0} --resource-group {1} --query [id] -o tsv".format(
                snapshotName_os, resourceGroupName)], shell=True)
        s3 = snapshotId_os.decode("utf-8")
        snapshotId_data = subprocess.check_output([
            "az snapshot show --name {0} --resource-group {1} --query [id] -o tsv".format(
                snapshotName_data, resourceGroupName)], shell=True)
        l3 = snapshotId_data.decode("utf-8")
        compute_client.disks.create_or_update(resourceGroupName, osDiskName, {
            'location': 'westus',
            'storage_profile': {
                'os_disk': {
                    'os_type': 'windows'
                }
            },
            'sku': {
                'name': storageType,

            },
            'creation_data': {
                'create_option': 'Copy',
                'source_resource_id': s3
            }
        })
        compute_client.disks.create_or_update(resourceGroupName, DiskName_data, {
            'location': 'westus',
            'storage_profile': {
                'os_disk': {
                    'os_type': 'Linux'
                }
            },
            'sku': {
                'name': storageType,

            },
            'creation_data': {
                'create_option': 'Copy',
                'source_resource_id': l3
            }
        })
        virtualMachineSize = 'Standard_D4_v2'
        result = subprocess.check_output([
                                             "az vm create --name {0}  --resource-group {1} --attach-os-disk {2} --os-type {3} --nics {4} --attach-data-disks {5} --size {6} --tags {7}".format(
                                                 virtual_machine_name,
                                                 resourceGroupName, osDiskName, osType, nicName, DiskName_data,
                                                 virtualMachineSize,
                                                 tags)], shell=True)
        result = result.decode("utf-8")
        result_split = result.split(',')[1]
        result_dict = result_split.split(":")
        instance_id = result_dict[1]
        return instance_id

    def launch_infa104(self, user, password, tenantid, vmbase, owner):

        k = vmbase.rfind('-')
        virtual_machine_name = vmbase[:k] + "-infa-" + vmbase[k + 1:]
        log.info(virtual_machine_name)
        subscriptionId = '950a5f1a-97b6-4c9c-b79b-e32d951b5e66'
        compute_client = self.get_compute_client(subscriptionId)
        # subprocess.check_output("az account set --subscription {0}".format(subscriptionId),shell=True)
        resourceGroupName = 'rg-cdw-workshops-201904'
        virtualNetworkName = 'vnet-cdw-workshops-201904'
        nsgName = "nsg-cdw-workshops-201904"
        snapshotName_os = 'cdw-104-student-master-disk'
        snapshotName_data = ''
        storageType = 'Standard_LRS'
        osType = 'linux'
        ssh_key = '/ops-web/data/keyPresalesNA_Prod_Demo.pem'
        ImageName = "CDW-Master-Azure-10.4-Linux_image_2020-04-07-1530"
        ImageId = "/subscriptions/950a5f1a-97b6-4c9c-b79b-e32d951b5e66/resourceGroups/rg-cdw-workshops-201904/providers/Microsoft.Compute/images/CDW-Master-Azure-10.4-Linux_image_2020-04-07-1530"
        virtualMachineSize = 'Standard_B12ms'

        tags = {
            'APPLICATIONENV' : 'PROD',
            'APPLICATIONROLE' : 'APPSVR',
            'BUSINESSUNIT' : 'NA-Presales',
            'OWNEREMAIL': owner,
            'RUNNINGSCHEDULE' : '00:06:20:00:1-5',
            'NAME' : virtual_machine_name

        }

        osDiskName = virtual_machine_name + "_os"
        DiskName_data = virtual_machine_name + "_data"
        nicName = virtual_machine_name + "_nic"
        myPublicIP = virtual_machine_name +"_public_ip"

        network_client = azure.mgmt.network.NetworkManagementClient(
            credentials=self.credentials, subscription_id=subscriptionId
        )

        def create_publicip(network_client):
            public_ip_params = {
                'location' : 'westus',
                'public_ip_allocation_method': 'Static'
            }
            creation_result = network_client.public_ip_addresses.create_or_update(
                resourceGroupName,
                myPublicIP,
                public_ip_params,
            )
            return creation_result.result()
        publicip=create_publicip(network_client)

        responsesubnet=network_client.virtual_networks.get(resourceGroupName,virtualNetworkName)
        SubnetId = responsesubnet.subnets[0].id
        SubnetName = responsesubnet.subnets[0].name
        network_security_group = network_client.network_security_groups.get(resourceGroupName,nsgName)
        nsgId = network_security_group.id
        log.info(nsgId)



        log.info(publicip.id)
        publicipid=publicip.id

        params = {'location': 'westus',
                  'ip_configurations': [{
                      'name':nicName,

                      'public_ip_address':
                          {'id': publicipid },
                      'subnet': {
                          'id': SubnetId
                      }

                  }],
                  'network_security_group' : { 'id' : nsgId }


                  }

        network_client.network_interfaces.create_or_update(resourceGroupName,nicName,params)
        snapshotId_os = compute_client.snapshots.get(resourceGroupName,snapshotName_os).id
        log.info(snapshotId_os)
        result = compute_client.disks.create_or_update(resourceGroupName, osDiskName, {
            'location': 'westus',
            'storage_profile': {
                'os_disk': {
                    'os_type': osType
                }
            },
            'sku': {
                'name': storageType,

            },
            'creation_data': {
                'create_option': 'Copy',
                'source_resource_id': snapshotId_os
            }
        })
        log.info(result)

        if snapshotName_data!= "":
            snapshotId_data = compute_client.snapshots.get(resourceGroupName,snapshotName_data).id
            result2 = compute_client.disks.create_or_update(resourceGroupName, DiskName_data, {
                'location': 'westus',
                'storage_profile': {
                    'os_disk': {
                        'os_type': osType
                    }
                },
                'sku': {
                    'name': storageType,

                },
                'creation_data': {
                    'create_option': 'Copy',
                    'source_resource_id': snapshotId_data
                }
            })
            log.info(result2)
        nicId = network_client.network_interfaces.get(resourceGroupName,nicName).id
        log.info(nicId)
        vm_parameters = {
            'location':'westus',
            'hardware_profile': {
                'vm_size': virtualMachineSize
            },

            'network_profile': {
                'network_interfaces': [{
                    'id': nicId,
                }]
            },
            'tags' : tags,
            "osProfile": {
                "adminUsername": "az-user",
                "computerName": "myVM",
                "adminPassword": "Infa@az@12346",

                "linuxConfiguration": {
                    "ssh": {
                        "publicKeys": [
                            {
                                "path": ssh_key,
                            }
                        ]
                    },
                    "disablePasswordAuthentication": 'false'
                }
            },
            'storage_profile': {
                'image_reference': {
                    'id': ImageId
                }
            },
                        }
        compute_client.virtual_machines.create_or_update(resourceGroupName,virtual_machine_name,vm_parameters)


def delete_machine(az: AZClient, machine_id: str):
    """Delete a virtual machine in Azure.

    This will delete the virtual machine as well as any disks that were attached to the virtual machine; any network
    interfaces attached to the virtual machine; and any public IP addresses associated with network interfaces that were
    attached to the virtual machine.

    This function takes too long to run while handling a web request, so be sure to run it using the scheduler."""

    tokens = machine_id.split('/')
    subscription_id = tokens[2]
    resource_group_name = tokens[4]
    vm_name = tokens[8]

    compute_client = azure.mgmt.compute.ComputeManagementClient(az.credentials, subscription_id)
    network_client = azure.mgmt.network.NetworkManagementClient(az.credentials, subscription_id)
    vm = compute_client.virtual_machines.get(resource_group_name, vm_name)

    # collect the names for all disks attached to the machine
    disks_to_delete = [vm.storage_profile.os_disk.name]
    disks_to_delete.extend([d.name for d in vm.storage_profile.data_disks])

    # collect the resource ids of all network interfaces attached to the machine
    network_interfaces_to_delete = [n.id for n in vm.network_profile.network_interfaces]

    # delete the machine
    log.debug(f'Delete machine: {machine_id}')
    vm_delete_op = compute_client.virtual_machines.delete(resource_group_name, vm_name)
    vm_delete_op.wait()

    # delete the disks
    for disk in disks_to_delete:
        log.debug(f'Delete disk: {disk}')
        compute_client.disks.delete(resource_group_name, disk)

    # delete the network interfaces
    public_ip_addresses_to_delete = []
    for interface_id in network_interfaces_to_delete:
        interface_tokens = interface_id.split('/')
        interface_resource_group_name = interface_tokens[4]
        interface_name = interface_tokens[8]
        interface = network_client.network_interfaces.get(interface_resource_group_name, interface_name)
        for ip_configuration in interface.ip_configurations:
            if ip_configuration.public_ip_address is not None:
                public_ip_addresses_to_delete.append(ip_configuration.public_ip_address.id)
        log.debug(f'Delete network interface: {interface_id}')
        network_client.network_interfaces.delete(interface_resource_group_name, interface_name)

    # delete the public ip addresses
    for public_ip_address_id in public_ip_addresses_to_delete:
        ip_tokens = public_ip_address_id.split('/')
        ip_resource_group_name = ip_tokens[4]
        ip_name = ip_tokens[8]
        log.debug(f'Delete public IP address: {public_ip_address_id}')
        network_client.public_ip_addresses.delete(ip_resource_group_name, ip_name)

    compute_client.close()
    network_client.close()
