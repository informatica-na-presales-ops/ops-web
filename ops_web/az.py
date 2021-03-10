import logging
import ops_web.config
import ops_web.db

from azure.identity import ClientSecretCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.subscription import SubscriptionClient
from typing import Dict

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
        self.db = ops_web.db.Database(config)
        self.credential = ClientSecretCredential(tenant_id=tenant, client_id=client_id, client_secret=secret)

        self.subscriptions = {}
        with SubscriptionClient(credential=self.credential) as client:
            for sub in client.subscriptions.list():
                self.subscriptions[sub.subscription_id] = sub.display_name

    def get_compute_client(self, subscription_id: str) -> ComputeManagementClient:
        return ComputeManagementClient(credential=self.credential, subscription_id=subscription_id)

    def get_network_client(self, subscription_id: str) -> NetworkManagementClient:
        return NetworkManagementClient(credential=self.credential, subscription_id=subscription_id)

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
                    'owner': image.tags.get('OWNEREMAIL', '').lower(),
                    'public': ops_web.config.as_bool(image.tags.get('image_public', '')),
                    'state': IMAGE_STATE_MAP.get(image.provisioning_state, image.provisioning_state),
                    'created': None,
                    'instanceid': None,
                    'business_unit': image.tags.get('BUSINESSUNIT', ''),
                    'application_env': image.tags.get('APPLICATIONENV', ''),
                    'application_role': image.tags.get('APPLICATIONROLE', ''),
                    'cost': '0'
                }
                yield params
            compute_client.close()

    def get_all_virtual_machines(self):
        for subscription_id in self.subscriptions:

            log.info(f'Getting all virtual machines in subscription {subscription_id}')
            compute_client = self.get_compute_client(subscription_id)

            network_client = self.get_network_client(subscription_id)
            network_interfaces = {nic.id: nic for nic in network_client.network_interfaces.list_all()}
            log.debug(network_interfaces)
            public_ips = {public_ip.id: public_ip for public_ip in network_client.public_ip_addresses.list_all()}
            log.debug(public_ips)

            for vm in compute_client.virtual_machines.list_all():
                log.debug(f'Found a virtual machine: {vm.id}')
                vm_rg = vm.id.split('/')[4]
                if vm.tags is None:
                    vm.tags = {}
                params = {
                    'id': vm.id,
                    'cloud': 'az',
                    'region': vm.location,
                    'environment': vm.tags.get('machine__environment_group'),
                    'name': vm.tags.get('NAME', vm.name),
                    'owner': vm.tags.get('OWNEREMAIL', '').lower(),
                    'contributors': vm.tags.get('CONTRIBUTORS', ''),
                    'private_ip': None,
                    'public_ip': None,
                    'type': vm.hardware_profile.vm_size,
                    'running_schedule': vm.tags.get('RUNNINGSCHEDULE', ''),
                    'state': 'unknown',
                    'state_transition_time': None,
                    'application_env': vm.tags.get('APPLICATIONENV', ''),
                    'application_role': vm.tags.get('APPLICATIONROLE', ''),
                    'business_unit': vm.tags.get('BUSINESSUNIT', ''),
                    'created': None,
                    'dns_names': vm.tags.get('image__dns_names_private', ''),
                    'whitelist': None,
                    'vpc': None,
                    'disable_termination': None
                }

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

                # Find cost of virtual machine and all attached disks and network interfaces
                cost = self.db.get_cost_for_resource(vm.id)
                if vm.storage_profile.os_disk.managed_disk is not None:
                    cost += self.db.get_cost_for_resource(vm.storage_profile.os_disk.managed_disk.id)
                for disk in vm.storage_profile.data_disks:
                    cost += self.db.get_cost_for_resource(disk.managed_disk.id)
                for interface in vm.network_profile.network_interfaces:
                    cost += self.db.get_cost_for_resource(interface.id)
                params['cost'] = cost

                yield params
            compute_client.close()
            network_client.close()

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
        compute_client.virtual_machines.begin_start(resource_group_name, vm_name)
        compute_client.close()

    def stop_machine(self, machine_id: str):
        log.debug(f'Stop machine: {machine_id}')
        tokens = machine_id.split('/')
        subscription_id = tokens[2]
        resource_group_name = tokens[4]
        vm_name = tokens[8]
        compute_client = self.get_compute_client(subscription_id)
        compute_client.virtual_machines.begin_deallocate(resource_group_name, vm_name)
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
            compute_client.virtual_machines.begin_update(resource_group_name, vm_name, vm)
        finally:
            compute_client.close()


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

    compute_client = ComputeManagementClient(az.credential, subscription_id)
    network_client = NetworkManagementClient(az.credential, subscription_id)
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
