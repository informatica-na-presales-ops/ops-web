import azure.common.credentials
import azure.mgmt.compute
import azure.mgmt.network
import azure.mgmt.subscription
import logging
import msrestazure.azure_exceptions
import ops_web.config

from typing import Dict

log = logging.getLogger(__name__)

IMAGE_STATE_MAP = {
    'Succeeded': 'available'
}

VM_STATE_MAP = {
    'stopped':     'suspended',
    'deallocated': 'stopped',
}


class AZClient:
    def __init__(self, config: ops_web.config.Config):
        self.config = config
        self.credentials = azure.common.credentials.ServicePrincipalCredentials(
            client_id=self.config.az_client_id, secret=self.config.az_client_secret, tenant=self.config.az_tenant_id
        )
        self.subscriptions = {}
        client = azure.mgmt.subscription.SubscriptionClient(self.credentials)
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
                    'image_public':'false',
                    'state': IMAGE_STATE_MAP.get(image.provisioning_state, image.provisioning_state),
                    'created': None,
                    'instanceid': None
                }
                yield params

    def get_all_virtual_machines(self):
        for subscription_id in self.subscriptions:
            log.info(f'Getting all virtual machines in subscription {subscription_id}')
            compute_client = self.get_compute_client(subscription_id)
            network_client = azure.mgmt.network.NetworkManagementClient(
                credentials=self.credentials, subscription_id=subscription_id
            )
            network_interfaces = {nic.id: nic for nic in network_client.network_interfaces.list_all()}
            public_ips = {public_ip.id: public_ip for public_ip in network_client.public_ip_addresses.list_all()}
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
                    'dns_names': vm.tags.get('image__dns_names_private', '')
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

                yield params

    def start_machine(self, machine_id: str):
        log.debug(f'Start machine: {machine_id}')
        tokens = machine_id.split('/')
        subscription_id = tokens[2]
        resource_group_name = tokens[4]
        vm_name = tokens[8]
        compute_client = self.get_compute_client(subscription_id)
        compute_client.virtual_machines.start(resource_group_name, vm_name)

    def stop_machine(self, machine_id: str):
        log.debug(f'Stop machine: {machine_id}')
        tokens = machine_id.split('/')
        subscription_id = tokens[2]
        resource_group_name = tokens[4]
        vm_name = tokens[8]
        compute_client = self.get_compute_client(subscription_id)
        compute_client.virtual_machines.deallocate(resource_group_name, vm_name)

    def update_machine_tags(self, machine_id: str, tags: Dict):
        log.debug(f'Update tags: {machine_id}')
        tokens = machine_id.split('/')
        subscription_id = tokens[2]
        resource_group_name = tokens[4]
        vm_name = tokens[8]
        compute_client = self.get_compute_client(subscription_id)
        vm = compute_client.virtual_machines.get(resource_group_name, vm_name)
        vm.tags.update(tags)
        vm.plan = None
        try:
            compute_client.virtual_machines.update(resource_group_name, vm_name, vm)
        except msrestazure.azure_exceptions.CloudError as e:
            log.critical(e.error)


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
