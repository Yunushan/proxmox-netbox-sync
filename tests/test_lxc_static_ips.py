import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pve_to_netbox as sync


class LxcStaticIpSyncTests(unittest.TestCase):
    def setUp(self):
        self.nb = Mock()
        interfaces = {"net0": SimpleNamespace(id=11), "net1": SimpleNamespace(id=12)}
        self.nb.virtualization.interfaces.get.side_effect = (
            lambda name, virtual_machine_id: interfaces[name]
        )
        self.addresses = self.nb.ipam.ip_addresses
        self.addresses.filter.return_value = []
        self.addresses.create.side_effect = lambda fields: SimpleNamespace(**fields)
        self.vm = Mock(id=21)
        self.vm.name = "test-container"
        self.proxmox = Mock()

    def sync_config(self, config):
        with patch.object(sync, "ensure_netbox_prefix") as prefixes:
            sync.ensure_vm_interface_and_ips(
                self.nb, self.proxmox, "node", 101, "lxc", self.vm, None, config=config
            )
        self.assertEqual(self.proxmox.mock_calls, [])
        return prefixes

    def test_local_addresses_do_not_become_prefixes_or_primary_ips(self):
        prefixes = self.sync_config({
            "net0": "name=eth0,ip=127.0.0.2/8,ip6=fe80::1/64",
            "net1": "name=eth1,ip=dhcp,ip6=::1/128",
        })
        prefixes.assert_not_called()
        self.addresses.filter.assert_not_called()
        self.addresses.create.assert_not_called()
        self.vm.save.assert_not_called()

    def test_static_addresses_stay_on_their_configured_interfaces(self):
        self.sync_config({
            "net0": "name=eth0,ip=192.0.2.3/24,ip6=auto",
            "net1": "name=eth1,ip=dhcp,ip6=2001:db8::3/64",
        })
        assigned = [c.args[0] for c in self.addresses.create.call_args_list]
        self.assertEqual(
            [(a["address"], a["assigned_object_id"]) for a in assigned],
            [("192.0.2.3/24", 11), ("2001:db8::3/64", 12)],
        )
        self.assertEqual(self.vm.primary_ip4.address, "192.0.2.3/24")
        self.assertEqual(self.vm.primary_ip6.address, "2001:db8::3/64")
