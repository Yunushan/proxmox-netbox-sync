#!/usr/bin/env python3
import os
import logging
from typing import Dict, Optional, List, Tuple

import requests
from proxmoxer import ProxmoxAPI
import pynetbox


LOG = logging.getLogger("pve_to_netbox")


# ---------------------------------------------------------------------------
# Helpers for environment variables
# ---------------------------------------------------------------------------

def env(name: str, default: Optional[str] = None, required: bool = False) -> Optional[str]:
    """
    Read an environment variable with optional default / required flag.
    """
    value = os.environ.get(name, default)
    if required and not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------

def connect_proxmox() -> ProxmoxAPI:
    host = env("PVE_HOST", required=True)             # hostname / IP of a node
    user = env("PVE_USER", required=True)             # e.g. netsync@pve
    token_name = env("PVE_TOKEN_NAME", required=True) # token ID
    token_value = env("PVE_TOKEN_VALUE", required=True)
    verify_ssl = env("PVE_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

    LOG.info("Connecting to Proxmox at %s as %s", host, user)

    proxmox = ProxmoxAPI(
        host,
        user=user,
        token_name=token_name,
        token_value=token_value,
        verify_ssl=verify_ssl,
        service="PVE",
    )
    return proxmox


def connect_netbox():
    url = env("NB_URL", required=True)
    token = env("NB_TOKEN", required=True)
    verify_ssl = env("NB_VERIFY_SSL", "true").lower() in ("1", "true", "yes")

    LOG.info("Connecting to NetBox at %s (verify_ssl=%s)", url, verify_ssl)

    # Custom session so we can toggle SSL verification (self-signed etc.)
    session = requests.Session()
    session.verify = verify_ssl

    nb = pynetbox.api(url=url, token=token)
    nb.http_session = session
    return nb


# ---------------------------------------------------------------------------
# NetBox lookups
# ---------------------------------------------------------------------------

def get_nb_cluster(nb):
    cluster_slug = env("NB_CLUSTER_SLUG", required=True)
    cluster = nb.virtualization.clusters.get(slug=cluster_slug)
    if not cluster:
        raise SystemExit(f"NetBox cluster with slug '{cluster_slug}' not found")
    return cluster


def get_nb_site(nb):
    site_slug = env("NB_SITE_SLUG")
    if not site_slug:
        return None
    site = nb.dcim.sites.get(slug=site_slug)
    if not site:
        raise SystemExit(f"NetBox site with slug '{site_slug}' not found")
    return site


def get_nb_device_role(nb):
    role_slug = env("NB_DEVICE_ROLE_SLUG")
    if not role_slug:
        return None
    role = nb.dcim.device_roles.get(slug=role_slug)
    if not role:
        raise SystemExit(f"NetBox device role with slug '{role_slug}' not found")
    return role


def get_nb_device_type(nb):
    dtype_slug = env("NB_DEVICE_TYPE_SLUG")
    if not dtype_slug:
        return None
    dtype = nb.dcim.device_types.get(slug=dtype_slug)
    if not dtype:
        raise SystemExit(f"NetBox device type with slug '{dtype_slug}' not found")
    return dtype


# ---------------------------------------------------------------------------
# Utility conversions
# ---------------------------------------------------------------------------

def bytes_to_mb(value: int) -> int:
    return int(round(value / (1024 * 1024))) if value is not None else 0


def bytes_to_gb(value: int) -> int:
    return int(round(value / (1024 * 1024 * 1024))) if value is not None else 0


def map_vm_status(pve_status: str) -> str:
    """
    Map Proxmox VM status -> NetBox VM status slug.
    """
    pve_status = (pve_status or "").lower()
    if pve_status in ("running", "online"):
        return "active"
    if pve_status in ("stopped", "stopping", "shutdown"):
        return "offline"
    # Everything else (paused, suspended, etc.)
    return "active"


def map_node_status(pve_status: str) -> str:
    pve_status = (pve_status or "").lower()
    return "active" if pve_status == "online" else "offline"


# ---------------------------------------------------------------------------
# VLAN + interface helpers
# ---------------------------------------------------------------------------

def get_or_create_vlan(nb, vid: int, site) -> object:
    """
    Get or create a VLAN with the given VID.

    We optionally bind the VLAN to the given site (if not None).
    """
    if vid is None:
        return None

    query = {"vid": vid}
    if site:
        query["site_id"] = site.id

    vlan = nb.ipam.vlans.get(**query)
    if vlan:
        return vlan

    vlan_name = f"VLAN{vid}"
    LOG.info("Creating VLAN %s (VID=%s)", vlan_name, vid)
    data = {
        "name": vlan_name,
        "vid": vid,
        "status": "active",
    }
    if site:
        data["site"] = site.id
    vlan = nb.ipam.vlans.create(data)
    return vlan


def parse_vm_nic_config(net_value: str) -> Dict[str, Optional[object]]:
    """
    Parse a Proxmox 'net0' style string, e.g.:

        virtio=BC:24:11:44:E6:98,bridge=vmbr0,tag=500

    Returns dict with keys: name, mac, bridge, vlan.
    """
    if not net_value:
        return {"name": "net0", "mac": None, "bridge": None, "vlan": None}

    mac = None
    bridge = None
    vlan = None

    for part in net_value.split(","):
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        key = key.strip()
        val = val.strip()
        if key in ("virtio", "e1000", "rtl8139", "vmxnet3"):
            mac = val.upper()
        elif key == "bridge":
            bridge = val
        elif key == "tag":
            try:
                vlan = int(val)
            except ValueError:
                pass

    return {"name": "net0", "mac": mac, "bridge": bridge, "vlan": vlan}


def fetch_guest_agent_interfaces(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
) -> List[dict]:
    """
    Call qemu-guest-agent network-get-interfaces and return raw 'result' list.
    """
    if pve_type != "qemu":
        return []

    try:
        result = proxmox.nodes(node_name).qemu(vmid).agent("network-get-interfaces").get()
    except Exception as exc:
        LOG.debug("No guest-agent data for vmid=%s on %s: %s", vmid, node_name, exc)
        return []

    return result.get("result", [])


def get_guest_interface_name(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
    nic_mac: Optional[str],
) -> Optional[str]:
    """
    Use guest agent to find the OS-level interface name (e.g. enp6s18) that
    corresponds to our NIC MAC. Fallback: first non-lo interface with an IP.
    """
    interfaces = fetch_guest_agent_interfaces(proxmox, node_name, vmid, pve_type)
    if not interfaces:
        return None

    mac_norm = nic_mac.upper() if nic_mac else None
    fallback = None

    for iface in interfaces:
        name = iface.get("name")
        hw = iface.get("hardware-address")
        if not name or name == "lo":
            continue

        # Prefer exact MAC match
        if hw and mac_norm and hw.upper() == mac_norm:
            return name

        # Otherwise remember first non-lo as fallback
        if not fallback:
            fallback = name

    return fallback


def fetch_guest_ips(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
) -> List[Tuple[str, int, int]]:
    """
    Use qemu-guest-agent to fetch IP addresses from the guest.

    Returns list of tuples: (ip, prefix, family) where family is 4 or 6.
    Only implemented for QEMU guests; LXC returns [] for now.
    """
    interfaces = fetch_guest_agent_interfaces(proxmox, node_name, vmid, pve_type)
    if not interfaces:
        return []

    ips: List[Tuple[str, int, int]] = []

    for iface in interfaces:
        for ip_info in iface.get("ip-addresses", []):
            ip = ip_info.get("ip-address")
            prefix = ip_info.get("prefix")
            if not ip or prefix is None:
                continue

            # Skip loopback
            if ip.startswith("127."):
                continue
            # Skip IPv6 link-local for now
            if ":" in ip and ip.lower().startswith("fe80:"):
                continue

            family = 6 if ":" in ip else 4
            ips.append((ip, int(prefix), family))

    return ips


# ---------------------------------------------------------------------------
# Sync nodes -> NetBox Devices
# ---------------------------------------------------------------------------

def ensure_node_devices(
    nb,
    proxmox: ProxmoxAPI,
    site,
    role,
    dtype,
    cluster,
) -> Dict[str, Optional[object]]:
    """
    Ensure each Proxmox node exists as a Device in NetBox.

    The device is also attached to the given virtualization cluster so it
    can be used as a VM host for that cluster.

    Returns dict mapping node_name -> NetBox Device (or None if creation disabled).
    """
    node_devices: Dict[str, Optional[object]] = {}

    nodes = proxmox.nodes.get()
    LOG.info("Found %d Proxmox nodes", len(nodes))

    for node in nodes:
        node_name = node["node"]
        status = node.get("status", "")
        maxmem = bytes_to_gb(node.get("maxmem", 0))
        maxdisk = bytes_to_gb(node.get("maxdisk", 0))
        maxcpu = node.get("maxcpu")

        if not (site and role and dtype):
            LOG.info(
                "Skipping automatic device creation for node %s "
                "(NB_SITE_SLUG / NB_DEVICE_ROLE_SLUG / NB_DEVICE_TYPE_SLUG not fully set)",
                node_name,
            )
            node_devices[node_name] = nb.dcim.devices.get(name=node_name)
            continue

        dev = nb.dcim.devices.get(name=node_name)
        if not dev:
            LOG.info("Creating NetBox device for Proxmox node %s", node_name)
            payload = {
                "name": node_name,
                "status": map_node_status(status),
                "site": site.id,
                # NetBox 4.x: field is 'role', not 'device_role'
                "role": role.id,
                "device_type": dtype.id,
                # Tie device to virtualization cluster (for VM hosting)
                "cluster": cluster.id,
                "comments": (
                    f"Imported from Proxmox node '{node_name}'. "
                    f"maxcpu={maxcpu}, maxmem={maxmem} GB, maxdisk={maxdisk} GB."
                ),
            }
            dev = nb.dcim.devices.create(payload)
        else:
            # Update existing device
            dev.status = map_node_status(status)
            dev.comments = (
                f"Imported from Proxmox node '{node_name}'. "
                f"maxcpu={maxcpu}, maxmem={maxmem} GB, maxdisk={maxdisk} GB."
            )
            if role:
                dev.role = role
            if dtype:
                dev.device_type = dtype
            dev.cluster = cluster
            dev.save()

        node_devices[node_name] = dev

    return node_devices


# ---------------------------------------------------------------------------
# VM interface + IP sync
# ---------------------------------------------------------------------------

def ensure_vm_interface_and_ips(
    nb,
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
    nb_vm,
    site,
):
    """
    Ensure VM has a vminterface with correct MAC/VLAN and assign IP addresses.

    VLANs are auto-created when needed.
    IPs come from qemu-guest-agent for QEMU guests.
    """
    # Get VM interface config (net0) from Proxmox
    config = {}
    try:
        if pve_type == "qemu":
            config = proxmox.nodes(node_name).qemu(vmid).config.get()
        elif pve_type == "lxc":
            config = proxmox.nodes(node_name).lxc(vmid).config.get()
    except Exception as exc:
        LOG.debug("Failed to get config for vmid=%s (%s): %s", vmid, pve_type, exc)

    nic_info = parse_vm_nic_config(config.get("net0", ""))
    mac = nic_info["mac"]
    vlan_vid = nic_info["vlan"]

    # Default logical name from Proxmox (net0), overridden by guest name if available
    iface_name = nic_info["name"] or "net0"
    guest_name = get_guest_interface_name(proxmox, node_name, vmid, pve_type, mac)
    if guest_name:
        iface_name = guest_name

    # Try to find interface by guest name first
    iface = nb.virtualization.interfaces.get(
        name=iface_name,
        virtual_machine_id=nb_vm.id,
    )

    # Migration path: if we previously created "net0", rename it to guest name
    if not iface and iface_name != "net0":
        old_iface = nb.virtualization.interfaces.get(
            name="net0",
            virtual_machine_id=nb_vm.id,
        )
        if old_iface:
            LOG.info(
                "Renaming NetBox VM interface net0 -> %s on VM %s",
                iface_name,
                nb_vm.name,
            )
            old_iface.name = iface_name
            old_iface.save()
            iface = old_iface

    vlan_obj = None
    if vlan_vid is not None:
        vlan_obj = get_or_create_vlan(nb, vlan_vid, site)

    if not iface:
        LOG.info("Creating NetBox VM interface %s on VM %s", iface_name, nb_vm.name)
        payload = {
            "name": iface_name,
            "virtual_machine": nb_vm.id,
            "enabled": True,
        }
        if mac:
            payload["mac_address"] = mac
        if vlan_obj:
            payload["mode"] = "access"
            payload["untagged_vlan"] = vlan_obj.id

        iface = nb.virtualization.interfaces.create(payload)
    else:
        changed = False
        if mac and (iface.mac_address or "").upper() != mac:
            iface.mac_address = mac
            changed = True

        if vlan_obj:
            # Access port with untagged VLAN
            iface.mode = "access"
            iface.untagged_vlan = vlan_obj
            changed = True

        if changed:
            LOG.info("Updating NetBox VM interface %s on VM %s", iface_name, nb_vm.name)
            iface.save()

    # Fetch IPs from guest (QEMU only for now)
    ips = fetch_guest_ips(proxmox, node_name, vmid, pve_type)
    if not ips:
        return

    primary_v4 = None
    primary_v6 = None

    for ip, prefix, family in ips:
        cidr = f"{ip}/{prefix}"
        ip_obj = nb.ipam.ip_addresses.get(address=cidr)

        if not ip_obj:
            LOG.info("Creating IP %s and assigning to %s", cidr, iface_name)
            ip_obj = nb.ipam.ip_addresses.create(
                {
                    "address": cidr,
                    "status": "active",
                    "assigned_object_type": "virtualization.vminterface",
                    "assigned_object_id": iface.id,
                }
            )
        else:
            # If it already exists, only touch it if it's already attached to this iface.
            ao_type = getattr(ip_obj, "assigned_object_type", None)
            ao_id = getattr(ip_obj, "assigned_object_id", None)

            if ao_type == "virtualization.vminterface" and ao_id == iface.id:
                # Already attached correctly; nothing to change.
                pass
            else:
                # It belongs to someone else (maybe primary IP there). Do not reassign.
                LOG.warning(
                    "IP %s already assigned to %s (id=%s); skipping reassignment to %s",
                    cidr,
                    ao_type,
                    ao_id,
                    iface_name,
                )
                # Do not consider this as primary for this VM either.
                continue

        # Only reach here when IP is attached to this iface
        if family == 4 and primary_v4 is None:
            primary_v4 = ip_obj
        elif family == 6 and primary_v6 is None:
            primary_v6 = ip_obj

    # Set primary IPs on the VM
    need_save = False
    if primary_v4:
        nb_vm.primary_ip4 = primary_v4
        need_save = True
    if primary_v6:
        nb_vm.primary_ip6 = primary_v6
        need_save = True
    if need_save:
        nb_vm.save()


# ---------------------------------------------------------------------------
# Sync VMs -> NetBox Virtual Machines (per-node enumeration)
# ---------------------------------------------------------------------------

def sync_vms(
    nb,
    proxmox: ProxmoxAPI,
    cluster,
    node_devices: Dict[str, Optional[object]],
    site,
):
    """
    Sync all Proxmox VMs (QEMU + LXC) into NetBox virtualization.virtual_machines.

    We enumerate VMs per node:
      - /nodes/{node}/qemu
      - /nodes/{node}/lxc
    """
    nodes = proxmox.nodes.get()
    total_vms = 0

    for node in nodes:
        node_name = node["node"]
        host_device = node_devices.get(node_name)

        # ----- QEMU guests -----
        try:
            qemus = proxmox.nodes(node_name).qemu.get()
        except Exception as exc:
            LOG.error("Failed to query QEMU VMs on node %s: %s", node_name, exc)
            qemus = []

        # ----- LXC containers -----
        try:
            lxcs = proxmox.nodes(node_name).lxc.get()
        except Exception as exc:
            LOG.error("Failed to query LXC containers on node %s: %s", node_name, exc)
            lxcs = []

        LOG.info(
            "Node %s: found %d QEMU VMs and %d LXC containers",
            node_name, len(qemus), len(lxcs)
        )

        for vm in qemus:
            total_vms += 1
            sync_single_vm(
                nb=nb,
                proxmox=proxmox,
                vm=vm,
                node_name=node_name,
                host_device=host_device,
                cluster=cluster,
                pve_type="qemu",
                site=site,
            )

        for vm in lxcs:
            total_vms += 1
            sync_single_vm(
                nb=nb,
                proxmox=proxmox,
                vm=vm,
                node_name=node_name,
                host_device=host_device,
                cluster=cluster,
                pve_type="lxc",
                site=site,
            )

    LOG.info("Total Proxmox guests synced (QEMU + LXC): %d", total_vms)


def sync_single_vm(
    nb,
    proxmox: ProxmoxAPI,
    vm: dict,
    node_name: str,
    host_device,
    cluster,
    pve_type: str,
    site,
):
    """
    Create or update one NetBox Virtual Machine from a Proxmox VM/LXC dict
    and sync its interface + IPs.
    """
    vmid = vm["vmid"]
    name = vm.get("name") or f"vm-{vmid}"
    pve_status = vm.get("status", "stopped")

    # Different Proxmox endpoints expose CPU fields slightly differently
    vcpus = (
        vm.get("cores")
        or vm.get("cpus")
        or vm.get("maxcpu")
        or 1
    )
    memory_mb = bytes_to_mb(vm.get("maxmem", 0))
    disk_mb = bytes_to_mb(vm.get("maxdisk", 0))  # NetBox expects MB

    status_slug = map_vm_status(pve_status)

    LOG.info(
        "Syncing VM %-30s (vmid=%s, node=%s, type=%s, status=%s)",
        name,
        vmid,
        node_name,
        pve_type,
        pve_status,
    )

    comments = (
        f"Synced from Proxmox.\n"
        f"vmid={vmid}, node={node_name}, type={pve_type}, "
        f"status={pve_status}, vcpus={vcpus}, maxmem={memory_mb} MB, disk={disk_mb} MB."
    )

    nb_vm = nb.virtualization.virtual_machines.get(name=name, cluster_id=cluster.id)
    if not nb_vm:
        LOG.info("Creating NetBox VM %s", name)
        create_data = {
            "name": name,
            "cluster": cluster.id,
            "status": status_slug,
            "vcpus": vcpus,
            "memory": memory_mb,
            "disk": disk_mb,
            "comments": comments,
        }
        if site:
            create_data["site"] = site.id
        if host_device:
            create_data["device"] = host_device.id

        nb_vm = nb.virtualization.virtual_machines.create(create_data)
    else:
        LOG.info("Updating NetBox VM %s", name)
        nb_vm.status = status_slug
        nb_vm.vcpus = vcpus
        nb_vm.memory = memory_mb
        nb_vm.disk = disk_mb
        nb_vm.comments = comments
        nb_vm.cluster = cluster
        if site:
            nb_vm.site = site
        if host_device:
            nb_vm.device = host_device
        nb_vm.save()

    # Interface + IP handling
    ensure_vm_interface_and_ips(
        nb=nb,
        proxmox=proxmox,
        node_name=node_name,
        vmid=vmid,
        pve_type=pve_type,
        nb_vm=nb_vm,
        site=site,
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    proxmox = connect_proxmox()
    nb = connect_netbox()

    cluster = get_nb_cluster(nb)
    site = get_nb_site(nb)
    role = get_nb_device_role(nb)
    dtype = get_nb_device_type(nb)

    node_devices = ensure_node_devices(nb, proxmox, site, role, dtype, cluster)
    sync_vms(nb, proxmox, cluster, node_devices, site)


if __name__ == "__main__":
    main()

