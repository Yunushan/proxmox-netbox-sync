# Proxmox to NetBox Sync

Sync Proxmox VE nodes, VMs, interfaces, VLANs, prefixes, and IP addresses into NetBox with a single script. Guest IPs are pulled via the QEMU guest agent when available, VLANs are auto-created (optionally scoped to a site), and guest CIDRs are created as NetBox prefixes when missing. Optional default IPAM roles can be auto-created and applied to synced VLANs and prefixes. Proxmox VM tags are mirrored to NetBox tags, and VM pools can be stored in a NetBox custom field. Optionally, the script can also read Forti public IPs (IPv4/IPv6) and sync them into a NetBox device interface.

## Requirements

- Python 3.9+
- Proxmox API token with permission to read nodes/VMs (create a dedicated `@pve` user + API token)
- NetBox API token
- Optional Forti API access (token or username/password) for public IP sync
- `qemu-guest-agent` installed in VMs to collect IPs (recommended)
- Python packages: `proxmoxer`, `pynetbox`, `requests`

## Install

```bash
git clone https://github.com/Yunushan/proxmox-netbox-sync.git
cd proxmox-netbox-sync
python3 -m venv venv
source venv/bin/activate
pip install proxmoxer pynetbox requests
```

## Configure

1. Copy the sample env file and fill in your values:
   ```bash
   cp netbox_pve_env.example netbox_pve_env.sh
   ```
2. Required variables:
   - `PVE_HOST`, `PVE_USER`, `PVE_TOKEN_NAME`, `PVE_TOKEN_VALUE`, `PVE_VERIFY_SSL`
   - Optional Proxmox API timeout: `PVE_API_TIMEOUT` (seconds, defaults to `60`)
   - `NB_URL`, `NB_TOKEN`, `NB_VERIFY_SSL`
   - `NB_CLUSTER_SLUG` (target virtualization cluster)
  - Optional device metadata: `NB_SITE_SLUG`, `NB_DEVICE_ROLE_SLUG`, `NB_DEVICE_TYPE_SLUG`
  - Optional prefix sync: `PVE_NB_PREFIX_SYNC` (defaults to `true`). Set `false` to disable NetBox prefix creation from guest CIDRs. Synthetic `/32` or `/128` fallbacks are not created as prefixes.
  - Optional IPAM role sync: `NB_PREFIX_ROLE_SLUG`, `NB_VLAN_ROLE_SLUG`. When set, the script auto-creates the role if needed and applies it to synced prefixes/VLANs on create and update.
  - Optional VM pool custom field key: `NB_VM_POOL_CF` (defaults to `pool`; auto-created and auto-attached to VMs if missing, requires NetBox custom field write permissions)
  - Optional VM gateway custom field keys: `NB_VM_GW4_CF` (defaults to `gateway4`), `NB_VM_GW6_CF` (defaults to `gateway6`). When enabled, the script stores gateway IPs from all LXC `netX` or QEMU cloud-init `ipconfigX` values; multiple gateways are stored as a comma-separated list. Set empty to disable. Requires NetBox custom field write permissions.
  - Optional VM metadata custom field keys (auto-created/attached if missing; set empty to disable; requires NetBox custom field write permissions). If you have duplicate fields, you can set a comma-separated list of keys to populate them all.
    - `NB_VM_VMID_CF` (defaults to `vmid`)
    - `NB_VM_SOCKETS_CF` (defaults to `sockets`)
    - `NB_VM_CORES_CF` (defaults to `cores`)
    - `NB_VM_CPU_TYPE_CF` (defaults to `cpu_type`)
    - `NB_VM_QEMU_CPU_TYPE_CF` (defaults to `qemu_cpu_type`)
    - `NB_VM_OS_TYPE_CF` (defaults to `os_type`; QEMU uses guest-agent "pretty-name" when available, otherwise Proxmox ostype)
    - `NB_VM_DESCRIPTION_CF` (defaults to `pve_description`)
    - `NB_VM_BOOT_DISK_CF` (defaults to `boot_disk`)
    - `NB_VM_BOOT_DISK_FORMAT_CF` (defaults to `boot_disk_format`)
    - `NB_VM_BOOT_DISK_STORAGE_CF` (defaults to `boot_disk_storage`)
    - `NB_VM_GUEST_AGENT_CF` (defaults to `guest_agent_status`, uses enabled/disabled from Proxmox config)
    - `NB_VM_MEMORY_MB_CF` (defaults to `memory_mb`)
    - `NB_VM_NODE_CF` (defaults to `vm_node`)
    - `NB_VM_STATUS_CF` (defaults to `vm_status`)
    - `NB_VM_TAGS_CF` (defaults to `vm_tags`)
    - `NB_VM_CPU_SOCKETS_CF` (defaults to `cpu_sockets`)
    - `NB_VM_QEMU_CORES_PER_SOCKET_CF` (defaults to `qemu_cores_per_socket`)
    - `NB_VM_QEMU_NUMA_CF` (defaults to `qemu_numa`, QEMU-only)
    - `NB_VM_QEMU_BIOS_CF` (defaults to `qemu_bios`, QEMU-only)
    - `NB_VM_QEMU_BOOT_ORDER_CF` (defaults to `qemu_boot_order`, QEMU-only)
    - `NB_VM_QEMU_MACHINE_CF` (defaults to `qemu_machine`, QEMU-only)
    - `NB_VM_LAST_SYNC_CF` (defaults to `last_sync`, timestamp)
    - `NB_VM_LAST_SYNC_TZ` (defaults to `+03:00`; set `local` to use system time)
  - Optional sync mode: `PVE_NB_SYNC_MODE` (`1`/`safe` = no deletions; `2`/`full` = delete NetBox VMs missing in Proxmox). If unset, the script prompts on startup (Enter defaults to safe).
  - Optional guest gateway fallback: `PVE_GUEST_GW_FALLBACK` (defaults to `true`). When enabled, QEMU guests with `qemu-guest-agent` will be queried for default routes via guest exec to populate gateways set inside the VM OS.
  - Optional env file auto-update path: `PVE_ENV_FILE` (defaults to `netbox_pve_env.sh`). If `PVE_GUEST_GW_FALLBACK` is missing and the env file exists, the script appends it.
  - Optional IP block report:
    - `PVE_NB_IP_BLOCK_REPORT` (optional bool; defaults to `false`). Set `true` to log prefix utilization after sync.
    - `PVE_NB_IP_BLOCK_REPORT_PATH` (optional file path). If set, writes the same prefix report to CSV.
    - Report scope follows `NB_SITE_SLUG` when set; otherwise all NetBox prefixes are included.
  - Optional node iLO/OOB sync:
    - `PVE_NODE_ILO_SYNC` (optional bool; defaults to enabled, set `false` to disable)
    - `PVE_NODE_ILO_MAP` (e.g. `node-a=192.0.2.10:443,node-b=198.51.100.20:443`)
    - `PVE_NODE_ILO_TEMPLATE` (e.g. `mgmt-{node}.example.net:443`)
    - `PVE_NODE_ILO_PREFIX` / `PVE_NODE_ILO_SUFFIX` (fallback host pattern, e.g. `mgmt-` + `{node}` + `.example.net:443`)
    - Optional NPM auto-discovery for `ilo-*` hostnames (reads proxy destinations):
      - `PVE_NODE_ILO_NPM_URL` (NPM base URL)
      - `PVE_NODE_ILO_NPM_TOKEN` (preferred) or `PVE_NODE_ILO_NPM_USERNAME` + `PVE_NODE_ILO_NPM_PASSWORD`
      - `PVE_NODE_ILO_NPM_VERIFY_SSL` (defaults to `false`)
      - `PVE_NODE_ILO_NPM_PREFIX` (defaults to `ilo-`)
    - `PVE_NODE_ILO_DOMAIN_SUFFIXES` (optional comma/space list of extra DNS suffixes for auto `ilo-{node}` lookup; e.g. `example.com example.net example.org`)
    - `PVE_NODE_ILO_INTERFACE` (defaults to `iLO`)
    - `PVE_NODE_ILO_SET_PRIMARY` (defaults to `true`; updates device primary IP from iLO IP)
  - Optional Forti public IP sync:
    - `PVE_FORTI_PUBLIC_IP_SYNC` (optional bool; defaults to `false`)
    - `PVE_FORTI_URL` (Forti base URL)
    - Authentication options:
      - REST API token mode: `PVE_FORTI_API_TOKEN` (recommended for `api-user` / REST API admin, and required when FortiOS rejects session API login)
      - Session login mode: `PVE_FORTI_USERNAME` + `PVE_FORTI_PASSWORD` (works on FortiOS builds that still allow `/logincheck`-based API sessions)
      - If both are set, token auth is tried first and session login is used as fallback on auth denial.
    - `PVE_FORTI_VERIFY_SSL` (defaults to `false`)
    - `PVE_FORTI_VDOM` (defaults to `root`)
    - `PVE_FORTI_TIMEOUT` (seconds, defaults to `20`)
    - `PVE_FORTI_WAN_INTERFACES` (optional preferred interface order, e.g. `wan1,wan2`)
    - `PVE_FORTI_MAX_RANGE_EXPANSION` (defaults to `2048`; max addresses expanded per VIP/IP pool range object)
    - NetBox target options:
      - `NB_FORTI_DEVICE` (optional NetBox device name or numeric ID; if unset, script tries Forti hostname -> NetBox device name match)
      - `NB_FORTI_INTERFACE` (optional NetBox interface override; defaults to selected Forti interface name)
      - `NB_FORTI_SET_PRIMARY` (defaults to `true`; updates device `primary_ip4`)
      - `NB_FORTI_SET_PRIMARY6` (defaults to `true`; updates device `primary_ip6`)

### Sync modes

- **Safe update** (default / `PVE_NB_SYNC_MODE=1`): Creates/updates VMs, interfaces, prefixes, and IPs. Nothing is removed from NetBox.
- **Full sync** (`PVE_NB_SYNC_MODE=2`): After syncing, deletes NetBox VMs in the target cluster that are not present in Proxmox. Matching is name-based but also vmid-aware (vmid is stored in comments) to avoid deleting renamed VMs/templates.
  - Safety behavior: if VM enumeration fails on any node in a run, deletion is skipped for that run.

## Required API permissions

- **NetBox API token** (user or token-scoped permissions):
  - Virtualization: read/write `clusters`, `virtual-machines`, `interfaces`.
  - IPAM: read/write `ip-addresses`, `vlans`, `prefixes`, `roles`.
  - DCIM: read/write `sites`, `devices`, `interfaces`, `device-roles`, `device-types`.
  - If you prefer read-only sites/roles/types, grant read on those and write on the objects the tool creates/updates (VMs, interfaces, prefixes, IPs, VLANs, devices).

- **Proxmox API user/token** (recommended: dedicated service account with a custom role):
  - Minimum privileges: `VM.Audit`, `VM.Monitor` (to call guest-agent), `VM.Config.Options` (to read NIC config), `Sys.Audit` (to list nodes).
  - If `PVE_GUEST_GW_FALLBACK` is enabled, guest-agent exec must be permitted for the token (same guest-agent access scope).
  - A simple approach: clone `PVEAuditor` and add `VM.Monitor` so guest-agent calls succeed, then assign that role to the token on the relevant nodes (or cluster-wide).

- **Per-node API host selection** (guest exec compatibility on mixed versions):
  - By default, the script derives per-node API hosts from `PVE_HOST` (e.g. `pve1.example.com` -> `pve2.example.com`).
  - Override with `PVE_NODE_HOST_SUFFIX`, `PVE_NODE_HOST_TEMPLATE`, or `PVE_NODE_HOST_MAP` when node names do not resolve via DNS.

- **Node iLO/OOB IP sync**:
  - Enabled by default. The script resolves one iLO/OOB address per Proxmox node, creates/uses a NetBox device interface (default name `iLO`), assigns the IP to that interface, and optionally sets `primary_ip4` / `primary_ip6`.
  - Host resolution order: `PVE_NODE_ILO_MAP` -> NPM `ilo-*` discovery (`PVE_NODE_ILO_NPM_*`) -> `PVE_NODE_ILO_TEMPLATE` -> `PVE_NODE_ILO_PREFIX` + `{node}` + `PVE_NODE_ILO_SUFFIX` -> automatic DNS discovery across multiple domain suffixes (`ilo-{node}.<suffix>` from resolver search domains, `PVE_HOST`/node host settings, and `PVE_NODE_ILO_DOMAIN_SUFFIXES`) -> `ilo-{node}`.
  - Hostnames are DNS-resolved and stored as `/32` (IPv4) or `/128` (IPv6) IP addresses.

- **Forti public IP sync (IPv4/IPv6)**:
  - Enable with `PVE_FORTI_PUBLIC_IP_SYNC=true`.
  - Auth supports both token-based REST API admins and session-based users (for example `super_admin_readonly`).
  - The script queries Forti interfaces, Virtual IPs (`firewall/vip`), and IP pools (`firewall/ippool`, `firewall/ippool6`), then collects globally routable public IPv4/IPv6 addresses.
  - Synced addresses are assigned as `/32` and `/128` to the target NetBox device interface(s), and `primary_ip4` / `primary_ip6` can be updated using the highest-ranked public address in each family.

- **Proxmox guest agent inside VMs**:
  - Install and enable `qemu-guest-agent` so IP discovery works. Without it, VMs are still synced but IPs remain empty.

## Run once (manual)

```bash
source venv/bin/activate
source ./netbox_pve_env.sh
python3 pve_to_netbox.py
```

## Run as a systemd service + timer

`systemd/pve-netbox-sync.service` is a oneshot unit that sources your env file and runs the sync; `systemd/pve-netbox-sync.timer` schedules it (immediately after boot + every 12 hours).

1. Place the project where the service will run, e.g. `/opt/proxmox-netbox-sync`, and create your `netbox_pve_env.sh` there.
2. Adjust `systemd/pve-netbox-sync.service` so `WorkingDirectory` points to that path and `User` is the account that should run the sync. The `ExecStart` line assumes the virtualenv lives inside that directory (`venv/bin/python3`).
3. Install the units:
   ```bash
   sudo cp systemd/pve-netbox-sync.service /etc/systemd/system/
   sudo cp systemd/pve-netbox-sync.timer /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now pve-netbox-sync.timer
   ```
4. To run immediately (outside the timer): `sudo systemctl start pve-netbox-sync.service`
5. Check logs: `sudo journalctl -u pve-netbox-sync -f`

To change the schedule, edit `OnUnitActiveSec` (and `OnBootSec`) in `pve-netbox-sync.timer`, then run `sudo systemctl daemon-reload` and `sudo systemctl restart pve-netbox-sync.timer`.
