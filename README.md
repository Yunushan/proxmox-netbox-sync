# Proxmox to NetBox Sync

Sync Proxmox VE nodes, VMs, interfaces, VLANs, and IP addresses into NetBox with a single script. Guest IPs are pulled via the QEMU guest agent when available, and VLANs are auto-created (optionally scoped to a site).

## Requirements

- Python 3.9+
- Proxmox API token with permission to read nodes/VMs (create a dedicated `@pve` user + API token)
- NetBox API token
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
   - `NB_URL`, `NB_TOKEN`, `NB_VERIFY_SSL`
   - `NB_CLUSTER_SLUG` (target virtualization cluster)
   - Optional device metadata: `NB_SITE_SLUG`, `NB_DEVICE_ROLE_SLUG`, `NB_DEVICE_TYPE_SLUG`
   - Optional sync mode: `PVE_NB_SYNC_MODE` (`1`/`safe` = no deletions; `2`/`full` = delete NetBox VMs missing in Proxmox). If unset, the script prompts on startup (Enter defaults to safe).

### Sync modes

- **Safe update** (default / `PVE_NB_SYNC_MODE=1`): Creates/updates VMs, interfaces, IPs. Nothing is removed from NetBox.
- **Full sync** (`PVE_NB_SYNC_MODE=2`): After syncing, deletes NetBox VMs in the target cluster that are not present in Proxmox. Matching is name-based but also vmid-aware (vmid is stored in comments) to avoid deleting renamed VMs/templates.

## Required API permissions

- **NetBox API token** (user or token-scoped permissions):
  - Virtualization: read/write `clusters`, `virtual-machines`, `interfaces`.
  - IPAM: read/write `ip-addresses`, `vlans`.
  - DCIM: read/write `sites`, `devices`, `device-roles`, `device-types`.
  - If you prefer read-only sites/roles/types, grant read on those and write on the objects the tool creates/updates (VMs, interfaces, IPs, VLANs, devices).

- **Proxmox API user/token** (recommended: dedicated service account with a custom role):
  - Minimum privileges: `VM.Audit`, `VM.Monitor` (to call guest-agent), `VM.Config.Options` (to read NIC config), `Sys.Audit` (to list nodes).
  - A simple approach: clone `PVEAuditor` and add `VM.Monitor` so guest-agent calls succeed, then assign that role to the token on the relevant nodes (or cluster-wide).

- **Proxmox guest agent inside VMs**:
  - Install and enable `qemu-guest-agent` so IP discovery works. Without it, VMs are still synced but IPs remain empty.

## Run once (manual)

```bash
source venv/bin/activate
source ./netbox_pve_env.sh
python3 pve_to_netbox.py
```

## Run as a systemd service + timer

`systemd/pve-netbox-sync.service` is a oneshot unit that sources your env file and runs the sync; `systemd/pve-netbox-sync.timer` schedules it (boot delay + every 5 minutes).

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
