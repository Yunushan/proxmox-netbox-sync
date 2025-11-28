# Proxmox → NetBox Sync Tool

This project synchronizes Proxmox VE nodes, VMs, interfaces, VLANs and IP addresses
into NetBox automatically.

## Installation

```bash
git clone https://github.com/Yunushan/proxmox-netbox-sync.git
cd proxmox-netbox-sync
python3 -m venv venv
source venv/bin/activate
pip install proxmoxer pynetbox requests

```
## Configuration 

Copy the example env file:

cp netbox_pve_env.example netbox_pve_env.sh

### Running

source venv/bin/activate
source ./netbox_pve_env.sh
python3 pve_to_netbox.py
