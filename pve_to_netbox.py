#!/usr/bin/env python3
import os
import logging
import ipaddress
import re
import base64
import binascii
import time
from functools import lru_cache
from urllib.parse import urlsplit
from typing import Dict, Optional, List, Tuple, Set

import requests
from proxmoxer import ProxmoxAPI
import pynetbox
from pynetbox.core.query import RequestError


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


def split_host_port(value: str) -> Tuple[str, Optional[int]]:
    if not value:
        return "", None

    raw = value.strip()
    hostport = raw
    if "://" in raw:
        parts = urlsplit(raw)
        hostport = parts.netloc or parts.path

    host = hostport
    port: Optional[int] = None

    if hostport.startswith("[") and "]" in hostport:
        host = hostport[1:hostport.index("]")]
        remainder = hostport[hostport.index("]") + 1 :]
        if remainder.startswith(":"):
            port_part = remainder[1:]
            if port_part.isdigit():
                port = int(port_part)
    elif hostport.count(":") == 1:
        host_part, port_part = hostport.rsplit(":", 1)
        if port_part.isdigit():
            host = host_part
            port = int(port_part)

    return host, port


def parse_node_host_map(value: Optional[str]) -> Dict[str, Tuple[str, Optional[int]]]:
    mapping: Dict[str, Tuple[str, Optional[int]]] = {}
    if not value:
        return mapping

    for item in value.split(","):
        item = item.strip()
        if not item or "=" not in item:
            continue
        node, host_value = item.split("=", 1)
        node = node.strip()
        host_value = host_value.strip()
        if not node or not host_value:
            continue
        host, port = split_host_port(host_value)
        if host:
            mapping[node] = (host, port)

    return mapping


@lru_cache(maxsize=None)
def resolve_node_host_details(node_name: str) -> Tuple[str, Optional[int]]:
    node_map = parse_node_host_map(env("PVE_NODE_HOST_MAP"))
    if node_name in node_map:
        return node_map[node_name]

    template = env("PVE_NODE_HOST_TEMPLATE")
    if template:
        host_value = template.format(node=node_name)
        host, port = split_host_port(host_value)
        return host, port

    suffix = env("PVE_NODE_HOST_SUFFIX")
    base_host_raw = env("PVE_HOST", "") or ""
    base_host, base_port = split_host_port(base_host_raw)

    if suffix:
        return f"{node_name}{suffix}", base_port

    if base_host and "." in base_host and "." not in node_name:
        base_suffix = base_host[base_host.find(".") :]
        return f"{node_name}{base_suffix}", base_port

    return node_name, base_port


def ensure_env_file_setting(env_file: Optional[str], key: str, value: str) -> None:
    if not env_file:
        return

    try:
        with open(env_file, "r", encoding="utf-8") as handle:
            contents = handle.read()
    except FileNotFoundError:
        return
    except OSError as exc:
        LOG.debug("Failed to read env file %s: %s", env_file, exc)
        return

    pattern = re.compile(rf"^\\s*(export\\s+)?{re.escape(key)}=", re.MULTILINE)
    if pattern.search(contents):
        return

    try:
        with open(env_file, "a", encoding="utf-8") as handle:
            if contents and not contents.endswith("\n"):
                handle.write("\n")
            handle.write(f'export {key}="{value}"\n')
        LOG.info("Added %s to %s", key, env_file)
    except OSError as exc:
        LOG.warning("Failed to update env file %s with %s: %s", env_file, key, exc)


# ---------------------------------------------------------------------------
# Sync mode selection
# ---------------------------------------------------------------------------

SYNC_MODE_ENV = "PVE_NB_SYNC_MODE"
GUEST_GW_FALLBACK_ENV = "PVE_GUEST_GW_FALLBACK"


def parse_sync_mode(value: str) -> str:
    """
    Normalize a sync mode value (interactive input or env var).
    Returns 'safe' or 'full'.
    """
    choice = (value or "").strip().lower()
    if choice in ("1", "safe", "safe-update", "safe_update", "safeupdate"):
        return "safe"
    if choice in ("2", "full", "full-sync", "full_sync", "fullsync", "delete"):
        return "full"
    raise ValueError(f"Invalid sync mode: {value}")


def select_sync_mode() -> str:
    """
    Ask the user which sync mode to run, unless pre-selected via env var.
    """
    env_choice = env(SYNC_MODE_ENV)
    if env_choice:
        try:
            mode = parse_sync_mode(env_choice)
        except ValueError:
            raise SystemExit(
                f"Invalid {SYNC_MODE_ENV} value '{env_choice}'. Use 1/2 or safe/full."
            )
        LOG.info("Sync mode preselected via %s=%s", SYNC_MODE_ENV, env_choice)
        return mode

    prompt = (
        "Select sync mode:\n"
        "1) Safe update (no deletions)\n"
        "2) Full sync (delete missing VMs from NetBox)\n"
        "Enter choice [1/2]: "
    )

    while True:
        try:
            choice = input(prompt).strip()
        except EOFError:
            raise SystemExit(
                f"No interactive input available. Set {SYNC_MODE_ENV} to 1 or 2."
            )

        if not choice:
            choice = "1"

        try:
            mode = parse_sync_mode(choice)
            LOG.info("Sync mode selected: %s", mode)
            return mode
        except ValueError:
            print("Please enter 1 or 2.")


# ---------------------------------------------------------------------------
# Connections
# ---------------------------------------------------------------------------

def connect_proxmox(
    host_override: Optional[str] = None,
    port_override: Optional[int] = None,
) -> ProxmoxAPI:
    host_value = host_override or env("PVE_HOST", required=True)  # hostname / IP of a node
    host, port = split_host_port(host_value)
    if not host:
        raise SystemExit("Invalid PVE_HOST value (empty)")
    user = env("PVE_USER", required=True)             # e.g. netsync@pve
    token_name = env("PVE_TOKEN_NAME", required=True) # token ID
    token_value = env("PVE_TOKEN_VALUE", required=True)
    verify_ssl = env("PVE_VERIFY_SSL", "false").lower() in ("1", "true", "yes")

    if port_override is not None:
        port = port_override

    LOG.info("Connecting to Proxmox at %s as %s", host, user)

    proxmox_kwargs = {
        "user": user,
        "token_name": token_name,
        "token_value": token_value,
        "verify_ssl": verify_ssl,
        "service": "PVE",
    }
    if port:
        proxmox_kwargs["port"] = port

    proxmox = ProxmoxAPI(host, **proxmox_kwargs)
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
# Per-node Proxmox connections (guest agent exec compatibility)
# ---------------------------------------------------------------------------

NODE_PROXMOX_CACHE: Dict[str, ProxmoxAPI] = {}


def get_node_proxmox(base_proxmox: ProxmoxAPI, node_name: str) -> ProxmoxAPI:
    host, port = resolve_node_host_details(node_name)
    if not host:
        return base_proxmox

    cache_key = f"{host}:{port}" if port else host
    if cache_key in NODE_PROXMOX_CACHE:
        return NODE_PROXMOX_CACHE[cache_key]

    base_host_raw = env("PVE_HOST", "") or ""
    base_host, base_port = split_host_port(base_host_raw)
    if host == base_host and (port or None) == base_port:
        NODE_PROXMOX_CACHE[cache_key] = base_proxmox
        return base_proxmox

    LOG.debug("Using per-node API host %s for node %s", cache_key, node_name)
    node_proxmox = connect_proxmox(host_override=host, port_override=port)
    NODE_PROXMOX_CACHE[cache_key] = node_proxmox
    return node_proxmox


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


def size_to_mb_decimal(value: float, unit: str) -> int:
    """
    Convert a size with unit (K/M/G/T) to MB using decimal (1000) multiplier.
    """
    unit = unit.upper()
    multipliers = {"K": 1 / 1000, "M": 1, "G": 1000, "T": 1000 * 1000}
    return int(round(value * multipliers.get(unit, 1)))


def parse_int(value: Optional[object]) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_bool(value: Optional[object]) -> Optional[bool]:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0

    raw = str(value).strip().lower()
    if raw in ("1", "true", "yes", "on", "enabled"):
        return True
    if raw in ("0", "false", "no", "off", "disabled"):
        return False
    if "enabled=1" in raw or "enable=1" in raw:
        return True
    if "enabled=0" in raw or "enable=0" in raw:
        return False
    if raw.startswith("1") and (raw == "1" or raw[1] in (",", ";")):
        return True
    if raw.startswith("0") and (raw == "0" or raw[1] in (",", ";")):
        return False

    return None


def normalize_text(value: Optional[object]) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def format_sync_timestamp() -> str:
    tz_setting = (env("NB_VM_LAST_SYNC_TZ", "+03:00") or "").strip().lower()

    if tz_setting in ("local", "server", "netbox", "system"):
        stamp = time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime())
        if len(stamp) >= 5 and stamp[-5] in ("+", "-"):
            stamp = f"{stamp[:-2]}:{stamp[-2:]}"
        return stamp

    raw = tz_setting
    if raw.startswith("utc"):
        raw = raw[3:]
    if raw in ("", "z"):
        raw = "+00:00"

    offset_seconds = parse_tz_offset(raw)
    if offset_seconds is None:
        offset_seconds = 3 * 3600

    offset_sign = "+" if offset_seconds >= 0 else "-"
    abs_minutes = abs(offset_seconds) // 60
    offset_str = f"{offset_sign}{abs_minutes // 60:02d}:{abs_minutes % 60:02d}"
    stamp = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() + offset_seconds))
    return f"{stamp}{offset_str}"


def parse_tz_offset(value: Optional[str]) -> Optional[int]:
    if not value:
        return None

    raw = str(value).strip().lower()
    match = re.match(r"^([+-])(\d{1,2})(?::?(\d{2}))?$", raw)
    if not match:
        return None

    sign, hours_raw, minutes_raw = match.groups()
    hours = int(hours_raw)
    minutes = int(minutes_raw or "0")
    if hours > 23 or minutes > 59:
        return None

    offset = (hours * 3600) + (minutes * 60)
    return offset if sign == "+" else -offset


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
# Proxmox metadata helpers (pool + tags)
# ---------------------------------------------------------------------------

def slugify_tag(value: str) -> str:
    value = (value or "").strip().lower()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def parse_proxmox_tags(raw: Optional[object]) -> List[str]:
    if raw is None:
        return []

    values: List[str] = []
    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            if item is None:
                continue
            values.append(str(item))
    else:
        values.append(str(raw))

    tags: List[str] = []
    for value in values:
        for tag in re.split(r"[;,]", value):
            tag = tag.strip()
            if tag:
                tags.append(tag)

    seen: Set[str] = set()
    unique: List[str] = []
    for tag in tags:
        if tag in seen:
            continue
        seen.add(tag)
        unique.append(tag)

    return unique


def ensure_netbox_tags(nb, tags: List[str]) -> Tuple[List[int], bool]:
    ensured: List[int] = []
    unresolved = False

    for tag in tags:
        tag_name = tag.strip()
        if not tag_name:
            continue

        tag_obj = None
        try:
            tag_obj = nb.extras.tags.get(name=tag_name)
        except RequestError as exc:
            LOG.warning("Failed to query NetBox tags for '%s': %s", tag_name, exc)
            unresolved = True
            continue

        if not tag_obj:
            slug = slugify_tag(tag_name)
            if slug:
                try:
                    tag_obj = nb.extras.tags.get(slug=slug)
                except RequestError as exc:
                    LOG.warning(
                        "Failed to query NetBox tags by slug '%s': %s",
                        slug,
                        exc,
                    )
                    unresolved = True
                    continue

        if tag_obj:
            ensured.append(tag_obj.id)
            continue

        create_payload = {"name": tag_name}
        slug = slugify_tag(tag_name)
        if slug:
            create_payload["slug"] = slug

        try:
            tag_obj = nb.extras.tags.create(create_payload)
            if tag_obj:
                ensured.append(tag_obj.id)
        except RequestError as exc:
            LOG.warning("Failed to create NetBox tag '%s': %s", tag_name, exc)
            unresolved = True

    return ensured, unresolved


def fetch_vm_config(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
) -> Optional[dict]:
    try:
        if pve_type == "qemu":
            return proxmox.nodes(node_name).qemu(vmid).config.get()
        if pve_type == "lxc":
            return proxmox.nodes(node_name).lxc(vmid).config.get()
    except Exception as exc:
        LOG.debug("Failed to fetch config for vmid=%s (%s): %s", vmid, pve_type, exc)
    return None


def build_vm_resource_map(proxmox: ProxmoxAPI) -> Dict[int, dict]:
    mapping: Dict[int, dict] = {}
    try:
        resources = proxmox.cluster.resources.get(type="vm")
    except Exception as exc:
        LOG.warning("Failed to fetch cluster resources for pool/tag sync: %s", exc)
        return mapping

    for res in resources:
        vmid = res.get("vmid")
        if not vmid:
            rid = res.get("id") or ""
            if "/" in rid:
                try:
                    vmid = int(rid.split("/", 1)[1])
                except ValueError:
                    vmid = None
        try:
            vmid_int = int(vmid)
        except (TypeError, ValueError):
            continue

        mapping[vmid_int] = {
            "pool": res.get("pool"),
            "pool_known": "pool" in res,
            "tags": res.get("tags"),
            "tags_known": "tags" in res,
        }

    return mapping


def resolve_vm_pool_tags(
    vmid: int,
    vm: dict,
    vm_resource_map: Dict[int, dict],
    config: Optional[dict],
) -> Tuple[Optional[str], bool, List[str], bool]:
    pool = None
    pool_known = False
    tags_raw: Optional[object] = None
    tags_known = False

    meta = vm_resource_map.get(vmid)
    if meta:
        if meta.get("pool_known"):
            pool = meta.get("pool")
            pool_known = True
        if meta.get("tags_known"):
            tags_raw = meta.get("tags")
            tags_known = True

    if not pool_known and "pool" in vm:
        pool = vm.get("pool")
        pool_known = True

    if not tags_known and "tags" in vm:
        tags_raw = vm.get("tags")
        tags_known = True

    if not tags_known and config is not None:
        tags_raw = config.get("tags")
        tags_known = True

    tags = parse_proxmox_tags(tags_raw) if tags_known else []
    return pool, pool_known, tags, tags_known


def create_vm_custom_field(
    nb,
    field_key: str,
    label: str,
    description: str,
    field_type: str = "text",
) -> Optional[object]:
    base_payload = {
        "name": field_key,
        "label": label,
        "type": field_type,
        "description": description,
    }

    attempts = [
        {**base_payload, "object_types": ["virtualization.virtualmachine"]},
        {**base_payload, "content_types": ["virtualization.virtualmachine"]},
        {"name": field_key, "type": "text", "object_types": ["virtualization.virtualmachine"]},
        {"name": field_key, "type": "text", "content_types": ["virtualization.virtualmachine"]},
    ]

    last_exc: Optional[RequestError] = None
    for payload in attempts:
        try:
            return nb.extras.custom_fields.create(payload)
        except RequestError as exc:
            last_exc = exc

    if last_exc:
        LOG.warning(
            "Failed to auto-create NetBox custom field '%s': %s",
            field_key,
            last_exc,
        )
    return None


def create_vm_text_custom_field(
    nb,
    field_key: str,
    label: str,
    description: str,
) -> Optional[object]:
    return create_vm_custom_field(nb, field_key, label, description, field_type="text")


def create_vm_pool_custom_field(nb, pool_cf_key: str) -> Optional[object]:
    return create_vm_text_custom_field(
        nb,
        pool_cf_key,
        "Pool",
        "Proxmox pool name",
    )


def normalize_content_type_list(values: Optional[object]) -> Tuple[List[object], bool, bool]:
    normalized: List[object] = []
    has_int = False
    has_str = False

    if not values:
        return normalized, has_int, has_str

    for item in values:
        if isinstance(item, str):
            normalized.append(item)
            has_str = True
            continue
        if isinstance(item, int):
            normalized.append(item)
            has_int = True
            continue
        if isinstance(item, dict):
            if "app_label" in item and "model" in item:
                normalized.append(f"{item['app_label']}.{item['model']}")
                has_str = True
                continue
            if "display" in item:
                normalized.append(str(item["display"]))
                has_str = True
                continue
            if "name" in item:
                normalized.append(str(item["name"]))
                has_str = True
                continue
            if "id" in item:
                try:
                    normalized.append(int(item["id"]))
                    has_int = True
                except (TypeError, ValueError):
                    pass

    return normalized, has_int, has_str


def get_vm_content_type_id(nb) -> Optional[int]:
    try:
        ct_endpoint = getattr(nb.extras, "content_types", None)
        if not ct_endpoint:
            return None
        ct = ct_endpoint.get(app_label="virtualization", model="virtualmachine")
    except Exception as exc:
        LOG.warning("Failed to query NetBox content types: %s", exc)
        return None
    return getattr(ct, "id", None)


def ensure_vm_custom_field_attached(nb, cf, field_key: str) -> bool:
    target_type = "virtualization.virtualmachine"

    raw_object_types = getattr(cf, "object_types", None)
    raw_content_types = getattr(cf, "content_types", None)
    field_attr = "object_types" if raw_object_types is not None else "content_types"
    raw_types = raw_object_types if raw_object_types is not None else raw_content_types

    normalized, has_int, has_str = normalize_content_type_list(raw_types)

    if has_str and target_type in normalized:
        return True

    if has_int:
        ct_id = get_vm_content_type_id(nb)
        if ct_id and ct_id in normalized:
            return True

    def try_save(updated_values: List[object]) -> bool:
        try:
            setattr(cf, field_attr, updated_values)
            cf.save()
            return True
        except RequestError as exc:
            LOG.warning(
                "Failed to auto-attach NetBox custom field '%s': %s",
                field_key,
                exc,
            )
            return False

    if has_str or not has_int:
        updated = [item for item in normalized if isinstance(item, str)]
        if target_type not in updated:
            updated.append(target_type)
        if try_save(updated):
            return True

    if has_int:
        ct_id = get_vm_content_type_id(nb)
        if not ct_id:
            LOG.warning(
                "Unable to resolve NetBox content type id for %s; custom field attach disabled",
                target_type,
            )
            return False
        updated = [item for item in normalized if isinstance(item, int)]
        if ct_id not in updated:
            updated.append(ct_id)
        if try_save(updated):
            return True

    return False


def resolve_vm_custom_field_spec(
    nb,
    env_var: str,
    label: str,
    description: str,
    default_key: Optional[str] = None,
    field_type: str = "text",
) -> Optional[List[dict]]:
    field_key_raw = (env(env_var, default_key) or "").strip()
    if not field_key_raw:
        return None
    field_keys = [key.strip() for key in field_key_raw.split(",") if key.strip()]
    if not field_keys:
        return None

    specs: List[dict] = []
    seen_keys: Set[str] = set()

    def add_cf(cf_obj: object, fallback_type: str) -> None:
        resolved_key = getattr(cf_obj, "name", None)
        if not resolved_key:
            return
        key_norm = str(resolved_key).strip().lower()
        if not key_norm or key_norm in seen_keys:
            return
        if not custom_field_attached_to_vm(nb, cf_obj):
            if not ensure_vm_custom_field_attached(nb, cf_obj, resolved_key):
                LOG.warning(
                    "NetBox custom field '%s' is not attached to virtualization.virtualmachine; "
                    "%s sync disabled",
                    resolved_key,
                    label,
                )
                return
        seen_keys.add(key_norm)
        resolved_type = getattr(cf_obj, "type", None) or fallback_type
        specs.append({"key": resolved_key, "type": resolved_type})

    # If multiple keys were explicitly provided, honor them as-is.
    if len(field_keys) > 1:
        for field_key in field_keys:
            try:
                cf = nb.extras.custom_fields.get(name=field_key)
            except Exception as exc:
                LOG.warning(
                    "Unable to query NetBox custom fields; %s sync disabled: %s",
                    label,
                    exc,
                )
                return None
            if not cf:
                cf = find_custom_field_by_label(nb, field_key, preferred_key=field_key)
            if cf:
                add_cf(cf, field_type)
            else:
                LOG.warning(
                    "NetBox custom field '%s' not found; skipping",
                    field_key,
                )
        return specs or None

    field_key = field_keys[0]
    try:
        cf = nb.extras.custom_fields.get(name=field_key)
    except Exception as exc:
        LOG.warning(
            "Unable to query NetBox custom fields; %s sync disabled: %s",
            label,
            exc,
        )
        return None

    if not cf:
        cf = find_custom_field_by_label(nb, field_key, preferred_key=field_key)
    if not cf and label and label != field_key:
        cf = find_custom_field_by_label(nb, label, preferred_key=field_key)

    if cf:
        add_cf(cf, field_type)
        cf_label = getattr(cf, "label", None)
        if cf_label:
            for extra in find_custom_fields_by_label(nb, cf_label):
                add_cf(extra, field_type)
        return specs or None

    label_matches = find_custom_fields_by_label(nb, label or field_key)
    attached_matches = [match for match in label_matches if custom_field_attached_to_vm(nb, match)]
    for match in attached_matches or label_matches:
        add_cf(match, field_type)

    if specs:
        return specs

    LOG.warning(
        "NetBox custom field '%s' not found; attempting to auto-create",
        field_key,
    )
    cf = create_vm_custom_field(nb, field_key, label, description, field_type=field_type)
    if not cf:
        LOG.warning(
            "%s sync disabled; custom field '%s' could not be created",
            label,
            field_key,
        )
        return None

    add_cf(cf, field_type)
    return specs or None


def resolve_vm_custom_field_specs(nb) -> Dict[str, Optional[List[dict]]]:
    return {
        "pool": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_POOL_CF",
            "Pool",
            "Proxmox pool name",
            default_key="pool",
            field_type="text",
        ),
        "gateway4": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_GW4_CF",
            "Gateway IPv4",
            "Proxmox VM default IPv4 gateway",
            default_key="gateway4",
            field_type="text",
        ),
        "gateway6": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_GW6_CF",
            "Gateway IPv6",
            "Proxmox VM default IPv6 gateway",
            default_key="gateway6",
            field_type="text",
        ),
        "vmid": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_VMID_CF",
            "VMID",
            "Proxmox VMID",
            default_key="vmid",
            field_type="integer",
        ),
        "sockets": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_SOCKETS_CF",
            "Sockets",
            "Proxmox VM CPU sockets",
            default_key="sockets",
            field_type="integer",
        ),
        "cores": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_CORES_CF",
            "Cores",
            "Proxmox VM CPU cores per socket",
            default_key="cores",
            field_type="integer",
        ),
        "cpu_type": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_CPU_TYPE_CF",
            "CPU Type",
            "Proxmox VM CPU type",
            default_key="cpu_type",
            field_type="text",
        ),
        "qemu_cpu_type": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_QEMU_CPU_TYPE_CF",
            "QEMU CPU Type",
            "Proxmox QEMU CPU type",
            default_key="qemu_cpu_type",
            field_type="text",
        ),
        "os_type": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_OS_TYPE_CF",
            "OS Type",
            "Proxmox VM OS type",
            default_key="os_type",
            field_type="text",
        ),
        "description": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_DESCRIPTION_CF",
            "VM Description",
            "Proxmox VM description",
            default_key="pve_description",
            field_type="text",
        ),
        "boot_disk": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_BOOT_DISK_CF",
            "Boot Disk",
            "Proxmox VM boot disk",
            default_key="boot_disk",
            field_type="text",
        ),
        "boot_disk_format": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_BOOT_DISK_FORMAT_CF",
            "Boot Disk Format",
            "Proxmox VM boot disk format",
            default_key="boot_disk_format",
            field_type="text",
        ),
        "boot_disk_storage": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_BOOT_DISK_STORAGE_CF",
            "Boot Disk Storage",
            "Proxmox VM boot disk storage",
            default_key="boot_disk_storage",
            field_type="text",
        ),
        "guest_agent": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_GUEST_AGENT_CF",
            "Guest Agent Status",
            "Proxmox VM guest agent status",
            default_key="guest_agent_status",
            field_type="text",
        ),
        "memory_mb": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_MEMORY_MB_CF",
            "Memory (MB)",
            "Proxmox VM memory in MB",
            default_key="memory_mb",
            field_type="integer",
        ),
        "vm_node": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_NODE_CF",
            "VM Node",
            "Proxmox VM node",
            default_key="vm_node",
            field_type="text",
        ),
        "vm_status": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_STATUS_CF",
            "VM Status",
            "Proxmox VM status",
            default_key="vm_status",
            field_type="text",
        ),
        "vm_tags": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_TAGS_CF",
            "Tags",
            "Proxmox VM tags (comma-separated)",
            default_key="vm_tags",
            field_type="text",
        ),
        "cpu_sockets": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_CPU_SOCKETS_CF",
            "CPU Sockets",
            "Proxmox VM CPU sockets",
            default_key="cpu_sockets",
            field_type="integer",
        ),
        "qemu_cores_per_socket": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_QEMU_CORES_PER_SOCKET_CF",
            "QEMU Cores per Socket",
            "Proxmox QEMU cores per socket",
            default_key="qemu_cores_per_socket",
            field_type="integer",
        ),
        "qemu_numa": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_QEMU_NUMA_CF",
            "QEMU NUMA Enabled",
            "Proxmox QEMU NUMA setting",
            default_key="qemu_numa",
            field_type="boolean",
        ),
        "qemu_bios": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_QEMU_BIOS_CF",
            "QEMU BIOS Type",
            "Proxmox QEMU BIOS type",
            default_key="qemu_bios",
            field_type="text",
        ),
        "qemu_boot_order": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_QEMU_BOOT_ORDER_CF",
            "QEMU Boot Order",
            "Proxmox QEMU boot order",
            default_key="qemu_boot_order",
            field_type="text",
        ),
        "qemu_machine": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_QEMU_MACHINE_CF",
            "QEMU Machine Type",
            "Proxmox QEMU machine type",
            default_key="qemu_machine",
            field_type="text",
        ),
        "last_sync": resolve_vm_custom_field_spec(
            nb,
            "NB_VM_LAST_SYNC_CF",
            "Last Sync",
            "Last Proxmox sync timestamp (UTC)",
            default_key="last_sync",
            field_type="text",
        ),
    }


def cast_custom_field_value(value: Optional[object], field_type: str) -> Optional[object]:
    if value is None:
        return None

    field_type = normalize_custom_field_type(field_type)
    if field_type == "integer":
        return parse_int(value)
    if field_type == "boolean":
        parsed = parse_bool(value)
        return parsed if parsed is not None else None

    return str(value)


def normalize_custom_field_type(field_type: Optional[object]) -> str:
    if not field_type:
        return "text"
    if isinstance(field_type, str):
        return field_type.lower()

    for attr in ("value", "name", "label", "slug"):
        try:
            candidate = getattr(field_type, attr)
        except Exception:
            candidate = None
        if isinstance(candidate, str) and candidate:
            return candidate.lower()

    return str(field_type).lower()


def custom_field_attached_to_vm(nb, cf: object) -> bool:
    target_type = "virtualization.virtualmachine"
    raw_object_types = getattr(cf, "object_types", None)
    raw_content_types = getattr(cf, "content_types", None)
    raw_types = raw_object_types if raw_object_types is not None else raw_content_types

    normalized, has_int, has_str = normalize_content_type_list(raw_types)
    if has_str and target_type in normalized:
        return True
    if has_int:
        ct_id = get_vm_content_type_id(nb)
        if ct_id and ct_id in normalized:
            return True
    return False


def find_custom_fields_by_label(nb, label_value: Optional[str]) -> List[object]:
    if not label_value:
        return []

    try:
        matches = list(nb.extras.custom_fields.filter(label=label_value))
    except Exception as exc:
        LOG.debug("Failed to query NetBox custom fields by label '%s': %s", label_value, exc)
        matches = []

    if matches:
        return matches

    # Fallback: case-insensitive label scan (NetBox label filters may be case-sensitive).
    try:
        all_fields = list(nb.extras.custom_fields.filter())
    except Exception as exc:
        LOG.debug("Failed to list NetBox custom fields for label scan: %s", exc)
        return []

    target = label_value.strip().lower()
    if not target:
        return []

    return [
        cf
        for cf in all_fields
        if str(getattr(cf, "label", "")).strip().lower() == target
    ]


def find_custom_field_by_label(
    nb,
    label_value: Optional[str],
    preferred_key: Optional[str] = None,
) -> Optional[object]:
    if not label_value:
        return None
    matches = find_custom_fields_by_label(nb, label_value)
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        preferred = select_custom_field_by_key(matches, preferred_key) or select_custom_field_by_key(
            matches, label_value
        )
        if preferred:
            return preferred
        LOG.warning(
            "Multiple NetBox custom fields match label '%s'; skipping label match",
            label_value,
        )
        return None
    return None


def select_custom_field_by_key(candidates: List[object], preferred_key: Optional[str]) -> Optional[object]:
    if not preferred_key:
        return None

    key = str(preferred_key).strip().lower()
    if not key:
        return None

    for cf in candidates:
        name = str(getattr(cf, "name", "")).strip().lower()
        if name == key:
            return cf

    tokens = [t for t in re.split(r"[^a-z0-9]+", key) if t]
    if not tokens:
        return None

    for cf in candidates:
        name = str(getattr(cf, "name", "")).strip().lower()
        if all(token in name for token in tokens):
            return cf

    return None


def set_custom_field_value(
    custom_fields_data: Dict[str, object],
    spec: Optional[object],
    value: Optional[object],
    include_if_none: bool = False,
) -> None:
    if isinstance(spec, list):
        for item in spec:
            set_custom_field_value(custom_fields_data, item, value, include_if_none=include_if_none)
        return
    if not spec:
        return
    if value is None and not include_if_none:
        return
    casted = cast_custom_field_value(value, spec.get("type", "text"))
    if casted is None and value is not None and not include_if_none:
        return
    custom_fields_data[spec["key"]] = casted


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


def parse_gateway_settings(raw_value: str) -> Tuple[Optional[str], bool, Optional[str], bool]:
    """
    Parse gw/gw6 from a Proxmox config string (netX or ipconfigX).

    Returns (gw4, gw4_known, gw6, gw6_known).
    """
    gw4 = None
    gw6 = None
    gw4_known = False
    gw6_known = False

    if not raw_value:
        return gw4, gw4_known, gw6, gw6_known

    for part in raw_value.split(","):
        if "=" not in part:
            continue
        key, val = part.split("=", 1)
        key = key.strip()
        val = val.strip()
        if key == "gw":
            gw4_known = True
            gw4 = val or None
        elif key == "gw6":
            gw6_known = True
            gw6 = val or None

    return gw4, gw4_known, gw6, gw6_known


def iter_vm_gateway_configs(pve_type: str, config: dict) -> List[str]:
    if pve_type == "lxc":
        pattern = r"^net(\d+)$"
    else:
        pattern = r"^ipconfig(\d+)$"

    matches: List[Tuple[int, str]] = []
    for key, value in (config or {}).items():
        match = re.match(pattern, str(key))
        if not match:
            continue
        index = int(match.group(1))
        if value is None:
            continue
        matches.append((index, str(value)))

    matches.sort(key=lambda item: item[0])
    return [value for _, value in matches]


def resolve_vm_gateways(
    pve_type: str,
    config: Optional[dict],
) -> Tuple[List[str], bool, List[str], bool]:
    if not config:
        return [], False, [], False

    gw4_values: List[str] = []
    gw6_values: List[str] = []
    gw4_known = False
    gw6_known = False

    for raw_value in iter_vm_gateway_configs(pve_type, config):
        gw4, gw4_present, gw6, gw6_present = parse_gateway_settings(raw_value)
        if gw4_present:
            gw4_known = True
            if gw4:
                gw4_values.append(gw4)
        if gw6_present:
            gw6_known = True
            if gw6:
                gw6_values.append(gw6)

    return gw4_values, gw4_known, gw6_values, gw6_known


def decode_guest_agent_output(raw: Optional[object]) -> str:
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        return raw.decode("utf-8", errors="replace")

    text = str(raw).strip()
    if not text:
        return ""

    if re.fullmatch(r"[A-Za-z0-9+/=]+", text) and len(text) % 4 == 0:
        try:
            decoded = base64.b64decode(text, validate=True)
            return decoded.decode("utf-8", errors="replace")
        except (binascii.Error, ValueError):
            pass

    return text


def build_guest_exec_stdin_payload(
    command: str,
    args: Optional[List[str]],
    encode_base64: bool = False,
) -> Tuple[Optional[dict], Optional[str]]:
    if not command:
        return None, None

    args = args or []
    script = None

    if command.lower().endswith("powershell.exe"):
        try:
            cmd_index = args.index("-Command")
            script = " ".join(args[cmd_index + 1 :]).strip()
        except ValueError:
            script = " ".join(args).strip() if args else None
    elif command.endswith("/sh") or command.endswith("\\sh"):
        if "-c" in args:
            try:
                c_index = args.index("-c")
                script = " ".join(args[c_index + 1 :]).strip()
            except ValueError:
                script = " ".join(args).strip() if args else None
        else:
            script = " ".join(args).strip() if args else None
    else:
        script = " ".join(args).strip() if args else None

    if not script:
        return None, None

    if not script.endswith("\n"):
        script += "\n"

    payload_value = script
    if encode_base64:
        payload_value = base64.b64encode(script.encode("utf-8")).decode("ascii")
    return {"command": command, "input-data": payload_value}, script


def looks_like_base64_script_error(err_text: str, script: str) -> bool:
    if not err_text or not script:
        return False
    match = re.search(r":\\s*([A-Za-z0-9+/=]{16,})\\s*:\\s*not found", err_text)
    if not match:
        return False
    token = match.group(1)
    try:
        decoded = base64.b64decode(token, validate=True).decode("utf-8", errors="replace")
    except (binascii.Error, ValueError):
        return False
    return script.strip() in decoded


def collect_guest_exec_output(
    node_proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    result: object,
    timeout_s: int,
) -> Tuple[Optional[str], Optional[int], str]:
    if isinstance(result, dict) and isinstance(result.get("result"), dict):
        result = result["result"]
    elif isinstance(result, dict) and isinstance(result.get("data"), dict):
        result = result["data"]

    pid = result.get("pid") if isinstance(result, dict) else None
    if not pid:
        LOG.debug("Guest exec returned no pid for vmid=%s on %s: %s", vmid, node_name, result)
        return None, None, ""

    status = None
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            status = node_proxmox.nodes(node_name).qemu(vmid).agent("exec-status").get(pid=pid)
        except Exception as exc:
            LOG.debug("Guest exec status failed for vmid=%s on %s: %s", vmid, node_name, exc)
            return None, None, ""
        if isinstance(status, dict) and isinstance(status.get("result"), dict):
            status = status["result"]
        elif isinstance(status, dict) and isinstance(status.get("data"), dict):
            status = status["data"]
        if not isinstance(status, dict):
            return None, None, ""
        if status.get("exited"):
            break
        time.sleep(0.2)

    if not status or not status.get("exited"):
        LOG.warning("Guest exec timed out for vmid=%s on %s", vmid, node_name)
        return None, None, ""

    exitcode = status.get("exitcode")
    out_data = decode_guest_agent_output(status.get("out-data"))
    err_data = decode_guest_agent_output(status.get("err-data"))
    return out_data, exitcode, err_data


def run_guest_agent_command(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
    command: str,
    args: Optional[List[str]] = None,
    timeout_s: int = 8,
) -> Optional[str]:
    if pve_type != "qemu":
        return None

    node_proxmox = get_node_proxmox(proxmox, node_name)

    arg_list = args or []
    payloads = [
        {"command": command, "arg": arg_list, "capture-output": 1},
        {"command": command, "args": arg_list, "capture-output": 1},
        {"command": command, "arg": arg_list},
        {"command": command, "args": arg_list},
    ]
    if not arg_list:
        payloads.append({"command": command})

    result = None
    last_exc: Optional[Exception] = None
    stdin_script = None
    stdin_base64 = False
    for payload in payloads:
        try:
            result = node_proxmox.nodes(node_name).qemu(vmid).agent("exec").post(**payload)
            break
        except Exception as exc:
            last_exc = exc
            LOG.debug(
                "Guest exec failed (payload keys=%s) for vmid=%s on %s: %s",
                ",".join(payload.keys()),
                vmid,
                node_name,
                exc,
            )
            result = None

    if result is None:
        stdin_payload, stdin_script = build_guest_exec_stdin_payload(
            command,
            arg_list,
            encode_base64=False,
        )
        if stdin_payload:
            LOG.debug(
                "Guest exec attempting stdin payload (mode=raw, keys=%s) for vmid=%s on %s",
                ",".join(stdin_payload.keys()),
                vmid,
                node_name,
            )
            try:
                result = node_proxmox.nodes(node_name).qemu(vmid).agent("exec").post(**stdin_payload)
                stdin_base64 = False
                LOG.debug(
                    "Guest exec succeeded using stdin payload for vmid=%s on %s",
                    vmid,
                    node_name,
                )
            except Exception as exc:
                LOG.debug(
                    "Guest exec failed with stdin payload for vmid=%s on %s: %s",
                    vmid,
                    node_name,
                    exc,
                )
                result = None
                stdin_script = None
                stdin_base64 = False

    if result is None:
        stdin_payload, stdin_script = build_guest_exec_stdin_payload(
            command,
            arg_list,
            encode_base64=True,
        )
        if stdin_payload:
            LOG.debug(
                "Guest exec attempting stdin payload (mode=base64, keys=%s) for vmid=%s on %s",
                ",".join(stdin_payload.keys()),
                vmid,
                node_name,
            )
            try:
                result = node_proxmox.nodes(node_name).qemu(vmid).agent("exec").post(**stdin_payload)
                stdin_base64 = True
                LOG.debug(
                    "Guest exec succeeded using stdin payload for vmid=%s on %s",
                    vmid,
                    node_name,
                )
            except Exception as exc:
                LOG.debug(
                    "Guest exec failed with stdin payload for vmid=%s on %s: %s",
                    vmid,
                    node_name,
                    exc,
                )
                result = None
                stdin_script = None
                stdin_base64 = False

    if result is None and arg_list:
        combined_command = " ".join([command] + arg_list)
        LOG.debug(
            "Guest exec attempting combined command for vmid=%s on %s: %s",
            vmid,
            node_name,
            combined_command,
        )
        try:
            result = node_proxmox.nodes(node_name).qemu(vmid).agent("exec").post(
                command=combined_command
            )
        except Exception as exc:
            LOG.debug(
                "Guest exec failed with combined command for vmid=%s on %s: %s",
                vmid,
                node_name,
                exc,
            )
            result = None

    if result is None:
        if last_exc:
            LOG.debug("Guest exec failed to start for vmid=%s on %s: %s", vmid, node_name, last_exc)
        return None

    out_data, exitcode, err_data = collect_guest_exec_output(
        node_proxmox,
        node_name,
        vmid,
        result,
        timeout_s,
    )

    if exitcode not in (0, None):
        if stdin_base64 and stdin_script and looks_like_base64_script_error(err_data, stdin_script):
            raw_payload, _ = build_guest_exec_stdin_payload(
                command,
                arg_list,
                encode_base64=False,
            )
            if raw_payload:
                LOG.debug(
                    "Guest exec retrying stdin payload without base64 for vmid=%s on %s",
                    vmid,
                    node_name,
                )
                try:
                    result = node_proxmox.nodes(node_name).qemu(vmid).agent("exec").post(
                        **raw_payload
                    )
                except Exception as exc:
                    LOG.debug(
                        "Guest exec failed with raw stdin payload for vmid=%s on %s: %s",
                        vmid,
                        node_name,
                        exc,
                    )
                    return None

                out_data, exitcode, err_data = collect_guest_exec_output(
                    node_proxmox,
                    node_name,
                    vmid,
                    result,
                    timeout_s,
                )
                if exitcode in (0, None):
                    return out_data

        if err_data:
            LOG.debug(
                "Guest exec exitcode=%s for vmid=%s on %s: %s",
                exitcode,
                vmid,
                node_name,
                err_data,
            )
        return None

    return out_data


def fetch_guest_osinfo(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
) -> Optional[dict]:
    if pve_type != "qemu":
        return None

    node_proxmox = get_node_proxmox(proxmox, node_name)

    try:
        result = node_proxmox.nodes(node_name).qemu(vmid).agent("get-osinfo").get()
    except Exception:
        return None

    if isinstance(result, dict) and "result" in result:
        return result.get("result")
    if isinstance(result, dict) and "data" in result:
        return result.get("data")
    if isinstance(result, dict):
        return result
    return None


def is_guest_windows(osinfo: Optional[dict]) -> bool:
    if not osinfo:
        return False
    for key in ("name", "id", "pretty-name", "version"):
        value = osinfo.get(key)
        if isinstance(value, str) and "windows" in value.lower():
            return True
    return False


def parse_default_gateway_lines(output: str) -> List[str]:
    gateways: List[str] = []
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        tokens = line.split()
        if "via" in tokens:
            idx = tokens.index("via")
            if idx + 1 < len(tokens):
                gateways.append(tokens[idx + 1])
                continue
        match = re.search(r"\bvia\s+(\S+)", line)
        if match:
            gateways.append(match.group(1))
    return gateways


def parse_gateway_list_lines(output: str) -> List[str]:
    gateways: List[str] = []
    for line in (output or "").splitlines():
        value = line.strip()
        if value:
            gateways.append(value)
    return gateways


def fetch_guest_default_gateways(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
) -> Tuple[List[str], List[str]]:
    if pve_type != "qemu":
        return [], []

    osinfo = fetch_guest_osinfo(proxmox, node_name, vmid, pve_type)
    if is_guest_windows(osinfo):
        gw4_cmd = (
            "Get-NetRoute -DestinationPrefix 0.0.0.0/0 | "
            "Where-Object {$_.NextHop -ne '0.0.0.0'} | "
            "Select-Object -ExpandProperty NextHop"
        )
        gw6_cmd = (
            "Get-NetRoute -DestinationPrefix ::/0 | "
            "Where-Object {$_.NextHop -ne '::'} | "
            "Select-Object -ExpandProperty NextHop"
        )
        out4 = run_guest_agent_command(
            proxmox,
            node_name,
            vmid,
            pve_type,
            command="powershell.exe",
            args=["-NoProfile", "-Command", gw4_cmd],
        )
        out6 = run_guest_agent_command(
            proxmox,
            node_name,
            vmid,
            pve_type,
            command="powershell.exe",
            args=["-NoProfile", "-Command", gw6_cmd],
        )
        return parse_gateway_list_lines(out4 or ""), parse_gateway_list_lines(out6 or "")

    def run_guest_cmd_variants(cmds: List[str]) -> str:
        for cmd in cmds:
            out = run_guest_agent_command(
                proxmox,
                node_name,
                vmid,
                pve_type,
                command="/bin/sh",
                args=["-c", cmd],
            )
            if out:
                return out
        return ""

    gw4_cmds = [
        "ip -4 route show default",
        "/usr/sbin/ip -4 route show default",
        "/sbin/ip -4 route show default",
        "ip route show default",
        "/usr/sbin/ip route show default",
        "/sbin/ip route show default",
    ]
    gw6_cmds = [
        "ip -6 route show default",
        "/usr/sbin/ip -6 route show default",
        "/sbin/ip -6 route show default",
    ]
    out4 = run_guest_cmd_variants(gw4_cmds)
    out6 = run_guest_cmd_variants(gw6_cmds)
    return parse_default_gateway_lines(out4 or ""), parse_default_gateway_lines(out6 or "")


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

    node_proxmox = get_node_proxmox(proxmox, node_name)

    try:
        result = node_proxmox.nodes(node_name).qemu(vmid).agent("network-get-interfaces").get()
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
# NetBox VM matching helpers
# ---------------------------------------------------------------------------

def extract_vmid_from_comments(comments: Optional[str]) -> Optional[int]:
    """
    Try to pull `vmid=<int>` from a NetBox VM comments field.
    """
    if not comments:
        return None
    match = re.search(r"vmid=(\\d+)", comments)
    if match:
        try:
            return int(match.group(1))
        except ValueError:
            return None
    return None


def map_netbox_vms_by_vmid(nb, cluster) -> Dict[int, object]:
    """
    Build a map of vmid -> NetBox VM for the given cluster using vmid in comments.
    """
    mapping: Dict[int, object] = {}
    cluster_vms = nb.virtualization.virtual_machines.filter(cluster_id=cluster.id)
    for vm in cluster_vms:
        vmid = extract_vmid_from_comments(getattr(vm, "comments", ""))
        if vmid is None or vmid in mapping:
            continue
        mapping[vmid] = vm
    return mapping


# ---------------------------------------------------------------------------
# Disk size helpers
# ---------------------------------------------------------------------------

DISK_KEY_PREFIXES = ("scsi", "sata", "virtio", "ide", "efidisk", "unused")
BOOT_DISK_PREFIXES = ("scsi", "sata", "virtio", "ide")


def parse_disk_sizes_from_config(config: dict) -> int:
    """
    Parse disk sizes from Proxmox VM/LXC config strings and return total MB (decimal).
    """
    total_mb = 0
    size_re = re.compile(r"size=([\d.]+)([KMGTP])", re.IGNORECASE)

    for key, value in config.items():
        key_l = str(key).lower()
        if not key_l.startswith(DISK_KEY_PREFIXES):
            continue
        if not isinstance(value, str):
            continue
        value_l = value.lower()
        # Ignore ISO / CD-ROM attachments (they carry size=N but aren't disk storage)
        if (
            "media=cdrom" in value_l
            or ",cdrom" in value_l
            or "cdrom=" in value_l
            or ".iso" in value_l
            or "iso/" in value_l
        ):
            continue

        match = size_re.search(value)
        if not match:
            continue
        amount = float(match.group(1))
        unit = match.group(2)
        total_mb += size_to_mb_decimal(amount, unit)

    return int(total_mb)


def get_vm_disk_mb(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
    vm: dict,
    config: Optional[dict] = None,
) -> int:
    """
    Determine VM disk size in MB (decimal). Prefer config parsing; fall back to maxdisk.
    """
    if config is None:
        config = fetch_vm_config(proxmox, node_name, vmid, pve_type)

    total_mb = parse_disk_sizes_from_config(config) if config else 0
    if total_mb > 0:
        LOG.debug("Disk size for vmid=%s from config: %s MB", vmid, total_mb)
        return total_mb

    maxdisk = vm.get("maxdisk") or 0
    if not maxdisk and config:
        maxdisk = config.get("maxdisk", 0)
    if not maxdisk:
        try:
            status = {}
            if pve_type == "qemu":
                status = proxmox.nodes(node_name).qemu(vmid).status.current.get()
            elif pve_type == "lxc":
                status = proxmox.nodes(node_name).lxc(vmid).status.current.get()
            maxdisk = status.get("maxdisk", 0)
        except Exception as exc:
            LOG.debug("Failed to fetch status.current for disk sizing (vmid=%s): %s", vmid, exc)

    return bytes_to_mb(maxdisk)


def is_cdrom_value(value: str) -> bool:
    value_l = value.lower()
    return (
        "media=cdrom" in value_l
        or ",cdrom" in value_l
        or "cdrom=" in value_l
        or ".iso" in value_l
        or "iso/" in value_l
    )


def is_disk_config_key(key: str, value: Optional[object]) -> bool:
    key_l = str(key).lower()
    if not key_l.startswith(DISK_KEY_PREFIXES):
        return False
    if not isinstance(value, str):
        return False
    if is_cdrom_value(value):
        return False
    return True


def is_boot_disk_config_key(key: str, value: Optional[object]) -> bool:
    key_l = str(key).lower()
    if not key_l.startswith(BOOT_DISK_PREFIXES):
        return False
    if key_l.startswith("unused"):
        return False
    if key_l.startswith("efidisk") or key_l.startswith("tpmstate"):
        return False
    if not isinstance(value, str):
        return False
    if is_cdrom_value(value):
        return False
    return True


def resolve_vm_cpu_info(
    vm: dict,
    config: Optional[dict],
    pve_type: str,
) -> Tuple[int, Optional[int], Optional[int], Optional[str]]:
    config = config or {}

    cores = parse_int(config.get("cores"))
    if cores is None:
        cores = parse_int(vm.get("cores"))

    sockets = parse_int(config.get("sockets"))
    if sockets is None:
        sockets = parse_int(vm.get("sockets"))

    if pve_type == "qemu" and sockets is None and cores is not None:
        sockets = 1

    cpu_type = None
    if pve_type == "qemu":
        cpu_type = normalize_text(
            config.get("cpu")
            or config.get("cputype")
            or vm.get("cpu")
            or vm.get("cputype")
        )

    vcpus = None
    if cores is not None and sockets is not None:
        vcpus = cores * sockets
    if not vcpus:
        vcpus = parse_int(vm.get("vcpus") or vm.get("cpus") or vm.get("maxcpu"))
    if not vcpus and cores is not None:
        vcpus = cores
    if not vcpus or vcpus < 1:
        vcpus = 1

    return vcpus, cores, sockets, cpu_type


def format_guest_os_name(osinfo: Optional[dict]) -> Optional[str]:
    if not osinfo:
        return None

    for key in ("pretty-name", "pretty_name", "prettyName"):
        value = osinfo.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    name = osinfo.get("name")
    version = osinfo.get("version") or osinfo.get("version-id")
    if isinstance(name, str) and name.strip():
        if isinstance(version, str) and version.strip():
            return f"{name.strip()} {version.strip()}"
        return name.strip()

    os_id = osinfo.get("id")
    if isinstance(os_id, str) and os_id.strip():
        return os_id.strip()

    return None


def map_pve_ostype(code: Optional[str], pve_type: str) -> Optional[str]:
    if not code:
        return None
    key = str(code).strip().lower()
    if not key:
        return None

    qemu_map = {
        "l26": "Linux",
        "l24": "Linux 2.4",
        "l16": "Linux 2.2",
        "otherlinux": "Linux",
        "win11": "Windows 11",
        "win10": "Windows 10",
        "win8": "Windows 8/8.1",
        "win7": "Windows 7",
        "w2k": "Windows 2000",
        "wxp": "Windows XP",
        "w2k3": "Windows Server 2003",
        "win2k8": "Windows Server 2008",
        "win2k8r2": "Windows Server 2008 R2",
        "win2k12": "Windows Server 2012",
        "win2k12r2": "Windows Server 2012 R2",
        "win2k16": "Windows Server 2016",
        "win2k19": "Windows Server 2019",
        "win2k22": "Windows Server 2022",
        "solaris": "Solaris",
        "opensolaris": "OpenSolaris",
        "freebsd": "FreeBSD",
        "netbsd": "NetBSD",
        "openbsd": "OpenBSD",
        "other": "Other",
    }

    lxc_map = {
        "alpine": "Alpine Linux",
        "archlinux": "Arch Linux",
        "amazon": "Amazon Linux",
        "centos": "CentOS",
        "debian": "Debian",
        "fedora": "Fedora Linux",
        "gentoo": "Gentoo Linux",
        "nixos": "NixOS",
        "oracle": "Oracle Linux",
        "opensuse": "openSUSE",
        "rocky": "Rocky Linux",
        "almalinux": "AlmaLinux",
        "ubuntu": "Ubuntu",
        "void": "Void Linux",
        "openwrt": "OpenWrt",
    }

    # If Proxmox reports a QEMU-style ostype (like l26), map it regardless of VM type.
    if key in qemu_map:
        return qemu_map[key]

    if pve_type == "lxc":
        return lxc_map.get(key, key.replace("_", " ").replace("-", " ").title())

    return qemu_map.get(key, key.replace("_", " ").replace("-", " ").title())


def resolve_vm_os_type(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
    vm: dict,
    config: Optional[dict],
) -> Optional[str]:
    if pve_type == "qemu":
        osinfo = fetch_guest_osinfo(proxmox, node_name, vmid, pve_type)
        pretty = format_guest_os_name(osinfo)
        if pretty:
            return pretty

    config = config or {}
    raw = normalize_text(config.get("ostype") or vm.get("ostype"))
    return map_pve_ostype(raw, pve_type)


def resolve_vm_description(vm: dict, config: Optional[dict]) -> Optional[str]:
    config = config or {}
    return normalize_text(config.get("description") or vm.get("description"))


def resolve_boot_disk(pve_type: str, config: Optional[dict]) -> Optional[str]:
    config = config or {}

    if pve_type == "lxc":
        rootfs = config.get("rootfs")
        if isinstance(rootfs, str):
            rootfs = rootfs.split(",", 1)[0]
        return normalize_text(rootfs)

    if pve_type != "qemu":
        return None

    bootdisk = normalize_text(config.get("bootdisk"))
    if bootdisk and not bootdisk.lower().startswith("unused"):
        return bootdisk

    boot = normalize_text(config.get("boot"))
    if boot:
        order_raw = boot
        match = re.search(r"order=([^\\s]+)", order_raw)
        if match:
            order_raw = match.group(1)
        for item in re.split(r"[;,\\s]+", order_raw):
            item = item.strip()
            if not item:
                continue
            value = config.get(item)
            if is_boot_disk_config_key(item, value):
                return item

    candidates: List[Tuple[int, int, str]] = []
    for key, value in config.items():
        if not is_boot_disk_config_key(key, value):
            continue
        key_s = str(key)
        key_l = key_s.lower()
        match = re.match(r"([a-z]+)(\\d+)$", key_l)
        if match:
            prefix, idx_raw = match.groups()
            idx = int(idx_raw)
        else:
            prefix, idx = key_l, 999
        prefix_rank = BOOT_DISK_PREFIXES.index(prefix) if prefix in BOOT_DISK_PREFIXES else 99
        candidates.append((prefix_rank, idx, key_s))

    if candidates:
        candidates.sort()
        return candidates[0][2]

    return None


def parse_disk_config_value(value: Optional[object]) -> Dict[str, Optional[str]]:
    if not value or not isinstance(value, str):
        return {"storage": None, "format": None, "volume": None}

    parts = [part.strip() for part in value.split(",") if part.strip()]
    main = parts[0] if parts else ""

    for part in parts:
        if part.startswith("file="):
            main = part.split("=", 1)[1]
            break
        if part.startswith("volume="):
            main = part.split("=", 1)[1]
            break

    storage = None
    volume = None
    if ":" in main:
        storage, volume = main.split(":", 1)
    elif main:
        volume = main

    fmt = None
    for part in parts:
        if part.startswith("format="):
            fmt = part.split("=", 1)[1].strip()
            break

    if not fmt and volume:
        ext = os.path.splitext(volume)[1].lower().lstrip(".")
        if ext in ("qcow2", "raw", "vmdk", "vhdx", "img"):
            fmt = ext
        elif ext == "":
            fmt = "raw"

    return {
        "storage": normalize_text(storage),
        "format": normalize_text(fmt),
        "volume": normalize_text(volume),
    }


def resolve_boot_disk_details(
    pve_type: str,
    config: Optional[dict],
    boot_disk: Optional[str],
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    if not boot_disk:
        return None, None, None
    config = config or {}

    disk_value: Optional[object] = None
    if pve_type == "qemu":
        disk_value = config.get(boot_disk)
    elif pve_type == "lxc":
        disk_value = boot_disk

    details = parse_disk_config_value(disk_value)
    return details.get("storage"), details.get("format"), details.get("volume")


def resolve_guest_agent_status(pve_type: str, config: Optional[dict]) -> Optional[str]:
    if pve_type != "qemu":
        return None
    config = config or {}
    enabled = parse_bool(config.get("agent"))
    if enabled is None:
        return None
    return "enabled" if enabled else "disabled"


def resolve_qemu_numa_status(pve_type: str, config: Optional[dict]) -> Optional[str]:
    if pve_type != "qemu":
        return None
    config = config or {}
    numa_enabled = parse_bool(config.get("numa"))
    if numa_enabled is None:
        return None
    return "enabled" if numa_enabled else "disabled"


def resolve_qemu_bios_type(pve_type: str, config: Optional[dict], vm: Optional[dict]) -> Optional[str]:
    if pve_type != "qemu":
        return None
    config = config or {}
    bios = normalize_text(config.get("bios") or (vm or {}).get("bios"))
    if bios:
        return bios
    # Infer default if not explicitly set
    for key in config.keys():
        if str(key).lower().startswith("efidisk"):
            return "ovmf"
    return "seabios"


def resolve_qemu_boot_order(pve_type: str, config: Optional[dict]) -> Optional[str]:
    if pve_type != "qemu":
        return None
    config = config or {}
    boot = normalize_text(config.get("boot"))
    if not boot:
        bootdisk = normalize_text(config.get("bootdisk"))
        if bootdisk:
            return bootdisk
        return None
    match = re.search(r"order=([^\\s]+)", boot)
    if match:
        return normalize_text(match.group(1))
    return boot


def resolve_qemu_machine_type(
    proxmox: Optional[ProxmoxAPI],
    node_name: Optional[str],
    vmid: Optional[int],
    pve_type: str,
    config: Optional[dict],
    vm: Optional[dict],
) -> Optional[str]:
    if pve_type != "qemu":
        return None
    config = config or {}
    machine = normalize_text(
        config.get("machine")
        or config.get("machine-type")
        or (vm or {}).get("machine")
        or (vm or {}).get("machine_type")
    )
    if machine:
        return machine

    args = config.get("args")
    machine = parse_machine_from_args(args)
    if machine:
        return machine

    if proxmox and node_name and vmid is not None:
        try:
            node_proxmox = get_node_proxmox(proxmox, node_name)
            status = node_proxmox.nodes(node_name).qemu(vmid).status.current.get()
            machine = normalize_text(status.get("machine"))
            if machine:
                return machine
        except Exception as exc:
            LOG.debug("Failed to fetch machine type from status.current for vmid=%s: %s", vmid, exc)

        try:
            node_proxmox = get_node_proxmox(proxmox, node_name)
            current_cfg = node_proxmox.nodes(node_name).qemu(vmid).config.get(current=1)
            machine = normalize_text(
                current_cfg.get("machine") or current_cfg.get("machine-type")
            )
            if machine:
                return machine
            machine = parse_machine_from_args(current_cfg.get("args"))
            if machine:
                return machine
        except Exception as exc:
            LOG.debug("Failed to fetch machine type from config current=1 for vmid=%s: %s", vmid, exc)

    return None


def parse_machine_from_args(args: Optional[object]) -> Optional[str]:
    if not args or not isinstance(args, str):
        return None
    # Match: -machine pc-q35-7.2 | -machine=pc-q35-7.2 | -M pc-q35-7.2 | -Mpc-q35-7.2
    match = re.search(r"(?:-machine\\s+|-machine=)([^\\s]+)", args)
    if match:
        return normalize_text(match.group(1))
    match = re.search(r"(?:-M\\s+|-M)([^\\s]+)", args)
    if match:
        return normalize_text(match.group(1))
    return None


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
    config: Optional[dict] = None,
):
    """
    Ensure VM has a vminterface with correct MAC/VLAN and assign IP addresses.

    VLANs are auto-created when needed.
    IPs come from qemu-guest-agent for QEMU guests.
    """
    # Get VM interface config (net0) from Proxmox
    if config is None:
        config = fetch_vm_config(proxmox, node_name, vmid, pve_type) or {}
    else:
        config = config or {}

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
        ip_obj = None

        # Skip network or broadcast addresses; NetBox rejects these on interfaces
        try:
            ip_addr = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(cidr, strict=False)
            is_network = ip_addr == network.network_address
            is_broadcast = (
                isinstance(network, ipaddress.IPv4Network)
                and ip_addr == network.broadcast_address
                and network.num_addresses > 1
            )
            if is_network or is_broadcast:
                LOG.warning(
                    "IP %s appears to be a %s address; skipping assignment to %s",
                    cidr,
                    "network" if is_network else "broadcast",
                    iface_name,
                )
                continue
        except ValueError as exc:
            LOG.warning("Invalid IP %s (%s); skipping", cidr, exc)
            continue

        # Try exact address match (may return multiple if duplicates exist)
        exact_candidates = list(nb.ipam.ip_addresses.filter(address=cidr))
        if exact_candidates:
            # Prefer one already on this interface, otherwise take the first
            ip_obj = next(
                (
                    c
                    for c in exact_candidates
                    if getattr(c, "assigned_object_type", None) == "virtualization.vminterface"
                    and getattr(c, "assigned_object_id", None) == iface.id
                ),
                exact_candidates[0],
            )
            if len(exact_candidates) > 1:
                LOG.warning(
                    "IP %s has %d records in NetBox; using id=%s and leaving others untouched",
                    cidr,
                    len(exact_candidates),
                    ip_obj.id,
                )

        # If not found with exact prefix, try to find any IP with the same host part
        if not ip_obj:
            candidates = []
            try:
                candidates = list(nb.ipam.ip_addresses.filter(q=ip))
            except RequestError as exc:
                status = getattr(getattr(exc, "req", None), "status_code", None)
                if status and 500 <= status < 600:
                    LOG.warning(
                        "NetBox returned %s while searching for IP host %s; skipping host match",
                        status,
                        ip,
                    )
                    candidates = []
                else:
                    raise

            for candidate in candidates:
                addr = getattr(candidate, "address", "")
                if addr and addr.split("/")[0] == ip:
                    ip_obj = candidate
                    break

        if not ip_obj:
            LOG.info("Creating IP %s and assigning to %s", cidr, iface_name)
            try:
                ip_obj = nb.ipam.ip_addresses.create(
                    {
                        "address": cidr,
                        "status": "active",
                        "assigned_object_type": "virtualization.vminterface",
                        "assigned_object_id": iface.id,
                    }
                )
            except RequestError as exc:
                err_str = str(getattr(exc, "error", exc))
                if "Duplicate IP address" in err_str:
                    LOG.warning(
                        "IP %s already exists in NetBox; leaving existing assignment untouched",
                        cidr,
                    )
                    continue
                status = getattr(getattr(exc, "req", None), "status_code", None)
                if status and 500 <= status < 600:
                    LOG.warning(
                        "NetBox returned %s while creating IP %s; skipping this IP and continuing",
                        status,
                        cidr,
                    )
                    continue
                raise
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
    vmid_map: Dict[int, object],
    vm_resource_map: Dict[int, dict],
    vm_cf_specs: Dict[str, Optional[List[dict]]],
    sync_timestamp: str,
) -> Tuple[Set[str], Set[int]]:
    """
    Sync all Proxmox VMs (QEMU + LXC) into NetBox virtualization.virtual_machines.

    We enumerate VMs per node:
      - /nodes/{node}/qemu
      - /nodes/{node}/lxc

    Returns (names_seen, vmids_seen) so deletion logic can be vmid-aware.
    """
    nodes = proxmox.nodes.get()
    total_vms = 0
    synced_vm_names: Set[str] = set()
    synced_vm_ids: Set[int] = set()

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
            name, vmid = sync_single_vm(
                nb=nb,
                proxmox=proxmox,
                vm=vm,
                node_name=node_name,
                host_device=host_device,
                cluster=cluster,
                pve_type="qemu",
                site=site,
                vmid_map=vmid_map,
                vm_resource_map=vm_resource_map,
                vm_cf_specs=vm_cf_specs,
                sync_timestamp=sync_timestamp,
            )
            synced_vm_names.add(name)
            synced_vm_ids.add(vmid)

        for vm in lxcs:
            total_vms += 1
            name, vmid = sync_single_vm(
                nb=nb,
                proxmox=proxmox,
                vm=vm,
                node_name=node_name,
                host_device=host_device,
                cluster=cluster,
                pve_type="lxc",
                site=site,
                vmid_map=vmid_map,
                vm_resource_map=vm_resource_map,
                vm_cf_specs=vm_cf_specs,
                sync_timestamp=sync_timestamp,
            )
            synced_vm_names.add(name)
            synced_vm_ids.add(vmid)

    LOG.info("Total Proxmox guests synced (QEMU + LXC): %d", total_vms)
    return synced_vm_names, synced_vm_ids


def sync_single_vm(
    nb,
    proxmox: ProxmoxAPI,
    vm: dict,
    node_name: str,
    host_device,
    cluster,
    pve_type: str,
    site,
    vmid_map: Dict[int, object],
    vm_resource_map: Dict[int, dict],
    vm_cf_specs: Dict[str, Optional[List[dict]]],
    sync_timestamp: str,
) -> Tuple[str, int]:
    """
    Create or update one NetBox Virtual Machine from a Proxmox VM/LXC dict
    and sync its interface + IPs.

    Prefers matching an existing NetBox VM by vmid (from comments) to avoid
    accidental deletion/duplication when names change.
    """
    vmid = vm["vmid"]
    name = vm.get("name") or f"vm-{vmid}"
    pve_status = vm.get("status", "stopped")

    config = fetch_vm_config(proxmox, node_name, vmid, pve_type)
    pool, pool_known, tags, tags_known = resolve_vm_pool_tags(
        vmid,
        vm,
        vm_resource_map,
        config,
    )

    tags_to_set: Optional[List[str]] = None
    if tags_known:
        if tags:
            ensured_tag_ids, unresolved = ensure_netbox_tags(nb, tags)
            if unresolved and not ensured_tag_ids:
                LOG.warning("Skipping tag sync for VM %s; unable to ensure tags", name)
            else:
                if unresolved and len(ensured_tag_ids) != len(tags):
                    LOG.warning(
                        "VM %s: some tags could not be ensured; syncing %d of %d",
                        name,
                        len(ensured_tag_ids),
                        len(tags),
                    )
                tags_to_set = ensured_tag_ids
        else:
            tags_to_set = []

    gw4_values, gw4_known, gw6_values, gw6_known = resolve_vm_gateways(pve_type, config)
    if (
        pve_type == "qemu"
        and env(GUEST_GW_FALLBACK_ENV, "true").lower() in ("1", "true", "yes")
    ):
        guest_gw4, guest_gw6 = fetch_guest_default_gateways(
            proxmox,
            node_name,
            vmid,
            pve_type,
        )
        if guest_gw4:
            gw4_values.extend(guest_gw4)
            gw4_known = True
        if guest_gw6:
            gw6_values.extend(guest_gw6)
            gw6_known = True
        if guest_gw4 or guest_gw6:
            LOG.debug(
                "VM %s: guest default gateways detected (v4=%s, v6=%s)",
                name,
                guest_gw4,
                guest_gw6,
            )

    def normalize_gateway_list(values: List[str], family: int, family_label: str) -> List[str]:
        normalized = []
        for raw in values:
            raw_value = (raw or "").strip()
            if not raw_value:
                continue
            try:
                addr = ipaddress.ip_address(raw_value)
            except ValueError:
                LOG.warning("VM %s: invalid gateway %s '%s'; skipping", name, family_label, raw_value)
                continue
            if addr.version != family:
                LOG.warning(
                    "VM %s: gateway %s '%s' has wrong IP family; skipping",
                    name,
                    family_label,
                    raw_value,
                )
                continue
            normalized.append(addr)

        if not normalized:
            return []

        return [str(addr) for addr in sorted(set(normalized))]

    gw4_list = normalize_gateway_list(gw4_values, 4, "IPv4")
    gw6_list = normalize_gateway_list(gw6_values, 6, "IPv6")
    gw4_value = ", ".join(gw4_list) if gw4_list else None
    gw6_value = ", ".join(gw6_list) if gw6_list else None

    vcpus, cores, sockets, cpu_type = resolve_vm_cpu_info(vm, config, pve_type)
    os_type = resolve_vm_os_type(proxmox, node_name, vmid, pve_type, vm, config)
    description = resolve_vm_description(vm, config)
    boot_disk = resolve_boot_disk(pve_type, config)
    boot_disk_storage, boot_disk_format, _boot_volume = resolve_boot_disk_details(
        pve_type, config, boot_disk
    )
    guest_agent_status = resolve_guest_agent_status(pve_type, config)
    qemu_numa_status = resolve_qemu_numa_status(pve_type, config)
    qemu_bios = resolve_qemu_bios_type(pve_type, config, vm)
    qemu_boot_order = resolve_qemu_boot_order(pve_type, config)
    qemu_machine = resolve_qemu_machine_type(proxmox, node_name, vmid, pve_type, config, vm)
    qemu_cpu_type = cpu_type if pve_type == "qemu" else None
    qemu_cores_per_socket = cores if pve_type == "qemu" else None

    memory_mb = bytes_to_mb(vm.get("maxmem", 0))
    disk_mb = get_vm_disk_mb(proxmox, node_name, vmid, pve_type, vm, config=config)  # decimal MB

    pool_cf = vm_cf_specs.get("pool")
    gw4_cf = vm_cf_specs.get("gateway4")
    gw6_cf = vm_cf_specs.get("gateway6")
    vmid_cf = vm_cf_specs.get("vmid")
    sockets_cf = vm_cf_specs.get("sockets")
    cores_cf = vm_cf_specs.get("cores")
    cpu_type_cf = vm_cf_specs.get("cpu_type")
    qemu_cpu_type_cf = vm_cf_specs.get("qemu_cpu_type")
    os_type_cf = vm_cf_specs.get("os_type")
    description_cf = vm_cf_specs.get("description")
    boot_disk_cf = vm_cf_specs.get("boot_disk")
    boot_disk_format_cf = vm_cf_specs.get("boot_disk_format")
    boot_disk_storage_cf = vm_cf_specs.get("boot_disk_storage")
    guest_agent_cf = vm_cf_specs.get("guest_agent")
    memory_cf = vm_cf_specs.get("memory_mb")
    vm_node_cf = vm_cf_specs.get("vm_node")
    vm_status_cf = vm_cf_specs.get("vm_status")
    vm_tags_cf = vm_cf_specs.get("vm_tags")
    cpu_sockets_cf = vm_cf_specs.get("cpu_sockets")
    qemu_cores_per_socket_cf = vm_cf_specs.get("qemu_cores_per_socket")
    qemu_numa_cf = vm_cf_specs.get("qemu_numa")
    qemu_bios_cf = vm_cf_specs.get("qemu_bios")
    qemu_boot_order_cf = vm_cf_specs.get("qemu_boot_order")
    qemu_machine_cf = vm_cf_specs.get("qemu_machine")
    last_sync_cf = vm_cf_specs.get("last_sync")

    custom_fields_data: Dict[str, object] = {}
    if pool_cf and pool_known:
        pool_value = pool if pool not in ("", None) else None
        set_custom_field_value(custom_fields_data, pool_cf, pool_value, include_if_none=True)
    if gw4_cf and gw4_known:
        set_custom_field_value(custom_fields_data, gw4_cf, gw4_value, include_if_none=True)
    if gw6_cf and gw6_known:
        set_custom_field_value(custom_fields_data, gw6_cf, gw6_value, include_if_none=True)

    set_custom_field_value(custom_fields_data, vmid_cf, vmid)
    set_custom_field_value(custom_fields_data, sockets_cf, sockets)
    set_custom_field_value(custom_fields_data, cpu_sockets_cf, sockets)
    set_custom_field_value(custom_fields_data, cores_cf, cores)
    set_custom_field_value(custom_fields_data, qemu_cores_per_socket_cf, qemu_cores_per_socket)
    set_custom_field_value(custom_fields_data, cpu_type_cf, cpu_type)
    set_custom_field_value(custom_fields_data, qemu_cpu_type_cf, qemu_cpu_type)
    set_custom_field_value(custom_fields_data, os_type_cf, os_type)
    set_custom_field_value(custom_fields_data, description_cf, description)
    set_custom_field_value(custom_fields_data, boot_disk_cf, boot_disk)
    set_custom_field_value(custom_fields_data, boot_disk_format_cf, boot_disk_format)
    set_custom_field_value(custom_fields_data, boot_disk_storage_cf, boot_disk_storage)
    set_custom_field_value(custom_fields_data, guest_agent_cf, guest_agent_status)
    set_custom_field_value(custom_fields_data, memory_cf, memory_mb)
    set_custom_field_value(custom_fields_data, vm_node_cf, node_name)
    set_custom_field_value(custom_fields_data, vm_status_cf, pve_status)
    if tags_known:
        tags_value = ", ".join(tags) if tags else None
        set_custom_field_value(custom_fields_data, vm_tags_cf, tags_value, include_if_none=True)
    set_custom_field_value(custom_fields_data, qemu_numa_cf, qemu_numa_status)
    set_custom_field_value(custom_fields_data, qemu_bios_cf, qemu_bios)
    set_custom_field_value(custom_fields_data, qemu_boot_order_cf, qemu_boot_order)
    set_custom_field_value(custom_fields_data, qemu_machine_cf, qemu_machine)
    set_custom_field_value(custom_fields_data, last_sync_cf, sync_timestamp)

    if not custom_fields_data:
        custom_fields_data = None

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
        # Try to reuse an existing NetBox VM that matches vmid in comments
        existing_by_vmid = vmid_map.pop(vmid, None)
        if existing_by_vmid:
            nb_vm = existing_by_vmid
            if nb_vm.name != name:
                LOG.info("Renaming NetBox VM %s -> %s based on vmid match", nb_vm.name, name)
                nb_vm.name = name

    if not nb_vm:
        LOG.info("Creating NetBox VM %s", name)
        create_data = {
            "name": name,
            "cluster": cluster.id,
            "status": status_slug,
            "vcpus": vcpus,
            "memory": memory_mb,
            "comments": comments,
        }
        if disk_mb:
            create_data["disk"] = disk_mb
        if site:
            create_data["site"] = site.id
        if host_device:
            create_data["device"] = host_device.id
        if tags_to_set is not None:
            create_data["tags"] = tags_to_set
        if custom_fields_data:
            create_data["custom_fields"] = custom_fields_data

        nb_vm = nb.virtualization.virtual_machines.create(create_data)
    else:
        LOG.info("Updating NetBox VM %s", name)
        nb_vm.status = status_slug
        nb_vm.vcpus = vcpus
        nb_vm.memory = memory_mb
        nb_vm.comments = comments
        nb_vm.cluster = cluster
        if site:
            nb_vm.site = site
        if host_device:
            nb_vm.device = host_device
        if tags_to_set is not None:
            nb_vm.tags = tags_to_set
        if custom_fields_data:
            merged_fields = dict(getattr(nb_vm, "custom_fields", {}) or {})
            merged_fields.update(custom_fields_data)
            nb_vm.custom_fields = merged_fields

        # Align disk with existing virtual disks if present; otherwise use computed.
        try:
            nb_disks = list(nb.virtualization.virtual_disks.filter(virtual_machine_id=nb_vm.id))
            nb_disk_sum = sum(int(getattr(d, "size", 0) or 0) for d in nb_disks)
        except Exception as exc:
            LOG.debug("Failed to fetch NetBox virtual disks for vm %s: %s", nb_vm.id, exc)
            nb_disk_sum = 0

        target_disk_mb = nb_disk_sum or disk_mb
        if target_disk_mb and (nb_vm.disk or 0) != target_disk_mb:
            nb_vm.disk = target_disk_mb

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
        config=config,
    )
    return name, vmid


# ---------------------------------------------------------------------------
# Full sync pruning
# ---------------------------------------------------------------------------

def delete_missing_netbox_vms(nb, cluster, keep_names: Set[str], keep_vm_ids: Set[int]):
    """
    Remove NetBox VMs in the target cluster that are absent from Proxmox.
    Keeps any VM whose name is seen OR whose vmid (parsed from comments) is seen.
    """
    cluster_label = getattr(cluster, "name", getattr(cluster, "id", cluster))
    cluster_vms = list(nb.virtualization.virtual_machines.filter(cluster_id=cluster.id))
    to_delete = []
    for vm in cluster_vms:
        if vm.name in keep_names:
            continue
        vmid = extract_vmid_from_comments(getattr(vm, "comments", ""))
        if vmid is not None and vmid in keep_vm_ids:
            # Matched by vmid; keep it (name likely changed and was reused above)
            continue
        to_delete.append(vm)

    if not to_delete:
        LOG.info("Full sync: no NetBox VMs to delete in cluster %s", cluster_label)
        return

    LOG.info(
        "Full sync: deleting %d NetBox VMs not present in Proxmox",
        len(to_delete),
    )
    for vm in to_delete:
        LOG.info("Deleting NetBox VM %s (id=%s)", vm.name, vm.id)
        try:
            vm.delete()
        except RequestError as exc:
            LOG.error(
                "Failed to delete NetBox VM %s (id=%s): %s",
                vm.name,
                vm.id,
                exc,
            )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    if env(GUEST_GW_FALLBACK_ENV) is None:
        env_file = env("PVE_ENV_FILE", "netbox_pve_env.sh")
        ensure_env_file_setting(env_file, GUEST_GW_FALLBACK_ENV, "true")

    sync_mode = select_sync_mode()
    delete_missing = sync_mode == "full"

    proxmox = connect_proxmox()
    nb = connect_netbox()

    cluster = get_nb_cluster(nb)
    site = get_nb_site(nb)
    role = get_nb_device_role(nb)
    dtype = get_nb_device_type(nb)
    vm_cf_specs = resolve_vm_custom_field_specs(nb)
    sync_timestamp = format_sync_timestamp()
    vm_resource_map = build_vm_resource_map(proxmox)

    vmid_map = map_netbox_vms_by_vmid(nb, cluster)
    node_devices = ensure_node_devices(nb, proxmox, site, role, dtype, cluster)
    synced_vm_names, synced_vm_ids = sync_vms(
        nb,
        proxmox,
        cluster,
        node_devices,
        site,
        vmid_map,
        vm_resource_map,
        vm_cf_specs,
        sync_timestamp,
    )

    if delete_missing:
        delete_missing_netbox_vms(nb, cluster, synced_vm_names, synced_vm_ids)


if __name__ == "__main__":
    main()
