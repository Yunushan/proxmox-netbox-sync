#!/usr/bin/env python3
import os
import logging
import ipaddress
import socket
import re
import json
import csv
import base64
import binascii
import time
from functools import lru_cache
from urllib.parse import urlsplit, urlunsplit
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


@lru_cache(maxsize=None)
def resolve_node_ilo_details(node_name: str) -> Tuple[str, Optional[int]]:
    node_map = parse_node_host_map(env(NODE_ILO_MAP_ENV))
    if node_name in node_map:
        return node_map[node_name]
    node_key = (node_name or "").strip().lower()
    if node_key in node_map:
        return node_map[node_key]

    npm_map = get_npm_ilo_host_map()
    if node_name in npm_map:
        return npm_map[node_name]
    if node_key in npm_map:
        return npm_map[node_key]

    template = env(NODE_ILO_TEMPLATE_ENV)
    if template:
        host_value = template.format(node=node_name)
        return split_host_port(host_value)

    prefix_raw = env(NODE_ILO_PREFIX_ENV)
    suffix_raw = env(NODE_ILO_SUFFIX_ENV)
    if prefix_raw is not None or suffix_raw is not None:
        prefix = "ilo-" if prefix_raw is None else (prefix_raw or "")
        suffix = suffix_raw or ""
        if prefix or suffix:
            host_value = f"{prefix}{node_name}{suffix}"
            return split_host_port(host_value)

    for candidate in build_auto_node_ilo_candidates(node_name):
        if resolve_host_primary_ip(candidate):
            return candidate, None

    return "", None


def normalize_domain_suffix(value: Optional[str]) -> Optional[str]:
    raw = (value or "").strip().strip(".").lower()
    if not raw or "." not in raw:
        return None
    return raw


def domain_suffix_from_host(value: Optional[str]) -> Optional[str]:
    host, _ = split_host_port(value or "")
    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return None
    except ValueError:
        pass

    if "." not in host:
        return None
    return normalize_domain_suffix(host.split(".", 1)[1])


def parse_domain_suffix_list(raw_value: Optional[str]) -> List[str]:
    if not raw_value:
        return []
    values: List[str] = []
    for chunk in re.split(r"[,\s;]+", raw_value.strip()):
        suffix = normalize_domain_suffix(chunk)
        if suffix:
            values.append(suffix)
    return values


@lru_cache(maxsize=1)
def get_resolver_search_domains() -> List[str]:
    paths = ["/etc/resolv.conf"]
    domains: List[str] = []
    seen: Set[str] = set()

    for path in paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8") as handle:
                lines = handle.readlines()
        except OSError:
            continue

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            tokens = line.split()
            if len(tokens) < 2:
                continue

            keyword = tokens[0].lower()
            if keyword not in ("search", "domain"):
                continue

            for token in tokens[1:]:
                suffix = normalize_domain_suffix(token)
                if not suffix or suffix in seen:
                    continue
                seen.add(suffix)
                domains.append(suffix)

    return domains


@lru_cache(maxsize=1)
def collect_auto_ilo_domain_suffixes() -> List[str]:
    domains: List[str] = []
    seen: Set[str] = set()

    def add_suffix(value: Optional[str]) -> None:
        suffix = normalize_domain_suffix(value)
        if not suffix or suffix in seen:
            return
        seen.add(suffix)
        domains.append(suffix)

    for suffix in parse_domain_suffix_list(env(NODE_ILO_DOMAIN_SUFFIXES_ENV)):
        add_suffix(suffix)

    host_suffix = env("PVE_NODE_HOST_SUFFIX")
    if host_suffix:
        add_suffix(host_suffix.lstrip("."))

    add_suffix(domain_suffix_from_host(env("PVE_HOST")))

    host_map = parse_node_host_map(env("PVE_NODE_HOST_MAP"))
    for host, _ in host_map.values():
        add_suffix(domain_suffix_from_host(host))

    host_template = env("PVE_NODE_HOST_TEMPLATE")
    if host_template:
        try:
            sample = host_template.format(node="node")
        except Exception:
            sample = host_template
        add_suffix(domain_suffix_from_host(sample))

    fqdn = socket.getfqdn()
    add_suffix(domain_suffix_from_host(fqdn))

    for suffix in get_resolver_search_domains():
        add_suffix(suffix)

    return domains


def build_auto_node_ilo_candidates(node_name: str) -> List[str]:
    node = (node_name or "").strip().lower()
    if not node:
        return []

    candidates: List[str] = []
    seen: Set[str] = set()

    def add_candidate(host: str) -> None:
        candidate = (host or "").strip().lower()
        if not candidate or candidate in seen:
            return
        seen.add(candidate)
        candidates.append(candidate)

    base_node = node
    node_domain = None
    if "." in node:
        base_node, node_domain = node.split(".", 1)
        add_candidate(f"ilo-{node}")

    if base_node:
        if node_domain:
            add_candidate(f"ilo-{base_node}.{node_domain}")

        for suffix in collect_auto_ilo_domain_suffixes():
            add_candidate(f"ilo-{base_node}.{suffix}")

        add_candidate(f"ilo-{base_node}")

    return candidates


def parse_env_assignment_value(line: str) -> str:
    if "=" not in line:
        return ""

    _, raw_value = line.split("=", 1)
    value = raw_value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
        value = value[1:-1]
    return value.strip()


def ensure_env_file_setting(
    env_file: Optional[str],
    key: str,
    value: str,
    replace_blank: bool = False,
) -> None:
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

    pattern = re.compile(rf"^\s*(export\s+)?{re.escape(key)}=", re.MULTILINE)
    lines = contents.splitlines(keepends=True)
    for idx, line in enumerate(lines):
        if not pattern.match(line):
            continue

        if not replace_blank or parse_env_assignment_value(line):
            return

        newline = "\n" if line.endswith("\n") else ""
        lines[idx] = f'export {key}="{value}"{newline}'
        try:
            with open(env_file, "w", encoding="utf-8") as handle:
                handle.write("".join(lines))
            LOG.info("Updated blank %s in %s to %r", key, env_file, value)
        except OSError as exc:
            LOG.warning("Failed to update env file %s with %s: %s", env_file, key, exc)
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
NODE_ILO_SYNC_ENV = "PVE_NODE_ILO_SYNC"
NODE_ILO_MAP_ENV = "PVE_NODE_ILO_MAP"
NODE_ILO_TEMPLATE_ENV = "PVE_NODE_ILO_TEMPLATE"
NODE_ILO_PREFIX_ENV = "PVE_NODE_ILO_PREFIX"
NODE_ILO_SUFFIX_ENV = "PVE_NODE_ILO_SUFFIX"
NODE_ILO_INTERFACE_ENV = "PVE_NODE_ILO_INTERFACE"
NODE_ILO_SET_PRIMARY_ENV = "PVE_NODE_ILO_SET_PRIMARY"
NODE_ILO_NPM_URL_ENV = "PVE_NODE_ILO_NPM_URL"
NODE_ILO_NPM_TOKEN_ENV = "PVE_NODE_ILO_NPM_TOKEN"
NODE_ILO_NPM_USERNAME_ENV = "PVE_NODE_ILO_NPM_USERNAME"
NODE_ILO_NPM_PASSWORD_ENV = "PVE_NODE_ILO_NPM_PASSWORD"
NODE_ILO_NPM_VERIFY_SSL_ENV = "PVE_NODE_ILO_NPM_VERIFY_SSL"
NODE_ILO_NPM_PREFIX_ENV = "PVE_NODE_ILO_NPM_PREFIX"
NODE_ILO_DOMAIN_SUFFIXES_ENV = "PVE_NODE_ILO_DOMAIN_SUFFIXES"
IP_BLOCK_REPORT_ENV = "PVE_NB_IP_BLOCK_REPORT"
IP_BLOCK_REPORT_PATH_ENV = "PVE_NB_IP_BLOCK_REPORT_PATH"
PREFIX_SYNC_ENV = "PVE_NB_PREFIX_SYNC"
PVE_API_TIMEOUT_ENV = "PVE_API_TIMEOUT"
FORTI_PUBLIC_IP_SYNC_ENV = "PVE_FORTI_PUBLIC_IP_SYNC"
FORTI_URL_ENV = "PVE_FORTI_URL"
FORTI_API_TOKEN_ENV = "PVE_FORTI_API_TOKEN"
FORTI_USERNAME_ENV = "PVE_FORTI_USERNAME"
FORTI_PASSWORD_ENV = "PVE_FORTI_PASSWORD"
FORTI_VERIFY_SSL_ENV = "PVE_FORTI_VERIFY_SSL"
FORTI_VDOM_ENV = "PVE_FORTI_VDOM"
FORTI_TIMEOUT_ENV = "PVE_FORTI_TIMEOUT"
FORTI_WAN_INTERFACES_ENV = "PVE_FORTI_WAN_INTERFACES"
FORTI_MAX_RANGE_EXPANSION_ENV = "PVE_FORTI_MAX_RANGE_EXPANSION"
NB_FORTI_DEVICE_ENV = "NB_FORTI_DEVICE"
NB_FORTI_INTERFACE_ENV = "NB_FORTI_INTERFACE"
NB_FORTI_SET_PRIMARY_ENV = "NB_FORTI_SET_PRIMARY"
NB_FORTI_SET_PRIMARY6_ENV = "NB_FORTI_SET_PRIMARY6"
NB_PREFIX_ROLE_ENV = "NB_PREFIX_ROLE_SLUG"
NB_VLAN_ROLE_ENV = "NB_VLAN_ROLE_SLUG"
DEFAULT_NB_PREFIX_ROLE_SLUG = "proxmox-prefix"
DEFAULT_NB_VLAN_ROLE_SLUG = "proxmox-vlan"


PREFIX_SYNC_DISABLED_REASON: Optional[str] = None


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
    timeout_raw = env(PVE_API_TIMEOUT_ENV, "60")
    timeout_s = parse_int(timeout_raw)
    if timeout_s is None or timeout_s < 1:
        LOG.warning(
            "Invalid %s=%r; using default timeout 60s",
            PVE_API_TIMEOUT_ENV,
            timeout_raw,
        )
        timeout_s = 60

    if port_override is not None:
        port = port_override

    LOG.info("Connecting to Proxmox at %s as %s (timeout=%ss)", host, user, timeout_s)

    proxmox_kwargs = {
        "user": user,
        "token_name": token_name,
        "token_value": token_value,
        "verify_ssl": verify_ssl,
        "service": "PVE",
        "timeout": timeout_s,
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


def build_netbox_api_root_url() -> str:
    raw_url = (env("NB_URL", required=True) or "").strip()
    parts = urlsplit(raw_url)
    path = (parts.path or "").rstrip("/")
    if not path.endswith("/api"):
        path = f"{path}/api" if path else "/api"
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def netbox_api_request(
    nb,
    method: str,
    path: str,
    params: Optional[dict] = None,
    payload: Optional[dict] = None,
) -> Optional[object]:
    session = getattr(nb, "http_session", None) or requests.Session()
    headers = {
        "Accept": "application/json",
        "Authorization": f"Token {env('NB_TOKEN', required=True)}",
    }
    if payload is not None:
        headers["Content-Type"] = "application/json"

    url = f"{build_netbox_api_root_url().rstrip('/')}/{path.lstrip('/')}"
    response = session.request(method, url, headers=headers, params=params, json=payload, timeout=30)
    response.raise_for_status()

    if response.status_code == 204:
        return None

    body = response.text.strip()
    if not body:
        return None

    try:
        return response.json()
    except ValueError:
        return None


def extract_netbox_results(payload: object) -> List[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        results = payload.get("results")
        if isinstance(results, list):
            return [item for item in results if isinstance(item, dict)]

        if all(key in payload for key in ("id", "name", "slug")):
            return [payload]

    return []


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


def format_slug_label(value: str) -> str:
    text = re.sub(r"[-_]+", " ", (value or "").strip())
    text = re.sub(r"\s+", " ", text).strip()
    return text.title() if text else ""


def resolve_default_ipam_role_slug(env_var: str, default_slug: str) -> Optional[str]:
    raw_value = os.environ.get(env_var)
    if raw_value is not None:
        normalized = raw_value.strip()
        if normalized.lower() in ("off", "false", "disable", "disabled", "none", "no"):
            LOG.info("Skipping NetBox IPAM role sync for %s: explicitly disabled (%s)", env_var, normalized)
            return None
        if normalized:
            return normalized

    env_file = env("PVE_ENV_FILE", "netbox_pve_env.sh")
    ensure_env_file_setting(env_file, env_var, default_slug, replace_blank=True)
    os.environ[env_var] = default_slug
    LOG.info("Defaulting %s to %s", env_var, default_slug)
    return default_slug


def get_nb_ipam_role_by_slug(nb, role_slug: str) -> Optional[object]:
    endpoint = getattr(getattr(nb, "ipam", None), "roles", None)
    if endpoint is not None:
        try:
            role = endpoint.get(slug=role_slug)
        except RequestError as exc:
            LOG.debug("Pynetbox IPAM role lookup failed for slug=%s: %s", role_slug, exc)
        except Exception as exc:
            LOG.debug("Unexpected pynetbox IPAM role lookup failure for slug=%s: %s", role_slug, exc)
        else:
            if role:
                return role

        try:
            matches = list(endpoint.filter(slug=role_slug))
        except RequestError as exc:
            LOG.debug("Pynetbox IPAM role filter failed for slug=%s: %s", role_slug, exc)
        except Exception as exc:
            LOG.debug("Unexpected pynetbox IPAM role filter failure for slug=%s: %s", role_slug, exc)
        else:
            if matches:
                return matches[0]

    try:
        payload = netbox_api_request(nb, "GET", "/ipam/roles/", params={"slug": role_slug, "limit": 2})
    except requests.RequestException as exc:
        LOG.debug("Direct NetBox IPAM role lookup failed for slug=%s: %s", role_slug, exc)
        return None

    matches = extract_netbox_results(payload)
    return matches[0] if matches else None


def create_nb_ipam_role(nb, role_name: str, role_slug: str) -> Optional[object]:
    endpoint = getattr(getattr(nb, "ipam", None), "roles", None)
    if endpoint is not None:
        try:
            role = endpoint.create({"name": role_name, "slug": role_slug})
        except RequestError as exc:
            err_text = str(getattr(exc, "error", exc))
            if request_error_status_code(exc) in (400, 409) or "duplicate" in err_text.lower():
                role = get_nb_ipam_role_by_slug(nb, role_slug)
                if role:
                    return role
            LOG.debug("Pynetbox IPAM role create failed for slug=%s: %s", role_slug, exc)
        except Exception as exc:
            LOG.debug("Unexpected pynetbox IPAM role create failure for slug=%s: %s", role_slug, exc)
        else:
            if role:
                return role

    try:
        payload = netbox_api_request(
            nb,
            "POST",
            "/ipam/roles/",
            payload={"name": role_name, "slug": role_slug},
        )
    except requests.RequestException as exc:
        LOG.debug("Direct NetBox IPAM role create failed for slug=%s: %s", role_slug, exc)
    else:
        matches = extract_netbox_results(payload)
        if matches:
            return matches[0]
        if isinstance(payload, dict) and payload:
            return payload

    return get_nb_ipam_role_by_slug(nb, role_slug)


def ensure_nb_ipam_role(nb, env_var: str) -> Optional[object]:
    default_slug = DEFAULT_NB_PREFIX_ROLE_SLUG if env_var == NB_PREFIX_ROLE_ENV else DEFAULT_NB_VLAN_ROLE_SLUG
    role_slug_raw = resolve_default_ipam_role_slug(env_var, default_slug)
    if not role_slug_raw:
        return None

    role_slug = slugify_tag(role_slug_raw)
    if not role_slug:
        LOG.warning(
            "Skipping NetBox IPAM role sync for %s: value %r does not contain a valid slug",
            env_var,
            role_slug_raw,
        )
        return None

    role_name = format_slug_label(role_slug_raw) or format_slug_label(role_slug) or role_slug
    role = get_nb_ipam_role_by_slug(nb, role_slug)
    if not role:
        LOG.info("Creating NetBox IPAM role %s (slug=%s)", role_name, role_slug)
        role = create_nb_ipam_role(nb, role_name, role_slug)

    if role:
        LOG.info(
            "Ensured NetBox IPAM role %s (slug=%s, id=%s) for %s",
            role_name,
            role_slug,
            get_related_object_id(role),
            env_var,
        )
        return role

    LOG.warning(
        "Failed to ensure NetBox IPAM role %s (slug=%s) for %s; continuing without role sync",
        role_name,
        role_slug,
        env_var,
    )
    return None


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


def request_error_status_code(exc: RequestError) -> Optional[int]:
    req = getattr(exc, "req", None)
    status = getattr(req, "status_code", None)
    if status is not None:
        try:
            return int(status)
        except (TypeError, ValueError):
            pass

    match = re.search(r"\bcode\s+(\d{3})\b", str(exc))
    if match:
        try:
            return int(match.group(1))
        except (TypeError, ValueError):
            return None
    return None


def is_retryable_netbox_error(exc: RequestError) -> bool:
    status = request_error_status_code(exc)
    return bool(status and 500 <= status < 600)


def save_netbox_object_with_retry(obj, context: str, max_attempts: int = 3) -> None:
    for attempt in range(1, max_attempts + 1):
        try:
            obj.save()
            return
        except RequestError as exc:
            if not is_retryable_netbox_error(exc):
                raise

            status = request_error_status_code(exc) or "5xx"
            if attempt >= max_attempts:
                LOG.error(
                    "NetBox returned %s while %s after %d attempts",
                    status,
                    context,
                    max_attempts,
                )
                raise

            delay_s = min(5.0, 1.5 * attempt)
            LOG.warning(
                "NetBox returned %s while %s (attempt %d/%d); retrying in %.1fs",
                status,
                context,
                attempt,
                max_attempts,
                delay_s,
            )
            time.sleep(delay_s)


def build_npm_api_base(url: str) -> str:
    base = (url or "").strip().rstrip("/")
    if not base:
        return ""
    if base.endswith("/api"):
        return base
    return f"{base}/api"


def parse_npm_domain_names(raw_value: Optional[object]) -> List[str]:
    values: List[str] = []
    if raw_value is None:
        return values

    if isinstance(raw_value, (list, tuple, set)):
        values = [str(v).strip() for v in raw_value if v is not None and str(v).strip()]
    elif isinstance(raw_value, str):
        text = raw_value.strip()
        if not text:
            return []

        parsed_json = None
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed_json = json.loads(text)
            except ValueError:
                parsed_json = None
        if isinstance(parsed_json, list):
            values = [str(v).strip() for v in parsed_json if v is not None and str(v).strip()]
        else:
            values = [chunk.strip() for chunk in re.split(r"[,\s]+", text) if chunk.strip()]
    else:
        values = [str(raw_value).strip()]

    seen: Set[str] = set()
    normalized: List[str] = []
    for value in values:
        clean = value.strip().strip(".").lower()
        if not clean or clean in seen:
            continue
        seen.add(clean)
        normalized.append(clean)
    return normalized


def parse_node_from_ilo_domain(domain: str, prefix: str) -> Optional[str]:
    clean = (domain or "").strip().strip(".").lower()
    if not clean:
        return None

    first_label = clean.split(".", 1)[0]
    pref = (prefix or "ilo-").strip().lower()
    if not pref:
        pref = "ilo-"
    if not first_label.startswith(pref):
        return None

    node = first_label[len(pref) :].strip()
    return node or None


def parse_npm_proxy_hosts_response(payload: object) -> List[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        for key in ("data", "result", "results", "items"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    return []


def extract_npm_token(payload: object) -> Optional[str]:
    if isinstance(payload, str):
        token = payload.strip()
        return token or None

    if isinstance(payload, dict):
        for key in ("token", "access_token", "jwt"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

        data = payload.get("data")
        if isinstance(data, dict):
            for key in ("token", "access_token", "jwt"):
                value = data.get(key)
                if isinstance(value, str) and value.strip():
                    return value.strip()

    return None


def rank_ilo_target(host: str, port: Optional[int]) -> Tuple[int, int]:
    resolved = resolve_host_primary_ip(host) or host
    scope_rank = 3
    try:
        addr = ipaddress.ip_address(resolved)
        if addr.is_private:
            scope_rank = 0
        elif addr.is_loopback or addr.is_link_local:
            scope_rank = 1
        elif addr.is_global:
            scope_rank = 2
        else:
            scope_rank = 3
    except ValueError:
        scope_rank = 3

    port_rank = 0 if port is not None else 1
    return scope_rank, port_rank


def should_replace_ilo_target(
    current: Tuple[str, Optional[int]],
    candidate: Tuple[str, Optional[int]],
) -> bool:
    return rank_ilo_target(*candidate) < rank_ilo_target(*current)


@lru_cache(maxsize=1)
def get_npm_ilo_host_map() -> Dict[str, Tuple[str, Optional[int]]]:
    url = env(NODE_ILO_NPM_URL_ENV)
    if not url:
        return {}

    api_base = build_npm_api_base(url)
    if not api_base:
        return {}

    verify = parse_bool(env(NODE_ILO_NPM_VERIFY_SSL_ENV, "false"))
    if verify is None:
        verify = False

    prefix = (env(NODE_ILO_NPM_PREFIX_ENV, "ilo-") or "ilo-").strip().lower()
    if not prefix:
        prefix = "ilo-"

    session = requests.Session()
    session.verify = verify

    token = env(NODE_ILO_NPM_TOKEN_ENV)
    username = env(NODE_ILO_NPM_USERNAME_ENV)
    password = env(NODE_ILO_NPM_PASSWORD_ENV)

    if not token and username and password:
        try:
            response = session.post(
                f"{api_base}/tokens",
                json={"identity": username, "secret": password},
                timeout=20,
            )
            response.raise_for_status()
            token = extract_npm_token(response.json())
        except Exception as exc:
            LOG.warning("Failed to authenticate to NPM API at %s: %s", api_base, exc)
            token = None

    if token:
        session.headers.update({"Authorization": f"Bearer {token}"})

    hosts: List[dict] = []
    try:
        response = session.get(f"{api_base}/nginx/proxy-hosts", timeout=30)
        response.raise_for_status()
        hosts = parse_npm_proxy_hosts_response(response.json())
    except Exception as exc:
        LOG.warning("Failed to read NPM proxy hosts from %s: %s", api_base, exc)
        return {}

    mapping: Dict[str, Tuple[str, Optional[int]]] = {}
    for host_data in hosts:
        forward_host_raw = (
            host_data.get("forward_host")
            or host_data.get("forward_hostname")
            or host_data.get("forward_domain")
        )
        if not forward_host_raw:
            continue

        forward_host, inline_port = split_host_port(str(forward_host_raw))
        if not forward_host:
            continue

        forward_port = parse_int(host_data.get("forward_port"))
        if forward_port is None:
            forward_port = inline_port

        domain_names = parse_npm_domain_names(
            host_data.get("domain_names")
            or host_data.get("domain_name")
            or host_data.get("domain")
        )
        if not domain_names:
            continue

        for domain in domain_names:
            node_key = parse_node_from_ilo_domain(domain, prefix)
            if not node_key:
                continue
            candidate = (forward_host, forward_port)
            current = mapping.get(node_key)
            if not current or should_replace_ilo_target(current, candidate):
                mapping[node_key] = candidate

    if mapping:
        LOG.info("Loaded %d iLO mappings from NPM proxy hosts", len(mapping))

    return mapping


def should_sync_node_ilo() -> bool:
    explicit = parse_bool(env(NODE_ILO_SYNC_ENV))
    if explicit is not None:
        return explicit

    return True


def has_explicit_node_ilo_mapping() -> bool:
    return any(
        env(var)
        for var in (
            NODE_ILO_MAP_ENV,
            NODE_ILO_TEMPLATE_ENV,
            NODE_ILO_PREFIX_ENV,
            NODE_ILO_SUFFIX_ENV,
            NODE_ILO_NPM_URL_ENV,
            NODE_ILO_DOMAIN_SUFFIXES_ENV,
        )
    )


FORTI_IPV4_RE = re.compile(
    r"\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b"
)


class FortiAPIError(RuntimeError):
    def __init__(self, message: str, status_code: Optional[int] = None):
        super().__init__(message)
        self.status_code = status_code


def forti_error_status_code(exc: Exception) -> Optional[int]:
    if isinstance(exc, FortiAPIError):
        return exc.status_code

    response = getattr(exc, "response", None)
    if response is not None:
        return parse_int(getattr(response, "status_code", None))
    return None


def is_forti_auth_error(exc: Exception) -> bool:
    status = forti_error_status_code(exc)
    if status in (401, 403):
        return True

    message = str(exc).strip().lower()
    return "logincheck" in message or "authentication rejected" in message


def is_forti_unauthorized(exc: Exception) -> bool:
    status = forti_error_status_code(exc)
    if status == 401:
        return True

    message = str(exc).strip().lower()
    return "logincheck" in message or "authentication rejected" in message


def is_forti_forbidden(exc: Exception) -> bool:
    return forti_error_status_code(exc) == 403


def should_sync_forti_public_ip() -> bool:
    enabled = parse_bool(env(FORTI_PUBLIC_IP_SYNC_ENV, "false"))
    return bool(enabled)


def parse_forti_interface_names(raw_value: Optional[str]) -> List[str]:
    if not raw_value:
        return []
    values = [chunk.strip().lower() for chunk in re.split(r"[,\s;]+", raw_value) if chunk.strip()]
    seen: Set[str] = set()
    normalized: List[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def parse_forti_result_items(payload: object) -> List[dict]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if isinstance(payload, dict):
        for key in ("results", "result", "items", "data", "interfaces", "entries"):
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            if isinstance(value, dict):
                nested = parse_forti_result_items(value)
                if nested:
                    return nested
                if any(k in value for k in ("name", "interface", "ifname")):
                    return [value]

        if any(k in payload for k in ("name", "interface", "ifname")):
            return [payload]

    return []


def build_forti_api_client() -> Optional[dict]:
    base_url = (env(FORTI_URL_ENV, "") or "").strip().rstrip("/")
    if not base_url:
        LOG.warning(
            "Skipping Forti public IP sync: %s is enabled but %s is empty",
            FORTI_PUBLIC_IP_SYNC_ENV,
            FORTI_URL_ENV,
        )
        return None

    verify = parse_bool(env(FORTI_VERIFY_SSL_ENV, "false"))
    if verify is None:
        verify = False

    timeout_s = parse_int(env(FORTI_TIMEOUT_ENV, "20"))
    if timeout_s is None or timeout_s <= 0:
        timeout_s = 20

    token = normalize_text(env(FORTI_API_TOKEN_ENV))
    username = normalize_text(env(FORTI_USERNAME_ENV))
    password = env(FORTI_PASSWORD_ENV)
    password_text = normalize_text(password)

    strategies: List[str] = []
    if token:
        strategies.extend(["token_header", "token_query"])
    if username and password_text:
        strategies.append("session")

    if not strategies:
        LOG.warning(
            "Skipping Forti public IP sync: set %s or %s+%s",
            FORTI_API_TOKEN_ENV,
            FORTI_USERNAME_ENV,
            FORTI_PASSWORD_ENV,
        )
        return None

    session = requests.Session()
    session.verify = verify
    return {
        "base_url": base_url,
        "timeout": timeout_s,
        "token": token,
        "username": username,
        "password": password_text,
        "session": session,
        "strategies": strategies,
        "active_strategy": None,
        "session_logged_in": False,
    }


def forti_api_login_with_session(client: dict) -> None:
    if client.get("session_logged_in"):
        return

    username = client.get("username")
    password = client.get("password")
    if not username or not password:
        raise FortiAPIError("Forti username/password are not configured for session login")

    session = client["session"]
    timeout_s = client["timeout"]
    url = f"{client['base_url']}/logincheck"
    response = session.post(
        url,
        data={"username": username, "secretkey": password, "ajax": "1"},
        timeout=timeout_s,
    )
    if response.status_code >= 400:
        raise FortiAPIError(
            f"Forti login failed with HTTP {response.status_code}",
            status_code=response.status_code,
        )

    body = (response.text or "").strip().lower()
    if body and not body.startswith("1") and "success" not in body:
        raise FortiAPIError(
            (
                "Forti session logincheck rejected the configured username/password. "
                f"Verify {FORTI_USERNAME_ENV}/{FORTI_PASSWORD_ENV}, trusted-host restrictions, "
                f"or set {FORTI_API_TOKEN_ENV} for token-based REST API access."
            ),
            status_code=401,
        )

    csrf = session.cookies.get("ccsrftoken")
    if csrf:
        session.headers.update({"X-CSRFTOKEN": csrf.strip('"')})

    client["session_logged_in"] = True


def forti_api_get_with_strategy(
    client: dict,
    path: str,
    params: Optional[dict],
    strategy: str,
) -> object:
    session = client["session"]
    timeout_s = client["timeout"]
    url = f"{client['base_url']}{path}"
    query = dict(params or {})
    headers: Dict[str, str] = {}

    if strategy == "token_header":
        token = client.get("token")
        if not token:
            raise FortiAPIError("Forti token is not configured for bearer authentication")
        headers["Authorization"] = f"Bearer {token}"
    elif strategy == "token_query":
        token = client.get("token")
        if not token:
            raise FortiAPIError("Forti token is not configured for query authentication")
        query["access_token"] = token
    elif strategy == "session":
        forti_api_login_with_session(client)
    else:
        raise FortiAPIError(f"Unsupported Forti auth strategy: {strategy}")

    response = session.get(url, params=query, headers=headers or None, timeout=timeout_s)
    if response.status_code in (401, 403):
        raise FortiAPIError(
            f"Forti authentication rejected request ({response.status_code})",
            status_code=response.status_code,
        )
    if response.status_code >= 400:
        raise FortiAPIError(
            f"Forti API request failed with HTTP {response.status_code}",
            status_code=response.status_code,
        )

    try:
        payload = response.json()
    except ValueError as exc:
        raise FortiAPIError(
            f"Forti API did not return JSON for {path}",
            status_code=response.status_code,
        ) from exc

    if isinstance(payload, dict):
        status_raw = str(payload.get("status", "")).strip().lower()
        if status_raw == "error":
            http_status = parse_int(payload.get("http_status"))
            error_detail = (
                payload.get("message")
                or payload.get("error")
                or payload.get("error_msg")
                or payload.get("status")
                or "unknown error"
            )
            raise FortiAPIError(
                f"Forti API error on {path}: {error_detail}",
                status_code=http_status or response.status_code,
            )

    return payload


def forti_api_get_json(client: dict, path: str, params: Optional[dict] = None) -> object:
    strategies: List[str] = list(client.get("strategies") or [])
    active = client.get("active_strategy")

    attempts: List[str] = []
    if active:
        attempts.append(active)
    for strategy in strategies:
        if strategy not in attempts:
            attempts.append(strategy)

    if not attempts:
        raise FortiAPIError("No Forti authentication strategies available")

    last_exc: Optional[Exception] = None
    for strategy in attempts:
        try:
            payload = forti_api_get_with_strategy(client, path, params, strategy)
            client["active_strategy"] = strategy
            return payload
        except Exception as exc:
            last_exc = exc
            status = forti_error_status_code(exc)
            if status == 401:
                LOG.debug("Forti auth strategy '%s' failed with HTTP %s", strategy, status)
                continue
            raise

    if last_exc:
        raise last_exc
    raise FortiAPIError(f"Forti API request failed for {path}")


def parse_ip_values(raw_value: Optional[object], family: int) -> List[str]:
    values: List[str] = []
    seen: Set[str] = set()
    expected_type = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address

    def add_ip(value: str) -> bool:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        if not isinstance(addr, expected_type):
            return False
        if addr.is_unspecified:
            return False
        text = str(addr)
        if text in seen:
            return True
        seen.add(text)
        values.append(text)
        return True

    def walk(value: Optional[object]) -> None:
        if value is None:
            return

        if isinstance(value, str):
            text = value.strip()
            if not text:
                return
            tokens = re.split(r"[\s,;]+", text)
            for token in tokens:
                candidate = token.strip().strip("\"'[](){}")
                if not candidate:
                    continue
                if "=" in candidate and candidate.count("=") == 1:
                    key, val = candidate.split("=", 1)
                    key_text = key.strip().lower()
                    if "ip" in key_text or "addr" in key_text:
                        candidate = val
                candidate = candidate.strip().strip("\"'[](){}")
                if not candidate:
                    continue
                if "/" in candidate:
                    candidate = candidate.split("/", 1)[0]
                add_ip(candidate)

            if family == 4:
                for match in FORTI_IPV4_RE.findall(text):
                    add_ip(match)
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
            return

        if isinstance(value, dict):
            for key, nested in value.items():
                key_text = str(key).lower()
                if "ip" not in key_text and "addr" not in key_text:
                    continue
                walk(nested)
            return

        walk(str(value))

    walk(raw_value)
    return values


def extract_forti_interface_ips(interface: dict, family: int) -> List[str]:
    values: List[str] = []
    seen: Set[str] = set()

    def append_many(items: List[str]) -> None:
        for item in items:
            if item in seen:
                continue
            seen.add(item)
            values.append(item)

    if family == 4:
        explicit_keys = (
            "ip",
            "ipv4",
            "ipv4-address",
            "ipv4_address",
            "public-ip",
            "public_ip",
            "dynamic_ip",
            "secondaryip",
            "secondary_ip",
        )
    else:
        explicit_keys = (
            "ip6",
            "ip6-address",
            "ip6_address",
            "ipv6",
            "ipv6-address",
            "ipv6_address",
            "public-ipv6",
            "public_ipv6",
            "secondaryip6",
            "secondary_ip6",
            "secondary-ipv6",
            "secondary_ipv6",
        )

    for key in explicit_keys:
        if key in interface:
            append_many(parse_ip_values(interface.get(key), family))

    if not values:
        for key, raw_value in interface.items():
            key_text = str(key).lower()
            if "ip" not in key_text and "addr" not in key_text:
                continue
            append_many(parse_ip_values(raw_value, family))

    return values


def collect_forti_interface_records(client: dict, vdom: str) -> List[dict]:
    requests_to_try = [
        (
            "/api/v2/monitor/system/interface",
            {"vdom": vdom},
        ),
        (
            "/api/v2/cmdb/system/interface",
            {"vdom": vdom, "format": "name|ip|role|status|mode|secondaryip"},
        ),
    ]

    for path, params in requests_to_try:
        try:
            payload = forti_api_get_json(client, path, params)
            records = parse_forti_result_items(payload)
            if records:
                return records
        except Exception as exc:
            if is_forti_unauthorized(exc):
                raise
            if is_forti_forbidden(exc):
                LOG.warning("Forti interface query forbidden for %s: %s", path, exc)
                continue
            LOG.warning("Forti interface query failed for %s: %s", path, exc)

    return []


def collect_forti_vip_records(client: dict, vdom: str) -> List[dict]:
    try:
        payload = forti_api_get_json(
            client,
            "/api/v2/cmdb/firewall/vip",
            {"vdom": vdom, "format": "name|extip|extip6|extintf|status|type"},
        )
        return parse_forti_result_items(payload)
    except Exception as exc:
        if is_forti_unauthorized(exc):
            raise
        if is_forti_forbidden(exc):
            LOG.warning("Forti VIP query forbidden for /api/v2/cmdb/firewall/vip: %s", exc)
            return []
        LOG.warning("Forti VIP query failed for /api/v2/cmdb/firewall/vip: %s", exc)
        return []


def collect_forti_ippool_records(client: dict, vdom: str, family: int) -> List[dict]:
    path = "/api/v2/cmdb/firewall/ippool6" if family == 6 else "/api/v2/cmdb/firewall/ippool"
    try:
        payload = forti_api_get_json(
            client,
            path,
            {
                "vdom": vdom,
                "format": (
                    "name|startip|endip|startip6|endip6|source-startip|source-endip|"
                    "source-startip6|source-endip6|associated-interface|arp-intf|status|type"
                ),
            },
        )
        return parse_forti_result_items(payload)
    except Exception as exc:
        if is_forti_unauthorized(exc):
            raise
        if is_forti_forbidden(exc):
            LOG.warning("Forti IP pool query forbidden for %s: %s", path, exc)
            return []
        LOG.warning("Forti IP pool query failed for %s: %s", path, exc)
        return []


def parse_forti_max_range_expansion() -> int:
    value = parse_int(env(FORTI_MAX_RANGE_EXPANSION_ENV, "2048"))
    if value is None or value < 1:
        return 2048
    return value


def expand_forti_ip_range(start_ip: str, end_ip: str, family: int, max_items: int) -> List[str]:
    try:
        start_addr = ipaddress.ip_address((start_ip or "").strip())
        end_addr = ipaddress.ip_address((end_ip or "").strip())
    except ValueError:
        return []

    expected_type = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address
    if not isinstance(start_addr, expected_type) or not isinstance(end_addr, expected_type):
        return []

    start_int = int(start_addr)
    end_int = int(end_addr)
    if end_int < start_int:
        start_int, end_int = end_int, start_int

    count = end_int - start_int + 1
    if count > max_items:
        LOG.warning(
            "Skipping Forti IP range %s-%s (family=%s): %d addresses exceed %s=%d",
            start_ip,
            end_ip,
            family,
            count,
            FORTI_MAX_RANGE_EXPANSION_ENV,
            max_items,
        )
        return []

    addr_type = start_addr.__class__
    return [str(addr_type(value)) for value in range(start_int, end_int + 1)]


def parse_forti_ip_value_or_range(raw_value: Optional[object], family: int, max_range: int) -> List[str]:
    values: List[str] = []
    seen: Set[str] = set()
    expected_type = ipaddress.IPv4Address if family == 4 else ipaddress.IPv6Address

    def add_ip(value: str) -> None:
        try:
            addr = ipaddress.ip_address((value or "").strip())
        except ValueError:
            return
        if not isinstance(addr, expected_type) or addr.is_unspecified:
            return
        text = str(addr)
        if text in seen:
            return
        seen.add(text)
        values.append(text)

    def walk(value: Optional[object]) -> None:
        if value is None:
            return

        if isinstance(value, (list, tuple, set)):
            for item in value:
                walk(item)
            return

        if isinstance(value, dict):
            for key, nested in value.items():
                key_text = str(key).lower()
                if "ip" not in key_text and "addr" not in key_text and "range" not in key_text:
                    continue
                walk(nested)
            return

        text = str(value).strip()
        if not text:
            return

        for token in re.split(r"[\s,;]+", text):
            candidate = token.strip().strip("\"'[](){}")
            if not candidate:
                continue

            if "=" in candidate and candidate.count("=") == 1:
                key, val = candidate.split("=", 1)
                key_text = key.strip().lower()
                if "ip" in key_text or "addr" in key_text:
                    candidate = val
            candidate = candidate.strip().strip("\"'[](){}")
            if not candidate:
                continue

            if "/" in candidate:
                candidate = candidate.split("/", 1)[0]

            if "-" in candidate and candidate.count("-") == 1:
                start_raw, end_raw = candidate.split("-", 1)
                expanded = expand_forti_ip_range(start_raw, end_raw, family, max_range)
                for ip_value in expanded:
                    add_ip(ip_value)
                continue

            add_ip(candidate)

        if family == 4:
            for match in FORTI_IPV4_RE.findall(text):
                add_ip(match)

    walk(raw_value)
    return values


def make_forti_public_ip_candidate(
    family: int,
    ip_value: str,
    source: str,
    interface_name: Optional[str] = None,
    role: Optional[str] = None,
    status: Optional[str] = None,
    object_name: Optional[str] = None,
) -> Optional[dict]:
    try:
        addr = ipaddress.ip_address(ip_value)
    except ValueError:
        return None

    if family == 4 and not isinstance(addr, ipaddress.IPv4Address):
        return None
    if family == 6 and not isinstance(addr, ipaddress.IPv6Address):
        return None
    if (
        addr.is_unspecified
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    ):
        return None

    return {
        "family": family,
        "source": source,
        "interface": normalize_text(interface_name) or "",
        "role": normalize_choice_value(role) or "",
        "status": normalize_choice_value(status) or "",
        "object_name": normalize_text(object_name) or "",
        "ip": str(addr),
        "is_global": bool(addr.is_global),
        "is_private": bool(addr.is_private),
    }


def build_forti_interface_public_ip_candidates(interface_records: List[dict], family: int) -> List[dict]:
    candidates: List[dict] = []
    for record in interface_records:
        if not isinstance(record, dict):
            continue

        interface_name = normalize_text(
            record.get("name")
            or record.get("interface")
            or record.get("ifname")
            or record.get("interface-name")
        )
        role = normalize_choice_value(record.get("role"))
        status = normalize_choice_value(record.get("status") or record.get("link"))
        for ip in extract_forti_interface_ips(record, family):
            candidate = make_forti_public_ip_candidate(
                family=family,
                ip_value=ip,
                source="interface",
                interface_name=interface_name,
                role=role,
                status=status,
            )
            if candidate:
                candidates.append(candidate)

    return candidates


def build_forti_vip_public_ip_candidates(vip_records: List[dict], family: int, max_range: int) -> List[dict]:
    candidates: List[dict] = []
    for record in vip_records:
        if not isinstance(record, dict):
            continue

        vip_name = normalize_text(record.get("name"))
        interface_name = normalize_text(record.get("extintf") or record.get("interface"))
        status = normalize_choice_value(record.get("status"))
        role = "wan"

        raw_values: List[Optional[object]] = []
        if family == 6:
            raw_values.extend([record.get("extip6"), record.get("extip")])
        else:
            raw_values.append(record.get("extip"))

        seen: Set[str] = set()
        for raw in raw_values:
            for ip in parse_forti_ip_value_or_range(raw, family, max_range):
                if ip in seen:
                    continue
                seen.add(ip)
                candidate = make_forti_public_ip_candidate(
                    family=family,
                    ip_value=ip,
                    source="vip",
                    interface_name=interface_name,
                    role=role,
                    status=status,
                    object_name=vip_name,
                )
                if candidate:
                    candidates.append(candidate)

    return candidates


def build_forti_ippool_public_ip_candidates(
    ippool_records: List[dict],
    family: int,
    max_range: int,
) -> List[dict]:
    candidates: List[dict] = []
    range_pairs = [
        ("startip", "endip"),
        ("start-ip", "end-ip"),
        ("source-startip", "source-endip"),
        ("source-start-ip", "source-end-ip"),
        ("startip6", "endip6"),
        ("source-startip6", "source-endip6"),
    ]
    standalone_keys = (
        "startip",
        "endip",
        "startip6",
        "endip6",
        "source-startip",
        "source-endip",
        "source-startip6",
        "source-endip6",
    )

    for record in ippool_records:
        if not isinstance(record, dict):
            continue

        pool_name = normalize_text(record.get("name"))
        interface_name = normalize_text(
            record.get("associated-interface")
            or record.get("associated_interface")
            or record.get("arp-intf")
            or record.get("arp_intf")
            or record.get("interface")
        )
        status = normalize_choice_value(record.get("status"))
        role = "wan"

        ips: List[str] = []
        seen: Set[str] = set()

        def add_ips(values: List[str]) -> None:
            for ip in values:
                if ip in seen:
                    continue
                seen.add(ip)
                ips.append(ip)

        for start_key, end_key in range_pairs:
            start_raw = normalize_text(record.get(start_key))
            end_raw = normalize_text(record.get(end_key))
            if start_raw and end_raw:
                add_ips(expand_forti_ip_range(start_raw, end_raw, family, max_range))
            elif start_raw:
                add_ips(parse_forti_ip_value_or_range(start_raw, family, max_range))
            elif end_raw:
                add_ips(parse_forti_ip_value_or_range(end_raw, family, max_range))

        for key in standalone_keys:
            if key in record:
                add_ips(parse_forti_ip_value_or_range(record.get(key), family, max_range))

        for ip in ips:
            candidate = make_forti_public_ip_candidate(
                family=family,
                ip_value=ip,
                source="ippool",
                interface_name=interface_name,
                role=role,
                status=status,
                object_name=pool_name,
            )
            if candidate:
                candidates.append(candidate)

    return candidates


def rank_forti_public_ip_candidate(
    candidate: dict,
    preferred_interfaces: Dict[str, int],
) -> Tuple[int, int, int, int, int, str, str]:
    interface_name = (candidate.get("interface") or "").strip().lower()
    role = (candidate.get("role") or "").strip().lower()
    status = (candidate.get("status") or "").strip().lower()
    source = (candidate.get("source") or "").strip().lower()

    source_rank = {"interface": 0, "vip": 1, "ippool": 2}.get(source, 3)
    scope_rank = 0 if candidate.get("is_global") else (1 if not candidate.get("is_private") else 2)
    preferred_rank = preferred_interfaces.get(interface_name, len(preferred_interfaces) + 1)
    role_rank = 0 if role == "wan" else 1
    status_rank = 0 if status in ("up", "enable", "enabled", "online", "link-up") else 1

    return (
        scope_rank,
        source_rank,
        preferred_rank,
        role_rank,
        status_rank,
        interface_name,
        candidate.get("ip", ""),
    )


def list_forti_public_ip_candidates(
    candidates: List[dict],
    preferred_interfaces: List[str],
) -> List[dict]:
    if not candidates:
        return []

    preferred_map = {name.lower(): idx for idx, name in enumerate(preferred_interfaces)}
    public_candidates = [item for item in candidates if item.get("is_global")]
    if not public_candidates:
        return []

    # The same public IP may appear more than once in Forti output; keep the best-ranked source.
    best_by_ip: Dict[str, dict] = {}
    for candidate in public_candidates:
        ip_value = normalize_text(candidate.get("ip"))
        if not ip_value:
            continue
        current = best_by_ip.get(ip_value)
        if not current:
            best_by_ip[ip_value] = candidate
            continue
        if rank_forti_public_ip_candidate(candidate, preferred_map) < rank_forti_public_ip_candidate(
            current,
            preferred_map,
        ):
            best_by_ip[ip_value] = candidate

    ranked = list(best_by_ip.values())
    ranked.sort(key=lambda item: rank_forti_public_ip_candidate(item, preferred_map))
    return ranked


def fetch_forti_hostname(client: dict, vdom: str) -> Optional[str]:
    try:
        payload = forti_api_get_json(client, "/api/v2/monitor/system/status", {"vdom": vdom})
    except Exception as exc:
        LOG.debug("Forti hostname query failed: %s", exc)
        return None

    records: List[dict] = []
    if isinstance(payload, dict):
        records.append(payload)
        for key in ("results", "result", "data"):
            value = payload.get(key)
            if isinstance(value, dict):
                records.append(value)
            elif isinstance(value, list):
                records.extend(item for item in value if isinstance(item, dict))

    for record in records:
        for key in ("hostname", "host-name", "name"):
            host = normalize_text(record.get(key))
            if host:
                return host

    return None


def find_netbox_device_by_identifier(nb, identifier: str):
    lookup = normalize_text(identifier)
    if not lookup:
        return None

    device_id = parse_int(lookup)
    if device_id is not None:
        device = nb.dcim.devices.get(id=device_id)
        if device:
            return device

    device = nb.dcim.devices.get(name=lookup)
    if device:
        return device

    matches = list(nb.dcim.devices.filter(q=lookup))
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        LOG.warning("NetBox device lookup '%s' is ambiguous (%d matches)", lookup, len(matches))
    return None


def resolve_forti_netbox_device(nb, client: dict, vdom: str):
    configured = normalize_text(env(NB_FORTI_DEVICE_ENV))
    if configured:
        device = find_netbox_device_by_identifier(nb, configured)
        if not device:
            LOG.warning("Configured Forti NetBox device '%s' was not found", configured)
        return device

    forti_hostname = fetch_forti_hostname(client, vdom)
    if not forti_hostname:
        LOG.warning(
            "Forti hostname lookup failed; set %s to choose the NetBox target device",
            NB_FORTI_DEVICE_ENV,
        )
        return None

    device = find_netbox_device_by_identifier(nb, forti_hostname)
    if not device:
        LOG.warning(
            "NetBox device matching Forti hostname '%s' was not found (set %s to override)",
            forti_hostname,
            NB_FORTI_DEVICE_ENV,
        )
    return device


def ensure_forti_device_interface(nb, device, iface_name: str):
    iface = nb.dcim.interfaces.get(device_id=device.id, name=iface_name)
    if iface:
        return iface

    LOG.info("Creating NetBox device interface %s on Forti device %s", iface_name, device.name)
    payloads = [
        {
            "name": iface_name,
            "device": device.id,
            "type": "virtual",
            "enabled": True,
        },
        {
            "name": iface_name,
            "device": device.id,
            "type": "other",
            "enabled": True,
        },
        {
            "name": iface_name,
            "device": device.id,
            "enabled": True,
        },
    ]

    last_exc: Optional[Exception] = None
    for payload in payloads:
        try:
            return nb.dcim.interfaces.create(payload)
        except RequestError as exc:
            last_exc = exc
            LOG.debug(
                "Failed to create Forti interface %s on %s with payload keys=%s: %s",
                iface_name,
                device.name,
                ",".join(payload.keys()),
                exc,
            )
        except Exception as exc:
            last_exc = exc
            LOG.debug(
                "Unexpected failure while creating Forti interface %s on %s: %s",
                iface_name,
                device.name,
                exc,
            )

    iface = nb.dcim.interfaces.get(device_id=device.id, name=iface_name)
    if iface:
        return iface

    if last_exc:
        raise last_exc
    return None


def sync_forti_public_ip_to_netbox(nb) -> None:
    if not should_sync_forti_public_ip():
        return

    client = build_forti_api_client()
    if not client:
        return

    vdom = (env(FORTI_VDOM_ENV, "root") or "root").strip() or "root"
    preferred_interfaces = parse_forti_interface_names(env(FORTI_WAN_INTERFACES_ENV))
    max_range = parse_forti_max_range_expansion()

    LOG.info("Syncing Forti public IPs (vdom=%s)", vdom)
    try:
        interface_records = collect_forti_interface_records(client, vdom)
        vip_records = collect_forti_vip_records(client, vdom)
        ippool4_records = collect_forti_ippool_records(client, vdom, family=4)
        ippool6_records = collect_forti_ippool_records(client, vdom, family=6)
    except Exception as exc:
        if is_forti_unauthorized(exc):
            LOG.error("Skipping Forti public IP sync: authentication failed: %s", exc)
            return
        raise

    if not interface_records:
        LOG.warning("Forti interface data is empty; continuing with VIP/IP pool sources")

    LOG.info(
        "Forti source records: interfaces=%d vip=%d ippool=%d ippool6=%d",
        len(interface_records),
        len(vip_records),
        len(ippool4_records),
        len(ippool6_records),
    )

    all_v4_candidates: List[dict] = []
    all_v4_candidates.extend(build_forti_interface_public_ip_candidates(interface_records, family=4))
    all_v4_candidates.extend(build_forti_vip_public_ip_candidates(vip_records, family=4, max_range=max_range))
    all_v4_candidates.extend(
        build_forti_ippool_public_ip_candidates(ippool4_records, family=4, max_range=max_range)
    )

    all_v6_candidates: List[dict] = []
    all_v6_candidates.extend(build_forti_interface_public_ip_candidates(interface_records, family=6))
    all_v6_candidates.extend(build_forti_vip_public_ip_candidates(vip_records, family=6, max_range=max_range))
    all_v6_candidates.extend(
        build_forti_ippool_public_ip_candidates(ippool6_records, family=6, max_range=max_range)
    )

    public_v4_candidates = list_forti_public_ip_candidates(all_v4_candidates, preferred_interfaces)
    public_v6_candidates = list_forti_public_ip_candidates(all_v6_candidates, preferred_interfaces)
    if not public_v4_candidates and not public_v6_candidates:
        if all_v4_candidates or all_v6_candidates:
            LOG.warning(
                "Skipping Forti public IP sync: Forti sources returned IPs but none are globally routable"
            )
        else:
            LOG.warning(
                "Skipping Forti public IP sync: no usable IPv4 or IPv6 address found on interfaces/VIPs/IP pools"
            )
        return

    LOG.info(
        "Forti public IP candidates: IPv4=%d IPv6=%d",
        len(public_v4_candidates),
        len(public_v6_candidates),
    )

    device = resolve_forti_netbox_device(nb, client, vdom)
    if not device:
        return

    target_interface_override = normalize_text(env(NB_FORTI_INTERFACE_ENV))
    set_primary_v4 = parse_bool(env(NB_FORTI_SET_PRIMARY_ENV, "true"))
    if set_primary_v4 is None:
        set_primary_v4 = True
    set_primary_v6 = parse_bool(env(NB_FORTI_SET_PRIMARY6_ENV, str(set_primary_v4).lower()))
    if set_primary_v6 is None:
        set_primary_v6 = set_primary_v4

    iface_cache: Dict[str, object] = {}
    synced_ip_objects: Dict[int, object] = {}
    candidates_by_family = (
        (4, public_v4_candidates),
        (6, public_v6_candidates),
    )

    for family, candidates in candidates_by_family:
        source_interface_default = "wan6" if family == 6 else "wan"
        prefix = 128 if family == 6 else 32

        for candidate in candidates:
            selected_ip = candidate["ip"]
            source_interface = normalize_text(candidate.get("interface"))
            if source_interface and source_interface.lower() in ("any", "all", "*"):
                source_interface = None
            source_interface = source_interface or source_interface_default
            target_interface = target_interface_override or source_interface
            cidr = f"{selected_ip}/{prefix}"

            iface = iface_cache.get(target_interface)
            if not iface:
                try:
                    iface = ensure_forti_device_interface(nb, device, target_interface)
                except RequestError as exc:
                    LOG.error(
                        "Forti public IP sync failed while ensuring interface %s on %s: %s",
                        target_interface,
                        device.name,
                        exc,
                    )
                    continue
                except Exception as exc:
                    LOG.error(
                        "Unexpected Forti public IP sync failure while ensuring interface %s on %s: %s",
                        target_interface,
                        device.name,
                        exc,
                    )
                    continue

                if not iface:
                    LOG.warning(
                        "Skipping Forti public IP assignment: could not ensure interface %s on device %s",
                        target_interface,
                        device.name,
                    )
                    continue
                iface_cache[target_interface] = iface

            try:
                ip_obj = ensure_node_ilo_ip_address(nb, iface, cidr)
            except RequestError as exc:
                LOG.error("Forti public IP sync failed while assigning %s: %s", cidr, exc)
                continue
            except Exception as exc:
                LOG.error("Unexpected Forti public IP sync failure while assigning %s: %s", cidr, exc)
                continue

            if not ip_obj:
                continue

            if family not in synced_ip_objects:
                synced_ip_objects[family] = ip_obj
            LOG.info(
                "Forti public IPv%s %s (source=%s object=%s interface=%s) synced to device %s interface %s",
                family,
                cidr,
                candidate.get("source") or "unknown",
                candidate.get("object_name") or "-",
                source_interface,
                device.name,
                target_interface,
            )

    if not synced_ip_objects:
        return

    need_save = False
    if set_primary_v4:
        ip_obj_v4 = synced_ip_objects.get(4)
        if ip_obj_v4:
            current_v4 = getattr(getattr(device, "primary_ip4", None), "id", None)
            if current_v4 != ip_obj_v4.id:
                device.primary_ip4 = ip_obj_v4
                need_save = True

    if set_primary_v6:
        ip_obj_v6 = synced_ip_objects.get(6)
        if ip_obj_v6:
            current_v6 = getattr(getattr(device, "primary_ip6", None), "id", None)
            if current_v6 != ip_obj_v6.id:
                device.primary_ip6 = ip_obj_v6
                need_save = True

    if need_save:
        save_netbox_object_with_retry(
            device,
            f"updating primary IPs for Forti device {device.name}",
        )


@lru_cache(maxsize=None)
def resolve_host_primary_ip(host: str) -> Optional[str]:
    host = (host or "").strip()
    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass

    try:
        addr_infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        LOG.debug("Unable to resolve iLO host '%s': %s", host, exc)
        return None
    except Exception as exc:
        LOG.debug("Unexpected resolver failure for iLO host '%s': %s", host, exc)
        return None

    candidates: List[str] = []
    seen: Set[str] = set()
    for _, _, _, _, sockaddr in addr_infos:
        ip_value = sockaddr[0]
        if ip_value in seen:
            continue
        seen.add(ip_value)
        candidates.append(ip_value)

    if not candidates:
        return None

    for candidate in candidates:
        if ":" not in candidate:
            return candidate
    return candidates[0]


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
    node_proxmox = get_node_proxmox(proxmox, node_name)
    try:
        if pve_type == "qemu":
            return node_proxmox.nodes(node_name).qemu(vmid).config.get()
        if pve_type == "lxc":
            return node_proxmox.nodes(node_name).lxc(vmid).config.get()
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


def ensure_ipam_object_role(obj, role_obj, context: str) -> bool:
    role_id = get_related_object_id(role_obj)
    if role_id is None or obj is None:
        return False

    current_role_id = get_related_object_id(getattr(obj, "role", None))
    if current_role_id == role_id:
        return False

    obj.role = role_id
    save_netbox_object_with_retry(obj, context)
    return True


# ---------------------------------------------------------------------------
# VLAN + interface helpers
# ---------------------------------------------------------------------------

def get_or_create_vlan(nb, vid: int, site, role_obj=None) -> object:
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
        ensure_ipam_object_role(vlan, role_obj, f"updating role on VLAN {vid}")
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
    role_id = get_related_object_id(role_obj)
    if role_id is not None:
        data["role"] = role_id
    vlan = nb.ipam.vlans.create(data)
    return vlan


def select_existing_prefix_candidate(
    candidates: List[object],
    prefix_cidr: str,
    vlan_obj,
) -> Optional[object]:
    exact_candidates = [
        candidate
        for candidate in candidates
        if str(getattr(candidate, "prefix", "") or "").strip() == prefix_cidr
    ]
    if not exact_candidates:
        return None

    target_vlan_id = get_related_object_id(vlan_obj)
    if target_vlan_id is not None:
        for candidate in exact_candidates:
            if get_related_object_id(getattr(candidate, "vlan", None)) == target_vlan_id:
                return candidate

    if len(exact_candidates) > 1:
        LOG.warning(
            "Prefix %s has %d records in NetBox; using id=%s and leaving others untouched",
            prefix_cidr,
            len(exact_candidates),
            getattr(exact_candidates[0], "id", "?"),
        )
    return exact_candidates[0]


def should_sync_guest_prefix(prefix: int, family: int, prefix_is_fallback: bool) -> bool:
    max_prefix = 128 if family == 6 else 32
    if prefix_is_fallback and prefix == max_prefix:
        return False
    return True


PREFIX_SCOPE_MODE: Optional[str] = None


def get_prefix_scope_modes() -> List[str]:
    preferred = PREFIX_SCOPE_MODE if PREFIX_SCOPE_MODE in ("scope", "site") else "scope"
    modes = [preferred]
    if preferred != "scope":
        modes.append("scope")
    if preferred != "site":
        modes.append("site")
    return modes


def remember_prefix_scope_mode(mode: Optional[str]) -> None:
    global PREFIX_SCOPE_MODE
    if mode in ("scope", "site"):
        PREFIX_SCOPE_MODE = mode


def build_prefix_site_query(site, mode: Optional[str]) -> Dict[str, object]:
    if not site or not getattr(site, "id", None):
        return {}
    if mode == "scope":
        return {"scope_type": "dcim.site", "scope_id": site.id}
    if mode == "site":
        return {"site_id": site.id}
    return {}


def apply_prefix_site_create_fields(data: Dict[str, object], site, mode: Optional[str]) -> None:
    if not site or not getattr(site, "id", None):
        return
    if mode == "scope":
        data["scope_type"] = "dcim.site"
        data["scope_id"] = site.id
    elif mode == "site":
        data["site"] = site.id


def is_prefix_scope_compat_error(exc: RequestError, mode: Optional[str]) -> bool:
    if mode not in ("scope", "site"):
        return False
    if request_error_status_code(exc) != 400:
        return False

    error_text = str(getattr(exc, "error", exc)).lower()
    if not any(token in error_text for token in ("unknown", "invalid", "unexpected", "unsupported", "not a valid")):
        return False

    if mode == "scope":
        return "scope_type" in error_text or "scope_id" in error_text or "'scope'" in error_text
    return "site_id" in error_text or "'site'" in error_text


def ensure_netbox_prefix(nb, cidr: str, site, vlan_obj=None, role_obj=None) -> Optional[object]:
    if parse_bool(env(PREFIX_SYNC_ENV, "true")) is False:
        return None
    if PREFIX_SYNC_DISABLED_REASON is not None:
        return None

    try:
        prefix_cidr = str(ipaddress.ip_network(cidr, strict=False))
    except ValueError:
        return None

    query: Dict[str, object] = {"prefix": prefix_cidr}
    candidates: Optional[List[object]] = None
    query_mode: Optional[str] = None

    for mode in get_prefix_scope_modes():
        query = {"prefix": prefix_cidr}
        query.update(build_prefix_site_query(site, mode))
        try:
            candidates = list(nb.ipam.prefixes.filter(**query))
            query_mode = mode
            remember_prefix_scope_mode(mode)
            break
        except RequestError as exc:
            if build_prefix_site_query(site, mode) and is_prefix_scope_compat_error(exc, mode):
                continue

            status = request_error_status_code(exc)
            if status in (401, 403):
                disable_prefix_sync_for_run(f"NetBox returned {status} while querying prefixes")
                return None
            if status and 500 <= status < 600:
                LOG.warning(
                    "NetBox returned %s while searching for prefix %s; skipping prefix sync",
                    status,
                    prefix_cidr,
                )
                return None
            LOG.warning("Failed to query NetBox prefixes for %s: %s", prefix_cidr, exc)
            return None
        except Exception as exc:
            LOG.warning("Failed to query NetBox prefixes for %s: %s", prefix_cidr, exc)
            return None

    if candidates is None:
        LOG.warning(
            "Failed to query NetBox prefixes for %s: no compatible site/scope filter accepted by API",
            prefix_cidr,
        )
        return None

    prefix_obj = select_existing_prefix_candidate(candidates, prefix_cidr, vlan_obj)
    if prefix_obj:
        ensure_ipam_object_role(prefix_obj, role_obj, f"updating role on prefix {prefix_cidr}")
        return prefix_obj

    vlan_id = get_related_object_id(vlan_obj)
    role_id = get_related_object_id(role_obj)

    LOG.info("Creating NetBox prefix %s", prefix_cidr)
    create_modes = [query_mode] if query_mode else []
    for mode in get_prefix_scope_modes():
        if mode not in create_modes:
            create_modes.append(mode)

    for mode in create_modes:
        data = {
            "prefix": prefix_cidr,
            "status": "active",
        }
        apply_prefix_site_create_fields(data, site, mode)
        if vlan_id is not None:
            data["vlan"] = vlan_id
        if role_id is not None:
            data["role"] = role_id

        try:
            prefix_obj = nb.ipam.prefixes.create(data)
            remember_prefix_scope_mode(mode)
            return prefix_obj
        except RequestError as exc:
            if build_prefix_site_query(site, mode) and is_prefix_scope_compat_error(exc, mode):
                continue

            status = request_error_status_code(exc)
            err_text = str(getattr(exc, "error", exc))
            if "duplicate" in err_text.lower():
                LOG.warning("Prefix %s already exists in NetBox; leaving existing record untouched", prefix_cidr)
                try:
                    duplicate_query = {"prefix": prefix_cidr}
                    duplicate_query.update(build_prefix_site_query(site, mode))
                    candidates = list(nb.ipam.prefixes.filter(**duplicate_query))
                except Exception:
                    return None
                prefix_obj = select_existing_prefix_candidate(candidates, prefix_cidr, vlan_obj)
                if prefix_obj:
                    ensure_ipam_object_role(prefix_obj, role_obj, f"updating role on prefix {prefix_cidr}")
                return prefix_obj
            if status in (401, 403):
                disable_prefix_sync_for_run(f"NetBox returned {status} while creating prefixes")
                return None
            if status and 500 <= status < 600:
                LOG.warning(
                    "NetBox returned %s while creating prefix %s; skipping prefix sync",
                    status,
                    prefix_cidr,
                )
                return None
            LOG.warning("Failed to create NetBox prefix %s: %s", prefix_cidr, exc)
            return None
        except Exception as exc:
            LOG.warning("Failed to create NetBox prefix %s: %s", prefix_cidr, exc)
            return None

    LOG.warning(
        "Failed to create NetBox prefix %s: no compatible site/scope payload accepted by API",
        prefix_cidr,
    )
    return None


MAC_ADDRESS_RE = re.compile(r"^[0-9A-F]{12}$")
PVE_NIC_MAC_KEYS = {
    "virtio",
    "e1000",
    "e1000e",
    "rtl8139",
    "vmxnet3",
    "hwaddr",
    "mac",
    "macaddr",
    "address",
}


def normalize_mac_address(value: Optional[object]) -> Optional[str]:
    if value is None:
        return None

    raw = str(value).strip().upper()
    if not raw:
        return None

    # Accept common separators (":", "-", ".") and normalize to "AA:BB:CC:DD:EE:FF".
    compact = re.sub(r"[^0-9A-F]", "", raw)
    if not MAC_ADDRESS_RE.fullmatch(compact):
        return None
    return ":".join(compact[i : i + 2] for i in range(0, 12, 2))


def get_related_object_id(value: Optional[object]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        return parse_int(value.get("id"))
    return parse_int(getattr(value, "id", None))


def normalize_choice_value(value: Optional[object]) -> Optional[str]:
    if isinstance(value, dict):
        value = value.get("value") or value.get("label")
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


def ensure_vm_interface_mac(nb, iface, mac: Optional[str]) -> bool:
    target_mac = normalize_mac_address(mac)
    if not target_mac:
        return False

    iface_label = f"{getattr(iface, 'name', '?')} (id={getattr(iface, 'id', '?')})"
    mac_endpoint = getattr(getattr(nb, "dcim", None), "mac_addresses", None)
    if mac_endpoint is not None:
        mac_obj = None

        # First try: look for an already assigned MAC on this interface.
        try:
            iface_macs = list(
                mac_endpoint.filter(
                    assigned_object_type="virtualization.vminterface",
                    assigned_object_id=iface.id,
                )
            )
        except Exception as exc:
            LOG.debug("Failed to query MACs assigned to VM interface %s: %s", iface_label, exc)
            iface_macs = []

        for candidate in iface_macs:
            candidate_mac = normalize_mac_address(getattr(candidate, "mac_address", None))
            if candidate_mac == target_mac:
                mac_obj = candidate
                break

        # Second try: look up the MAC by value (for existing objects created previously).
        global_mac_matches = []
        if mac_obj is None:
            try:
                global_mac_matches = list(mac_endpoint.filter(mac_address=target_mac))
            except Exception as exc:
                LOG.debug("Failed to query MAC %s by value: %s", target_mac, exc)

            for candidate in global_mac_matches:
                assigned_type = getattr(candidate, "assigned_object_type", None)
                assigned_id = get_related_object_id(getattr(candidate, "assigned_object_id", None))
                if assigned_type == "virtualization.vminterface" and assigned_id == iface.id:
                    mac_obj = candidate
                    break

        if mac_obj is None:
            # Reuse an unassigned matching MAC object if available.
            for candidate in global_mac_matches:
                assigned_type = getattr(candidate, "assigned_object_type", None)
                assigned_id = get_related_object_id(getattr(candidate, "assigned_object_id", None))
                if not assigned_type and not assigned_id:
                    mac_obj = candidate
                    break

        if mac_obj is None:
            try:
                mac_obj = mac_endpoint.create(
                    {
                        "mac_address": target_mac,
                        "assigned_object_type": "virtualization.vminterface",
                        "assigned_object_id": iface.id,
                    }
                )
            except Exception as exc:
                LOG.warning("Failed to create MAC %s for VM interface %s: %s", target_mac, iface_label, exc)
                return False
        else:
            assigned_type = getattr(mac_obj, "assigned_object_type", None)
            assigned_id = get_related_object_id(getattr(mac_obj, "assigned_object_id", None))
            if assigned_type != "virtualization.vminterface" or assigned_id != iface.id:
                try:
                    mac_obj.assigned_object_type = "virtualization.vminterface"
                    mac_obj.assigned_object_id = iface.id
                    save_netbox_object_with_retry(
                        mac_obj,
                        f"assigning MAC {target_mac} to VM interface {iface_label}",
                    )
                except Exception as exc:
                    LOG.warning(
                        "Failed to assign existing MAC %s to VM interface %s: %s",
                        target_mac,
                        iface_label,
                        exc,
                    )
                    return False

        mac_id = get_related_object_id(mac_obj)
        if mac_id and hasattr(iface, "primary_mac_address"):
            current_primary_id = get_related_object_id(getattr(iface, "primary_mac_address", None))
            if current_primary_id != mac_id:
                last_exc = None
                for candidate in (mac_id, {"id": mac_id}):
                    try:
                        iface.primary_mac_address = candidate
                        save_netbox_object_with_retry(
                            iface,
                            f"setting primary MAC on VM interface {iface_label}",
                        )
                        last_exc = None
                        break
                    except Exception as exc:
                        last_exc = exc
                if last_exc is not None:
                    LOG.warning(
                        "Failed to set primary MAC %s on VM interface %s: %s",
                        target_mac,
                        iface_label,
                        last_exc,
                    )
                    return False

        return True

    # NetBox <4 compatibility path where interface has a direct mac_address field.
    current_mac = normalize_mac_address(getattr(iface, "mac_address", None))
    if current_mac == target_mac:
        return False
    try:
        iface.mac_address = target_mac
        save_netbox_object_with_retry(iface, f"updating MAC on VM interface {iface_label}")
        return True
    except Exception as exc:
        LOG.warning("Unable to set MAC %s on VM interface %s: %s", target_mac, iface_label, exc)
        return False


def parse_vm_nic_config(net_value: Optional[object], nic_name: str = "net0") -> Dict[str, Optional[object]]:
    """
    Parse a Proxmox 'net0' style string, e.g.:

        virtio=BC:24:11:44:E6:98,bridge=vmbr0,tag=500

    Returns dict with keys: name, mac, bridge, vlan.
    """
    if not net_value:
        return {"name": nic_name, "mac": None, "bridge": None, "vlan": None}

    mac = None
    bridge = None
    vlan = None

    for part in str(net_value).split(","):
        part = part.strip()
        if not part:
            continue
        if "=" not in part:
            if mac is None:
                mac = normalize_mac_address(part)
            continue
        key, val = part.split("=", 1)
        key = key.strip().lower()
        val = val.strip()
        if not val:
            continue

        if key in PVE_NIC_MAC_KEYS:
            parsed_mac = normalize_mac_address(val)
            if parsed_mac:
                mac = parsed_mac
        elif key == "bridge":
            bridge = val
        elif key == "tag":
            parsed_vlan = parse_int(val)
            if parsed_vlan is not None and 1 <= parsed_vlan <= 4094:
                vlan = parsed_vlan
        elif mac is None:
            parsed_mac = normalize_mac_address(val)
            if parsed_mac:
                mac = parsed_mac

    return {"name": nic_name, "mac": mac, "bridge": bridge, "vlan": vlan}


def extract_vm_nic_configs(config: Optional[dict]) -> List[Dict[str, Optional[object]]]:
    if not isinstance(config, dict):
        return []

    parsed: List[Tuple[int, Dict[str, Optional[object]]]] = []
    for key, value in config.items():
        key_text = str(key).strip().lower()
        match = re.fullmatch(r"net(\d+)", key_text)
        if not match:
            continue
        idx = int(match.group(1))
        parsed.append((idx, parse_vm_nic_config(value, nic_name=f"net{idx}")))

    parsed.sort(key=lambda item: item[0])
    return [nic for _, nic in parsed]


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

    if isinstance(result, list):
        return [item for item in result if isinstance(item, dict)]

    if isinstance(result, dict):
        interfaces = result.get("result")
        if isinstance(interfaces, list):
            return [item for item in interfaces if isinstance(item, dict)]

        interfaces = result.get("data")
        if isinstance(interfaces, list):
            return [item for item in interfaces if isinstance(item, dict)]

    LOG.debug(
        "Unexpected network-get-interfaces payload for vmid=%s on %s: type=%s",
        vmid,
        node_name,
        type(result).__name__,
    )
    return []


def parse_guest_ip_prefix(prefix: Optional[object], ip: str) -> Optional[int]:
    family = 6 if ":" in ip else 4
    max_prefix = 128 if family == 6 else 32

    if prefix is None:
        # If guest agent omits prefix, keep address visibility by falling back to host-only.
        return max_prefix

    if isinstance(prefix, int):
        prefix_int = prefix
    else:
        raw = str(prefix).strip()
        if not raw:
            return max_prefix
        try:
            prefix_int = int(raw)
        except (TypeError, ValueError):
            # Some Windows guests may return netmask instead of prefix length.
            if family == 4:
                try:
                    network = ipaddress.ip_network(f"0.0.0.0/{raw}", strict=False)
                    prefix_int = int(network.prefixlen)
                except ValueError:
                    return None
            else:
                return None

    if 0 <= prefix_int <= max_prefix:
        return prefix_int
    return None


def get_guest_interface_name_from_payload(
    interfaces: List[dict],
    nic_mac: Optional[str],
) -> Optional[str]:
    """
    Use guest agent to find the OS-level interface name (e.g. enp6s18) that
    corresponds to our NIC MAC. Fallback: first non-lo interface with an IP.
    """
    if not interfaces:
        return None

    mac_norm = nic_mac.upper() if nic_mac else None
    fallback = None

    for iface in interfaces:
        name = str(iface.get("name") or "").strip()
        hw = normalize_mac_address(iface.get("hardware-address"))
        if not name or name == "lo":
            continue

        # Prefer exact MAC match
        if hw and mac_norm and hw.upper() == mac_norm:
            return name

        # Otherwise remember first non-lo as fallback
        if not fallback:
            fallback = name

    return fallback


def get_guest_interface_name(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
    nic_mac: Optional[str],
) -> Optional[str]:
    interfaces = fetch_guest_agent_interfaces(proxmox, node_name, vmid, pve_type)
    return get_guest_interface_name_from_payload(interfaces, nic_mac)


def fetch_guest_ip_details(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
    interfaces: Optional[List[dict]] = None,
) -> List[Dict[str, object]]:
    """
    Use qemu-guest-agent to fetch IP addresses from the guest.

    Returns dicts with ip/prefix/family plus guest interface metadata when
    available. Only implemented for QEMU guests; LXC returns [] for now.
    """
    if interfaces is None:
        interfaces = fetch_guest_agent_interfaces(proxmox, node_name, vmid, pve_type)
    if not interfaces:
        return []

    ips: List[Dict[str, object]] = []
    seen: Set[Tuple[str, int, int]] = set()

    for iface in interfaces:
        guest_name = str(iface.get("name") or "").strip() or None
        guest_mac = normalize_mac_address(iface.get("hardware-address"))
        ip_infos = iface.get("ip-addresses")
        if not isinstance(ip_infos, list):
            continue

        for ip_info in ip_infos:
            if not isinstance(ip_info, dict):
                continue

            ip_raw = ip_info.get("ip-address")
            if ip_raw is None:
                continue

            ip = str(ip_raw).strip()
            if not ip:
                continue

            # Skip loopback
            if ip == "::1" or ip.startswith("127."):
                continue
            # Skip IPv6 link-local for now
            if ":" in ip and ip.lower().startswith("fe80:"):
                continue

            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                LOG.warning(
                    "Guest agent returned invalid IP %r for vmid=%s on %s; skipping",
                    ip,
                    vmid,
                    node_name,
                )
                continue

            family = 6 if ":" in ip else 4
            if ip_obj.version != family:
                continue

            prefix_raw = ip_info.get("prefix")
            prefix_int = parse_guest_ip_prefix(prefix_raw, ip)
            if prefix_int is None:
                LOG.warning(
                    "Guest agent returned invalid prefix %r for IP %s on vmid=%s; skipping",
                    prefix_raw,
                    ip,
                    vmid,
                )
                continue

            item = (ip, prefix_int, family)
            if item in seen:
                continue

            seen.add(item)
            ips.append(
                {
                    "ip": ip,
                    "prefix": prefix_int,
                    "family": family,
                    "guest_name": guest_name,
                    "mac": guest_mac,
                    "prefix_is_fallback": prefix_raw is None
                    or (isinstance(prefix_raw, str) and not prefix_raw.strip()),
                }
            )

    return ips


def fetch_guest_ips(
    proxmox: ProxmoxAPI,
    node_name: str,
    vmid: int,
    pve_type: str,
) -> List[Tuple[str, int, int]]:
    return [
        (str(item["ip"]), int(item["prefix"]), int(item["family"]))
        for item in fetch_guest_ip_details(proxmox, node_name, vmid, pve_type)
    ]


def disable_prefix_sync_for_run(reason: str) -> None:
    global PREFIX_SYNC_DISABLED_REASON
    if PREFIX_SYNC_DISABLED_REASON is not None:
        return
    PREFIX_SYNC_DISABLED_REASON = reason
    LOG.warning("Prefix sync disabled for this run: %s", reason)


# ---------------------------------------------------------------------------
# NetBox VM matching helpers
# ---------------------------------------------------------------------------

def extract_vmid_from_comments(comments: Optional[str]) -> Optional[int]:
    """
    Try to pull `vmid=<int>` from a NetBox VM comments field.
    """
    if not comments:
        return None
    match = re.search(r"vmid=(\d+)", comments)
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

    return infer_default_qemu_machine(config)


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


def infer_default_qemu_machine(config: Optional[dict]) -> Optional[str]:
    config = config or {}
    bios = normalize_text(config.get("bios"))
    if bios == "ovmf":
        return "q35"

    for key in config.keys():
        key_l = str(key).lower()
        if key_l.startswith("efidisk"):
            return "q35"

    return "i440fx"


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


def ensure_node_ilo_interface(nb, device, iface_name: str):
    iface = nb.dcim.interfaces.get(device_id=device.id, name=iface_name)
    if iface:
        return iface

    LOG.info("Creating NetBox device interface %s on node %s", iface_name, device.name)
    payloads = [
        {
            "name": iface_name,
            "device": device.id,
            "type": "virtual",
            "enabled": True,
            "mgmt_only": True,
        },
        {
            "name": iface_name,
            "device": device.id,
            "type": "other",
            "enabled": True,
            "mgmt_only": True,
        },
        {
            "name": iface_name,
            "device": device.id,
            "type": "virtual",
            "enabled": True,
        },
        {
            "name": iface_name,
            "device": device.id,
            "enabled": True,
        },
    ]

    last_exc: Optional[Exception] = None
    for payload in payloads:
        try:
            return nb.dcim.interfaces.create(payload)
        except RequestError as exc:
            last_exc = exc
            LOG.debug(
                "Failed to create iLO interface %s on %s with payload keys=%s: %s",
                iface_name,
                device.name,
                ",".join(payload.keys()),
                exc,
            )
        except Exception as exc:
            last_exc = exc
            LOG.debug(
                "Unexpected failure while creating iLO interface %s on %s: %s",
                iface_name,
                device.name,
                exc,
            )

    iface = nb.dcim.interfaces.get(device_id=device.id, name=iface_name)
    if iface:
        return iface

    if last_exc:
        raise last_exc
    return None


def ensure_node_ilo_ip_address(nb, iface, cidr: str):
    ip = cidr.split("/", 1)[0]
    candidates = list(nb.ipam.ip_addresses.filter(address=cidr))

    ip_obj = next(
        (
            c
            for c in candidates
            if getattr(c, "assigned_object_type", None) == "dcim.interface"
            and getattr(c, "assigned_object_id", None) == iface.id
        ),
        None,
    )
    if not ip_obj and candidates:
        ip_obj = next((c for c in candidates if not getattr(c, "assigned_object_id", None)), None)
    if not ip_obj and candidates:
        ip_obj = candidates[0]

    if not ip_obj:
        host_candidates = list(nb.ipam.ip_addresses.filter(q=ip))
        same_host = [c for c in host_candidates if str(getattr(c, "address", "")).split("/")[0] == ip]
        ip_obj = next(
            (
                c
                for c in same_host
                if getattr(c, "assigned_object_type", None) == "dcim.interface"
                and getattr(c, "assigned_object_id", None) == iface.id
            ),
            None,
        )
        if not ip_obj and same_host:
            ip_obj = next((c for c in same_host if not getattr(c, "assigned_object_id", None)), None)
        if not ip_obj and same_host:
            ip_obj = same_host[0]

    if not ip_obj:
        return nb.ipam.ip_addresses.create(
            {
                "address": cidr,
                "status": "active",
                "assigned_object_type": "dcim.interface",
                "assigned_object_id": iface.id,
            }
        )

    ao_type = getattr(ip_obj, "assigned_object_type", None)
    ao_id = getattr(ip_obj, "assigned_object_id", None)
    if ao_type == "dcim.interface" and ao_id == iface.id:
        return ip_obj

    if ao_type and ao_id:
        LOG.warning(
            "IP %s already assigned to %s (id=%s); leaving existing assignment untouched",
            cidr,
            ao_type,
            ao_id,
        )
        return None

    ip_obj.status = "active"
    ip_obj.assigned_object_type = "dcim.interface"
    ip_obj.assigned_object_id = iface.id
    ip_obj.save()
    return ip_obj


def sync_node_ilo_addresses(nb, node_devices: Dict[str, Optional[object]]) -> None:
    if not should_sync_node_ilo():
        return

    interface_name = (env(NODE_ILO_INTERFACE_ENV, "iLO") or "iLO").strip() or "iLO"
    set_primary = parse_bool(env(NODE_ILO_SET_PRIMARY_ENV, "true"))
    explicit_mapping = has_explicit_node_ilo_mapping()
    if set_primary is None:
        set_primary = True

    LOG.info("Syncing node iLO addresses (interface=%s)", interface_name)

    for node_name, device in sorted(node_devices.items(), key=lambda item: item[0]):
        if not device:
            LOG.warning("Skipping iLO sync for node %s: no matching NetBox device", node_name)
            continue

        host, port = resolve_node_ilo_details(node_name)
        if not host:
            if explicit_mapping:
                LOG.warning("Skipping iLO sync for node %s: unable to derive iLO host", node_name)
            else:
                LOG.info("Skipping iLO sync for node %s: no resolvable iLO host found", node_name)
            continue

        ip = resolve_host_primary_ip(host)
        if not ip:
            LOG.warning(
                "Skipping iLO sync for node %s: unable to resolve host '%s'",
                node_name,
                host,
            )
            continue

        prefix = 128 if ":" in ip else 32
        cidr = f"{ip}/{prefix}"

        try:
            iface = ensure_node_ilo_interface(nb, device, interface_name)
            if not iface:
                LOG.warning(
                    "Skipping iLO IP assignment for node %s: failed to get interface %s",
                    node_name,
                    interface_name,
                )
                continue

            ip_obj = ensure_node_ilo_ip_address(nb, iface, cidr)
        except RequestError as exc:
            LOG.error("Failed iLO sync for node %s (%s): %s", node_name, cidr, exc)
            continue
        except Exception as exc:
            LOG.error("Unexpected iLO sync failure for node %s (%s): %s", node_name, cidr, exc)
            continue

        if not ip_obj:
            continue

        endpoint = f"{host}:{port}" if port else host
        LOG.info("Node %s iLO endpoint %s resolved to %s", node_name, endpoint, cidr)

        if not set_primary:
            continue

        need_save = False
        if ":" in ip:
            current_v6 = getattr(getattr(device, "primary_ip6", None), "id", None)
            if current_v6 != ip_obj.id:
                device.primary_ip6 = ip_obj
                need_save = True
        else:
            current_v4 = getattr(getattr(device, "primary_ip4", None), "id", None)
            if current_v4 != ip_obj.id:
                device.primary_ip4 = ip_obj
                need_save = True

        if need_save:
            device.save()


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
    prefix_role=None,
    vlan_role=None,
    config: Optional[dict] = None,
):
    """
    Ensure VM has a vminterface with correct MAC/VLAN, assign IP addresses,
    and create guest prefixes when possible.

    VLANs are auto-created when needed.
    IPs come from qemu-guest-agent for QEMU guests.
    """
    # Get VM interface config (netX) from Proxmox
    if config is None:
        config = fetch_vm_config(proxmox, node_name, vmid, pve_type) or {}
    else:
        config = config or {}

    nic_infos = extract_vm_nic_configs(config)
    if not nic_infos:
        nic_infos = [parse_vm_nic_config(config.get("net0", ""), nic_name="net0")]

    guest_interfaces = fetch_guest_agent_interfaces(proxmox, node_name, vmid, pve_type)
    primary_record = None
    iface_records_by_mac: Dict[str, Dict[str, object]] = {}
    iface_records_by_name: Dict[str, Dict[str, object]] = {}

    def remember_iface_name(name_value: Optional[object], record: Dict[str, object]) -> None:
        name_key = str(name_value or "").strip().lower()
        if name_key and name_key not in iface_records_by_name:
            iface_records_by_name[name_key] = record

    for nic_info in nic_infos:
        mac = normalize_mac_address(nic_info.get("mac"))
        vlan_vid = parse_int(nic_info.get("vlan"))
        source_iface_name = (str(nic_info.get("name") or "net0").strip() or "net0")

        # Use guest agent name only when NIC MAC is known; this avoids guessing wrong mappings.
        guest_name = None
        if mac:
            guest_name = get_guest_interface_name_from_payload(guest_interfaces, mac)
        iface_name = guest_name or source_iface_name

        iface = nb.virtualization.interfaces.get(
            name=iface_name,
            virtual_machine_id=nb_vm.id,
        )

        # Migration path: if we previously created netX, rename it to guest name.
        if not iface and guest_name and source_iface_name != guest_name:
            old_iface = nb.virtualization.interfaces.get(
                name=source_iface_name,
                virtual_machine_id=nb_vm.id,
            )
            if old_iface:
                LOG.info(
                    "Renaming NetBox VM interface %s -> %s on VM %s",
                    source_iface_name,
                    guest_name,
                    nb_vm.name,
                )
                old_iface.name = guest_name
                save_netbox_object_with_retry(
                    old_iface,
                    f"renaming VM interface {source_iface_name} to {guest_name}",
                )
                iface = old_iface

        vlan_obj = None
        if vlan_vid is not None:
            vlan_obj = get_or_create_vlan(nb, vlan_vid, site, vlan_role)

        if not iface:
            LOG.info("Creating NetBox VM interface %s on VM %s", iface_name, nb_vm.name)
            payload = {
                "name": iface_name,
                "virtual_machine": nb_vm.id,
                "enabled": True,
            }
            if vlan_obj:
                payload["mode"] = "access"
                payload["untagged_vlan"] = vlan_obj.id

            iface = nb.virtualization.interfaces.create(payload)
        else:
            changed = False
            if vlan_obj:
                current_mode = normalize_choice_value(getattr(iface, "mode", None))
                current_vlan_id = get_related_object_id(getattr(iface, "untagged_vlan", None))
                if current_mode != "access" or current_vlan_id != vlan_obj.id:
                    iface.mode = "access"
                    iface.untagged_vlan = vlan_obj.id
                    changed = True

            if changed:
                LOG.info("Updating NetBox VM interface %s on VM %s", iface_name, nb_vm.name)
                save_netbox_object_with_retry(
                    iface,
                    f"updating VM interface {iface_name} on {nb_vm.name}",
                )

        if iface and mac:
            mac_synced = ensure_vm_interface_mac(nb, iface, mac)
            if not mac_synced:
                LOG.warning(
                    "MAC sync failed for VM interface %s on VM %s (target MAC %s)",
                    iface_name,
                    nb_vm.name,
                    mac,
                )

        if iface:
            record = {
                "iface": iface,
                "iface_name": iface_name,
                "source_iface_name": source_iface_name,
                "guest_name": guest_name,
                "mac": mac,
                "vlan_obj": vlan_obj,
            }
            if primary_record is None:
                primary_record = record
            if mac:
                iface_records_by_mac[mac] = record
            remember_iface_name(iface_name, record)
            remember_iface_name(guest_name, record)
            remember_iface_name(source_iface_name, record)

    if primary_record is None:
        return

    # Fetch IPs from guest (QEMU only for now)
    ip_details = fetch_guest_ip_details(
        proxmox,
        node_name,
        vmid,
        pve_type,
        interfaces=guest_interfaces,
    )
    if not ip_details:
        return

    primary_v4 = None
    primary_v6 = None

    for item in ip_details:
        target_record = None

        item_mac = normalize_mac_address(item.get("mac"))
        if item_mac:
            target_record = iface_records_by_mac.get(item_mac)

        if not target_record:
            guest_name_key = str(item.get("guest_name") or "").strip().lower()
            if guest_name_key:
                target_record = iface_records_by_name.get(guest_name_key)

        if not target_record:
            target_record = primary_record

        iface = target_record["iface"]
        iface_name = str(
            target_record.get("iface_name")
            or target_record.get("source_iface_name")
            or "net0"
        )
        vlan_obj = target_record.get("vlan_obj")
        ip = str(item["ip"])
        prefix = int(item["prefix"])
        family = int(item["family"])
        prefix_is_fallback = bool(item.get("prefix_is_fallback"))
        cidr = f"{ip}/{prefix}"
        ip_obj = None

        # Skip only true invalid IPv4 network/broadcast addresses.
        # /31 and /32 are valid host assignments and must not be skipped.
        try:
            ip_addr = ipaddress.ip_address(ip)
            network = ipaddress.ip_network(cidr, strict=False)
            is_network = (
                isinstance(network, ipaddress.IPv4Network)
                and network.prefixlen <= 30
                and ip_addr == network.network_address
            )
            is_broadcast = (
                isinstance(network, ipaddress.IPv4Network)
                and network.prefixlen <= 30
                and ip_addr == network.broadcast_address
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

        if should_sync_guest_prefix(prefix, family, prefix_is_fallback):
            ensure_netbox_prefix(nb, cidr, site, vlan_obj, prefix_role)

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
                status = request_error_status_code(exc)
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
                status = request_error_status_code(exc)
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
            elif not ao_type and not ao_id:
                try:
                    ip_obj.status = "active"
                    ip_obj.assigned_object_type = "virtualization.vminterface"
                    ip_obj.assigned_object_id = iface.id
                    save_netbox_object_with_retry(
                        ip_obj,
                        f"assigning existing IP {cidr} to VM interface {iface_name}",
                    )
                except Exception as exc:
                    LOG.warning(
                        "Failed to assign existing unassigned IP %s to %s: %s",
                        cidr,
                        iface_name,
                        exc,
                    )
                    continue
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
        save_netbox_object_with_retry(nb_vm, f"updating primary IPs on VM {nb_vm.name}")


# ---------------------------------------------------------------------------
# Sync VMs -> NetBox Virtual Machines (per-node enumeration)
# ---------------------------------------------------------------------------

def sync_vms(
    nb,
    proxmox: ProxmoxAPI,
    cluster,
    node_devices: Dict[str, Optional[object]],
    site,
    prefix_role,
    vlan_role,
    vmid_map: Dict[int, object],
    vm_resource_map: Dict[int, dict],
    vm_cf_specs: Dict[str, Optional[List[dict]]],
    sync_timestamp: str,
) -> Tuple[Set[str], Set[int], Set[str]]:
    """
    Sync all Proxmox VMs (QEMU + LXC) into NetBox virtualization.virtual_machines.

    We enumerate VMs per node:
      - /nodes/{node}/qemu
      - /nodes/{node}/lxc

    Returns (names_seen, vmids_seen, failed_nodes) so deletion logic can be vmid-aware
    and can be safely skipped when node enumeration fails.
    """
    nodes = proxmox.nodes.get()
    nodes = sorted(nodes, key=lambda item: str(item.get("node", "")))
    total_vms = 0
    synced_vm_names: Set[str] = set()
    synced_vm_ids: Set[int] = set()
    failed_nodes: Set[str] = set()

    for node in nodes:
        node_name = node["node"]
        host_device = node_devices.get(node_name)
        node_proxmox = get_node_proxmox(proxmox, node_name)

        # ----- QEMU guests -----
        try:
            qemus = node_proxmox.nodes(node_name).qemu.get()
        except Exception as exc:
            LOG.error("Failed to query QEMU VMs on node %s: %s", node_name, exc)
            qemus = []
            failed_nodes.add(node_name)

        # ----- LXC containers -----
        try:
            lxcs = node_proxmox.nodes(node_name).lxc.get()
        except Exception as exc:
            LOG.error("Failed to query LXC containers on node %s: %s", node_name, exc)
            lxcs = []
            failed_nodes.add(node_name)

        LOG.info(
            "Node %s: found %d QEMU VMs and %d LXC containers",
            node_name, len(qemus), len(lxcs)
        )

        def sync_and_track_vm(vm: dict, vm_kind: str) -> None:
            nonlocal total_vms
            total_vms += 1

            vmid = vm.get("vmid")
            vm_name = vm.get("name") or f"vm-{vmid}"

            try:
                name, synced_vmid = sync_single_vm(
                    nb=nb,
                    proxmox=proxmox,
                    vm=vm,
                    node_name=node_name,
                    host_device=host_device,
                    cluster=cluster,
                    pve_type=vm_kind,
                    site=site,
                    prefix_role=prefix_role,
                    vlan_role=vlan_role,
                    vmid_map=vmid_map,
                    vm_resource_map=vm_resource_map,
                    vm_cf_specs=vm_cf_specs,
                    sync_timestamp=sync_timestamp,
                )
            except RequestError as exc:
                status = request_error_status_code(exc)
                if status and 500 <= status < 600:
                    LOG.error(
                        "Skipping VM %s (vmid=%s, node=%s, type=%s): transient NetBox API error %s: %s",
                        vm_name,
                        vmid,
                        node_name,
                        vm_kind,
                        status,
                        exc,
                    )
                    return
                raise

            synced_vm_names.add(name)
            synced_vm_ids.add(synced_vmid)

        for vm in qemus:
            sync_and_track_vm(vm, "qemu")

        for vm in lxcs:
            sync_and_track_vm(vm, "lxc")

    LOG.info("Total Proxmox guests synced (QEMU + LXC): %d", total_vms)
    if failed_nodes:
        LOG.warning(
            "Node VM enumeration failed for %d node(s): %s",
            len(failed_nodes),
            ", ".join(sorted(failed_nodes)),
        )
    return synced_vm_names, synced_vm_ids, failed_nodes


def sync_single_vm(
    nb,
    proxmox: ProxmoxAPI,
    vm: dict,
    node_name: str,
    host_device,
    cluster,
    pve_type: str,
    site,
    prefix_role,
    vlan_role,
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

        save_netbox_object_with_retry(nb_vm, f"updating NetBox VM {name}")

    # Interface + IP handling
    ensure_vm_interface_and_ips(
        nb=nb,
        proxmox=proxmox,
        node_name=node_name,
        vmid=vmid,
        pve_type=pve_type,
        nb_vm=nb_vm,
        site=site,
        prefix_role=prefix_role,
        vlan_role=vlan_role,
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
# IP block reporting
# ---------------------------------------------------------------------------

def describe_related_value(value: Optional[object]) -> str:
    if value is None:
        return "-"

    if isinstance(value, dict):
        for key in ("name", "display", "label", "value", "slug", "id"):
            raw = value.get(key)
            if raw not in (None, ""):
                return str(raw)
        return "-"

    for attr in ("name", "display", "label", "value", "slug", "id"):
        raw = getattr(value, attr, None)
        if raw not in (None, ""):
            return str(raw)

    return str(value)


def build_ip_block_report_rows(nb, site) -> List[dict]:
    query: Dict[str, object] = {}
    prefixes: List[object] = []
    query_attempted = False

    for mode in get_prefix_scope_modes():
        query = {}
        query.update(build_prefix_site_query(site, mode))
        try:
            prefixes = list(nb.ipam.prefixes.filter(**query))
            remember_prefix_scope_mode(mode)
            query_attempted = True
            break
        except RequestError as exc:
            if build_prefix_site_query(site, mode) and is_prefix_scope_compat_error(exc, mode):
                continue
            raise

    if not query_attempted:
        prefixes = list(nb.ipam.prefixes.filter())

    rows: List[dict] = []

    for prefix in prefixes:
        prefix_cidr = str(getattr(prefix, "prefix", "") or "").strip()
        if not prefix_cidr:
            continue

        try:
            network = ipaddress.ip_network(prefix_cidr, strict=False)
        except ValueError as exc:
            LOG.warning("IP block report: skipping invalid prefix '%s': %s", prefix_cidr, exc)
            continue

        used_ips = 0
        try:
            used_ips = len(list(nb.ipam.ip_addresses.filter(parent=prefix_cidr)))
        except Exception as exc:
            LOG.warning("IP block report: failed to count IPs in %s: %s", prefix_cidr, exc)

        total_ips = int(network.num_addresses)
        free_ips = max(total_ips - used_ips, 0)
        utilization_pct = (used_ips / total_ips * 100.0) if total_ips else 0.0

        vlan_obj = getattr(prefix, "vlan", None)
        vlan_vid = parse_int(vlan_obj.get("vid")) if isinstance(vlan_obj, dict) else parse_int(getattr(vlan_obj, "vid", None))
        vlan_label = describe_related_value(vlan_obj)
        if vlan_obj is None:
            vlan_value = "-"
        elif vlan_vid is None:
            vlan_value = vlan_label
        elif vlan_label in ("-", str(vlan_vid)):
            vlan_value = str(vlan_vid)
        else:
            vlan_value = f"{vlan_vid} ({vlan_label})"

        is_pool = parse_bool(getattr(prefix, "is_pool", None))
        is_pool_text = "true" if is_pool is True else "false" if is_pool is False else "-"

        rows.append(
            {
                "prefix": prefix_cidr,
                "family": network.version,
                "prefix_length": network.prefixlen,
                "site": describe_related_value(
                    getattr(prefix, "scope", None) or getattr(prefix, "site", None)
                ),
                "vrf": describe_related_value(getattr(prefix, "vrf", None)),
                "vlan": vlan_value,
                "status": describe_related_value(getattr(prefix, "status", None)),
                "is_pool": is_pool_text,
                "total_ips": total_ips,
                "used_ips": used_ips,
                "free_ips": free_ips,
                "utilization_pct": round(utilization_pct, 2),
                "_network_int": int(network.network_address),
            }
        )

    rows.sort(key=lambda row: (row["family"], row["_network_int"], row["prefix_length"]))
    return rows


def write_ip_block_report_csv(rows: List[dict], csv_path: str) -> None:
    output_path = (csv_path or "").strip()
    if not output_path:
        return

    directory = os.path.dirname(output_path)
    if directory:
        os.makedirs(directory, exist_ok=True)

    fieldnames = [
        "prefix",
        "family",
        "prefix_length",
        "site",
        "vrf",
        "vlan",
        "status",
        "is_pool",
        "total_ips",
        "used_ips",
        "free_ips",
        "utilization_pct",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def maybe_report_ip_blocks(nb, site) -> None:
    enabled = parse_bool(env(IP_BLOCK_REPORT_ENV, "false"))
    if not enabled:
        return

    scope_label = "all sites"
    if site and getattr(site, "name", None):
        scope_label = f"site={site.name}"

    try:
        rows = build_ip_block_report_rows(nb, site)
    except Exception as exc:
        LOG.error("IP block report failed while building data: %s", exc)
        return

    if not rows:
        LOG.info("IP block report: no prefixes found (%s)", scope_label)
        return

    LOG.info("IP block report (%s): %d prefixes", scope_label, len(rows))
    for row in rows:
        LOG.info(
            "Prefix=%s used=%d free=%d total=%d util=%.2f%% site=%s vrf=%s vlan=%s status=%s pool=%s",
            row["prefix"],
            row["used_ips"],
            row["free_ips"],
            row["total_ips"],
            row["utilization_pct"],
            row["site"],
            row["vrf"],
            row["vlan"],
            row["status"],
            row["is_pool"],
        )

    csv_path = (env(IP_BLOCK_REPORT_PATH_ENV, "") or "").strip()
    if csv_path:
        try:
            write_ip_block_report_csv(rows, csv_path)
            LOG.info("IP block report CSV written to %s", csv_path)
        except Exception as exc:
            LOG.error("Failed to write IP block report CSV to %s: %s", csv_path, exc)


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
    prefix_role = ensure_nb_ipam_role(nb, NB_PREFIX_ROLE_ENV)
    vlan_role = ensure_nb_ipam_role(nb, NB_VLAN_ROLE_ENV)
    vm_cf_specs = resolve_vm_custom_field_specs(nb)
    sync_timestamp = format_sync_timestamp()
    vm_resource_map = build_vm_resource_map(proxmox)

    vmid_map = map_netbox_vms_by_vmid(nb, cluster)
    node_devices = ensure_node_devices(nb, proxmox, site, role, dtype, cluster)
    sync_node_ilo_addresses(nb, node_devices)
    sync_forti_public_ip_to_netbox(nb)
    synced_vm_names, synced_vm_ids, failed_nodes = sync_vms(
        nb,
        proxmox,
        cluster,
        node_devices,
        site,
        prefix_role,
        vlan_role,
        vmid_map,
        vm_resource_map,
        vm_cf_specs,
        sync_timestamp,
    )

    if delete_missing:
        if failed_nodes:
            LOG.error(
                "Full sync deletion is skipped because node VM enumeration failed: %s",
                ", ".join(sorted(failed_nodes)),
            )
        else:
            delete_missing_netbox_vms(nb, cluster, synced_vm_names, synced_vm_ids)

    maybe_report_ip_blocks(nb, site)


if __name__ == "__main__":
    main()
