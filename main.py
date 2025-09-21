#!/usr/bin/env python3
"""
PAN-OS object and policy creator from YAML.

- Reads firewall host (IP/DNS) from an inventory YAML file
- Reads objects and security policies from the same YAML
- Uses API key from environment variable: PA_API_KEY
- Creates objects (tags, addresses, address-groups, services, service-groups)
- Creates security policies
- Commits the configuration
"""
import argparse
import os
import ssl
import sys
import urllib.parse
import urllib.request
import traceback
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as xml_escape

DEFAULT_VSYS = "vsys1"
API_KEY_ENV = "PA_API_KEY"


# -------------- HTTP/XML helpers --------------

def _url(host: str, path: str = "/api/") -> str:
    if host.startswith("http://") or host.startswith("https://"):
        parsed = urllib.parse.urlparse(host)
        base = f"{parsed.scheme}://{parsed.netloc}"
        return urllib.parse.urljoin(base, path.lstrip("/"))
    return f"https://{host}{path}"


def _ssl_context(verify_ssl: bool) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    if not verify_ssl:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _http_request(
    url: str,
    params: Dict[str, Any],
    method: str = "GET",
    verify_ssl: bool = False,
    timeout: int = 30,
) -> str:
    query = urllib.parse.urlencode(params)
    data = None
    req_url = url
    if method.upper() == "GET":
        joiner = "&" if ("?" in url) else "?"
        req_url = f"{url}{joiner}{query}" if query else url
    else:
        data = query.encode("utf-8")

    req = urllib.request.Request(req_url, data=data, method=method.upper())
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    ctx = _ssl_context(verify_ssl)
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as resp:
        return resp.read().decode("utf-8")


def _ensure_success(response_xml: str, error_prefix: str) -> None:
    if 'status="success"' in response_xml:
        return
    msg = ""
    s = response_xml.find("<msg>")
    e = response_xml.find("</msg>")
    if s != -1 and e != -1:
        msg = response_xml[s + 5 : e].strip()
    raise RuntimeError(f"{error_prefix}. Response: {msg or response_xml}")


def _api_config_set(
    host: str, api_key: str, xpath: str, element_xml: str, verify_ssl: bool = False, timeout: int = 30
) -> str:
    url = _url(host, "/api/")
    params = {"type": "config", "action": "set", "xpath": xpath, "element": element_xml, "key": api_key}
    response_xml = _http_request(url, params, method="POST", verify_ssl=verify_ssl, timeout=timeout)
    _ensure_success(response_xml, "Config set failed")
    return response_xml


def _api_config_delete(
    host: str, api_key: str, xpath: str, verify_ssl: bool = False, timeout: int = 30
) -> str:
    url = _url(host, "/api/")
    params = {"type": "config", "action": "delete", "xpath": xpath, "key": api_key}
    try:
        response_xml = _http_request(url, params, method="POST", verify_ssl=verify_ssl, timeout=timeout)
        _ensure_success(response_xml, "Config delete failed")
        return response_xml
    except RuntimeError as e:
        msg = str(e)
        if "cannot be deleted because of references" in msg:
            raise RuntimeError(
                msg + " Hint: remove referencing rules or objects first, then retry."
            )
        raise


def _vprint(enabled: bool, message: str) -> None:
    if enabled:
        print(message, flush=True)


def _api_op(host: str, api_key: str, cmd_xml: str, verify_ssl: bool = False, timeout: int = 60) -> str:
    url = _url(host, "/api/")
    params = {"type": "commit" if cmd_xml.strip().startswith("<commit") else "op", "cmd": cmd_xml, "key": api_key}
    response_xml = _http_request(url, params, method="POST", verify_ssl=verify_ssl, timeout=timeout)
    _ensure_success(response_xml, "Operation failed")
    return response_xml


def _op_show_system_info(host: str, api_key: str, verify_ssl: bool) -> str:
    cmd = "<show><system><info></info></system></show>"
    return _api_op(host, api_key, cmd, verify_ssl=verify_ssl)


def _vsys_xpath(vsys: str) -> str:
    v = xml_escape(vsys)
    return f"/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='{v}']"


def _api_config_get(
    host: str, api_key: str, xpath: str, verify_ssl: bool = False, timeout: int = 30
) -> str:
    url = _url(host, "/api/")
    params = {"type": "config", "action": "get", "xpath": xpath, "key": api_key}
    response_xml = _http_request(url, params, method="GET", verify_ssl=verify_ssl, timeout=timeout)
    _ensure_success(response_xml, "Config get failed")
    return response_xml


def _extract_entry_names(xml_text: str) -> List[str]:
    names: List[str] = []
    start = 0
    pat1, pat2 = "entry name='", 'entry name="'
    while True:
        i, q = xml_text.find(pat1, start), "'"
        if i == -1:
            i, q = xml_text.find(pat2, start), '"'
        if i == -1:
            break
        j = i + (len(pat1) if q == "'" else len(pat2))
        k = xml_text.find(q, j)
        if k == -1:
            break
        names.append(xml_text[j:k])
        start = k + 1
    return names


def get_existing_zones(host: str, api_key: str, vsys: str, verify_ssl: bool) -> List[str]:
    xpath = f"{_vsys_xpath(vsys)}/zone"
    xml_resp = _api_config_get(host, api_key, xpath, verify_ssl=verify_ssl)
    return _extract_entry_names(xml_resp)


def get_log_forwarding_profiles(host: str, api_key: str, verify_ssl: bool) -> List[str]:
    xpath = "/config/shared/log-settings/profiles"
    try:
        xml_resp = _api_config_get(host, api_key, xpath, verify_ssl=verify_ssl)
    except Exception:
        return []
    return _extract_entry_names(xml_resp)


# -------------- Object Creators --------------

def _normalize_tag_color(color: Optional[object]) -> Optional[str]:
    if color is None: return None
    if isinstance(color, int): return f"color{color}"
    s = str(color).strip().lower()
    if s.isdigit(): return f"color{s}"
    if s.startswith("color") and s[5:].isdigit(): return s
    raise ValueError(f"Invalid tag color: {color}. Use an int or 'colorN'.")


def create_tag(host: str, api_key: str, vsys: str, name: str, color: Optional[int], comments: Optional[str], verify_ssl: bool) -> None:
    name_x, color_key = xml_escape(name), _normalize_tag_color(color)
    color_xml = f"<color>{xml_escape(color_key)}</color>" if color_key else ""
    comments_xml = f"<comments>{xml_escape(comments)}</comments>" if comments else ""
    element = f"<entry name='{name_x}'>{color_xml}{comments_xml}</entry>"
    xpath = f"{_vsys_xpath(vsys)}/tag"
    _api_config_set(host, api_key, xpath, element, verify_ssl=verify_ssl)


def create_address(host: str, api_key: str, vsys: str, o: Dict[str, Any], verify_ssl: bool) -> None:
    name, typ, value = str(o["name"]), str(o["type"]), str(o["value"])
    desc, tags = o.get("description"), o.get("tags") or []
    if typ not in {"ip-netmask", "ip-range", "fqdn"}:
        raise ValueError(f"Invalid address.type for {name}: {typ}")
    name_x, value_x = xml_escape(name), xml_escape(value)
    desc_xml = f"<description>{xml_escape(desc)}</description>" if desc else ""
    tags_xml = ""
    if tags: tags_xml = "<tag>" + "".join(f"<member>{xml_escape(t)}</member>" for t in tags) + "</tag>"
    element = f"<entry name='{name_x}'><{typ}>{value_x}</{typ}>{desc_xml}{tags_xml}</entry>"
    xpath = f"{_vsys_xpath(vsys)}/address"
    _api_config_set(host, api_key, xpath, element, verify_ssl=verify_ssl)


def create_address_group(host: str, api_key: str, vsys: str, g: Dict[str, Any], verify_ssl: bool) -> None:
    name, static, dynamic = str(g["name"]), g.get("static_members") or [], g.get("dynamic_filter")
    desc, tags = g.get("description"), g.get("tags") or []
    if bool(static) == bool(dynamic):
        raise ValueError(f"Address-group {name}: provide exactly one of static_members or dynamic_filter")
    name_x = xml_escape(name)
    desc_xml = f"<description>{xml_escape(desc)}</description>" if desc else ""
    tags_xml = ""
    if tags: tags_xml = "<tag>" + "".join(f"<member>{xml_escape(t)}</member>" for t in tags) + "</tag>"
    content = ""
    if static:
        content = "<static>" + "".join(f"<member>{xml_escape(m)}</member>" for m in static) + "</static>"
    else:
        content = f"<dynamic><filter>{xml_escape(dynamic)}</filter></dynamic>"
    element = f"<entry name='{name_x}'>{content}{desc_xml}{tags_xml}</entry>"
    xpath = f"{_vsys_xpath(vsys)}/address-group"
    _api_config_set(host, api_key, xpath, element, verify_ssl=verify_ssl)


def create_service(host: str, api_key: str, vsys: str, s: Dict[str, Any], verify_ssl: bool) -> None:
    name, protocol, ports = str(s["name"]), str(s["protocol"]).lower(), str(s["ports"])
    desc, tags = s.get("description"), s.get("tags") or []
    if protocol not in {"tcp", "udp"}: raise ValueError(f"Service {name}: protocol must be tcp or udp")
    name_x, port_x = xml_escape(name), xml_escape(ports)
    desc_xml = f"<description>{xml_escape(desc)}</description>" if desc else ""
    tags_xml = ""
    if tags: tags_xml = "<tag>" + "".join(f"<member>{xml_escape(t)}</member>" for t in tags) + "</tag>"
    element = (f"<entry name='{name_x}'><protocol><{protocol}><port>{port_x}</port></{protocol}></protocol>{desc_xml}{tags_xml}</entry>")
    xpath = f"{_vsys_xpath(vsys)}/service"
    _api_config_set(host, api_key, xpath, element, verify_ssl=verify_ssl)


def create_service_group(host: str, api_key: str, vsys: str, g: Dict[str, Any], verify_ssl: bool) -> None:
    name, members, tags = str(g["name"]), g.get("members") or [], g.get("tags") or []
    name_x = xml_escape(name)
    tags_xml = ""
    if tags: tags_xml = "<tag>" + "".join(f"<member>{xml_escape(t)}</member>" for t in tags) + "</tag>"
    members_xml = "".join(f"<member>{xml_escape(m)}</member>" for m in members)
    element = f"<entry name='{name_x}'><members>{members_xml}</members>{tags_xml}</entry>"
    xpath = f"{_vsys_xpath(vsys)}/service-group"
    _api_config_set(host, api_key, xpath, element, verify_ssl=verify_ssl)


# -------------- Deleters --------------

def delete_address(host: str, api_key: str, vsys: str, name: str, verify_ssl: bool) -> None:
    xpath = f"{_vsys_xpath(vsys)}/address/entry[@name='{xml_escape(name)}']"
    _api_config_delete(host, api_key, xpath, verify_ssl=verify_ssl)


def delete_address_group(host: str, api_key: str, vsys: str, name: str, verify_ssl: bool) -> None:
    xpath = f"{_vsys_xpath(vsys)}/address-group/entry[@name='{xml_escape(name)}']"
    _api_config_delete(host, api_key, xpath, verify_ssl=verify_ssl)


def delete_service(host: str, api_key: str, vsys: str, name: str, verify_ssl: bool) -> None:
    xpath = f"{_vsys_xpath(vsys)}/service/entry[@name='{xml_escape(name)}']"
    _api_config_delete(host, api_key, xpath, verify_ssl=verify_ssl)


def delete_service_group(host: str, api_key: str, vsys: str, name: str, verify_ssl: bool) -> None:
    xpath = f"{_vsys_xpath(vsys)}/service-group/entry[@name='{xml_escape(name)}']"
    _api_config_delete(host, api_key, xpath, verify_ssl=verify_ssl)


def delete_tag(host: str, api_key: str, vsys: str, name: str, verify_ssl: bool) -> None:
    xpath = f"{_vsys_xpath(vsys)}/tag/entry[@name='{xml_escape(name)}']"
    _api_config_delete(host, api_key, xpath, verify_ssl=verify_ssl)


def delete_security_rule(host: str, api_key: str, vsys: str, name: str, verify_ssl: bool) -> None:
    xpath = f"{_vsys_xpath(vsys)}/rulebase/security/rules/entry[@name='{xml_escape(name)}']"
    _api_config_delete(host, api_key, xpath, verify_ssl=verify_ssl)


# -------------- Security policy --------------

def _bool_to_yesno(b: Optional[bool]) -> Optional[str]:
    if b is None: return None
    return "yes" if b else "no"


def create_security_rule(host: str, api_key: str, vsys: str, rule: Dict[str, Any], verify_ssl: bool) -> None:
    name = str(rule["name"])
    name_x = xml_escape(name)

    def members_block(tag: str, values: List[str]) -> str:
        vs = [str(v) for v in (values or [])]
        if not vs: return f"<{tag}><member>any</member></{tag}>"
        return f"<{tag}>" + "".join(f"<member>{xml_escape(v)}</member>" for v in vs) + f"</{tag}>"

    def resolve_zones(requested: List[str], existing: List[str], rule_name: str) -> List[str]:
        if not requested: return ["any"]
        ex_map = {z.lower(): z for z in existing}
        resolved: List[str] = []
        for z in requested:
            zs = str(z).strip()
            if zs.lower() == "any":
                resolved.append("any")
                continue
            match = ex_map.get(zs.lower())
            if not match:
                raise ValueError(
                    f"Zone '{zs}' in rule '{rule_name}' not found. Existing: {', '.join(existing) or '(none)'}"
                )
            resolved.append(match)
        return resolved

    existing_zones = get_existing_zones(host, api_key, vsys, verify_ssl)
    existing_lfp = {p.lower(): p for p in get_log_forwarding_profiles(host, api_key, verify_ssl)}

    from_zones = resolve_zones(rule.get("from_zones"), existing_zones, name)
    to_zones = resolve_zones(rule.get("to_zones"), existing_zones, name)

    log_setting_req = rule.get("log_setting")
    log_setting = None
    if log_setting_req:
        ls_key = str(log_setting_req).strip().lower()
        if ls_key in existing_lfp:
            log_setting = existing_lfp[ls_key]
        else:
            _vprint(True, f"Warning: log-setting '{log_setting_req}' not found; omitting from rule '{name}'.")

    # Build XML parts cleanly
    desc_xml = f"<description>{xml_escape(str(rule.get('description')))}</description>" if rule.get("description") else ""
    tag_xml = ""
    if rule.get("tags"):
        tag_xml = "<tag>" + "".join(f"<member>{xml_escape(t)}</member>" for t in rule.get("tags", [])) + "</tag>"
    log_setting_xml = f"<log-setting>{xml_escape(log_setting)}</log-setting>" if log_setting else ""
    log_start_xml = f"<log-start>{_bool_to_yesno(rule.get('log_start'))}</log-start>" if rule.get('log_start') is not None else ""
    log_end_xml = f"<log-end>{_bool_to_yesno(rule.get('log_end'))}</log-end>" if rule.get('log_end') is not None else ""
    disabled_xml = f"<disabled>{_bool_to_yesno(rule.get('disabled'))}</disabled>" if rule.get('disabled') is not None else ""

    element = (
        f"<entry name='{name_x}'>"
        f"{members_block('to', to_zones)}"
        f"{members_block('from', from_zones)}"
        f"{members_block('source', rule.get('source_addresses') or ['any'])}"
        f"{members_block('destination', rule.get('destination_addresses') or ['any'])}"
        f"{members_block('application', rule.get('applications') or ['any'])}"
        f"{members_block('service', rule.get('services') or ['any'])}"
        f"{members_block('source-user', rule.get('users') or ['any'])}"
        f"<action>{xml_escape(str(rule.get('action', 'allow')))}</action>"
        f"{desc_xml}"
        f"{tag_xml}"
        f"{log_setting_xml}"
        f"{log_start_xml}"
        f"{log_end_xml}"
        f"{disabled_xml}"
        f"</entry>"
    )
    xpath = f"{_vsys_xpath(vsys)}/rulebase/security/rules"
    _api_config_set(host, api_key, xpath, element, verify_ssl=verify_ssl)


# -------------- YAML loader --------------

def load_yaml(path: str) -> Dict[str, Any]:
    try:
        import yaml
    except ImportError:
        print("Error: PyYAML is required. Install with: pip install pyyaml", file=sys.stderr)
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


# -------------- Orchestration --------------

def apply_inventory(inventory_path: str, device_name: Optional[str], api_key: str, verify_ssl_flag: Optional[bool], do_commit: bool, verbose: bool = False) -> None:
    _vprint(verbose, f"[apply] loading inventory: {inventory_path}")
    data = load_yaml(inventory_path)
    _vprint(verbose, "[apply] inventory loaded")

    devices = data.get("devices") or []
    if not devices: raise ValueError("No devices found in inventory YAML")
    
    device = devices[0]
    if device_name:
        matches = [d for d in devices if str(d.get("name")) == device_name]
        if not matches: raise KeyError(f"Device '{device_name}' not found")
        device = matches[0]

    host = str(device.get("host") or "").strip()
    if not host: raise ValueError("Device 'host' is required")
    
    vsys = str(device.get("vsys") or DEFAULT_VSYS)
    verify_ssl = bool(device.get("verify_ssl", False))
    if verify_ssl_flag is not None: verify_ssl = verify_ssl_flag

    _vprint(verbose, f"[apply] target host={host} vsys={vsys} verify_ssl={verify_ssl}")
    try:
        _vprint(verbose, "[apply] running API connectivity precheck...")
        _op_show_system_info(host, api_key, verify_ssl)
        _vprint(verbose, "[apply] precheck OK")
    except Exception as e:
        raise RuntimeError(f"API connectivity precheck failed: {e}")

    objects = data.get("objects") or {}
    tags_list = objects.get("tags", [])
    _vprint(verbose, f"[apply] creating {len(tags_list)} tag(s)...")
    for t in tags_list:
        _vprint(verbose, f"  - tag: {t.get('name')}")
        create_tag(
            host,
            api_key,
            vsys,
            name=str(t["name"]),
            color=t.get("color"),
            comments=t.get("comments"),
            verify_ssl=verify_ssl,
        )

    addrs_list = objects.get("addresses", [])
    _vprint(verbose, f"[apply] creating {len(addrs_list)} address(es)...")
    for addr in addrs_list:
        _vprint(verbose, f"  - address: {addr.get('name')}")
        create_address(host, api_key, vsys, addr, verify_ssl)

    ag_list = objects.get("address_groups", [])
    _vprint(verbose, f"[apply] creating {len(ag_list)} address group(s)...")
    for ag in ag_list:
        _vprint(verbose, f"  - address-group: {ag.get('name')}")
        create_address_group(host, api_key, vsys, ag, verify_ssl)

    svc_list = objects.get("services", [])
    _vprint(verbose, f"[apply] creating {len(svc_list)} service(s)...")
    for svc in svc_list:
        _vprint(verbose, f"  - service: {svc.get('name')}")
        create_service(host, api_key, vsys, svc, verify_ssl)

    sg_list = objects.get("service_groups", [])
    _vprint(verbose, f"[apply] creating {len(sg_list)} service group(s)...")
    for sg in sg_list:
        _vprint(verbose, f"  - service-group: {sg.get('name')}")
        create_service_group(host, api_key, vsys, sg, verify_ssl)

    policies = data.get("policies") or {}
    sec_rules = policies.get("security", [])
    _vprint(verbose, f"[apply] creating {len(sec_rules)} security rule(s)...")
    for rule in sec_rules:
        _vprint(verbose, f"  - security-rule: {rule.get('name')}")
        create_security_rule(host, api_key, vsys, rule, verify_ssl)

    if do_commit:
        _vprint(verbose, "[apply] committing changes...")
        _api_op(host, api_key, "<commit></commit>", verify_ssl)
        print("Commit initiated.", flush=True)
    else:
        print("Skipped commit (--no-commit).", flush=True)


def delete_all_from_inventory(
    inventory_path: str, device_name: Optional[str], api_key: str, verify_ssl_flag: Optional[bool], do_commit: bool, strict: bool = False
) -> None:
    data = load_yaml(inventory_path)
    devices = data.get("devices") or []
    if not devices: raise ValueError("No devices found")
    
    device = devices[0]
    if device_name:
        matches = [d for d in devices if str(d.get("name")) == device_name]
        if not matches: raise KeyError(f"Device '{device_name}' not found")
        device = matches[0]

    host, vsys = str(device.get("host") or "").strip(), str(device.get("vsys") or DEFAULT_VSYS)
    verify_ssl = bool(device.get("verify_ssl", False))
    if verify_ssl_flag is not None: verify_ssl = verify_ssl_flag

    def safe_delete(kind: str, name: str, func):
        try:
            func(host, api_key, vsys, name, verify_ssl)
        except Exception as e:
            if strict: raise
            print(f"Warning: failed to delete {kind} '{name}': {e}", file=sys.stderr)

    objects, policies = data.get("objects", {}), data.get("policies", {})
    for rule in policies.get("security", []):
        if "name" in rule: safe_delete("security-rule", str(rule["name"]), delete_security_rule)
    for sg in objects.get("service_groups", []):
        if "name" in sg: safe_delete("service-group", str(sg["name"]), delete_service_group)
    for svc in objects.get("services", []):
        if "name" in svc: safe_delete("service", str(svc["name"]), delete_service)
    for ag in objects.get("address_groups", []):
        if "name" in ag: safe_delete("address-group", str(ag["name"]), delete_address_group)
    for addr in objects.get("addresses", []):
        if "name" in addr: safe_delete("address", str(addr["name"]), delete_address)
    for t in objects.get("tags", []):
        if "name" in t: safe_delete("tag", str(t["name"]), delete_tag)

    if do_commit:
        _api_op(host, api_key, "<commit/>", verify_ssl=verify_ssl)
        print("Deletion committed.")
    else:
        print("Deleted (commit skipped by --no-commit).")


def main(argv: List[str]) -> int:
    print("[cli] starting main()", flush=True)
    parser = argparse.ArgumentParser(description="PAN-OS object and policy creator from YAML")
    sub = parser.add_subparsers(dest="command", required=True)

    # --- apply command ---
    p_apply = sub.add_parser("apply", help="Apply objects and policies from YAML inventory")
    p_apply.add_argument("--inventory", required=True, help="Path to inventory YAML")
    p_apply.add_argument("--device", help="Device name to target (defaults to first)")
    p_apply.add_argument("--verify-ssl", action="store_true")
    p_apply.add_argument("--no-commit", action="store_true")
    p_apply.add_argument("--verbose", action="store_true")
    p_apply.add_argument("--debug", action="store_true")

    # --- health command ---
    p_health = sub.add_parser("health", help="Test API connectivity")
    p_health.add_argument("--inventory", required=True, help="Path to inventory YAML")
    p_health.add_argument("--device", help="Device name to target")
    p_health.add_argument("--verify-ssl", action="store_true")

    # --- delete-all command ---
    p_del_all = sub.add_parser("delete-all", help="Delete all items from inventory")
    p_del_all.add_argument("--inventory", required=True, help="Path to inventory YAML")
    p_del_all.add_argument("--device", help="Device name to target")
    p_del_all.add_argument("--verify-ssl", action="store_true")
    p_del_all.add_argument("--no-commit", action="store_true")
    p_del_all.add_argument("--strict", action="store_true", help="Fail fast on the first error")

    # --- delete command ---
    p_delete = sub.add_parser("delete", help="Delete a single item")
    p_delete.add_argument("--inventory", required=True, help="Path to inventory YAML")
    p_delete.add_argument("--device", help="Device name to target")
    p_delete.add_argument("--verify-ssl", action="store_true")
    p_delete.add_argument("--no-commit", action="store_true")
    p_delete.add_argument("--kind", required=True, choices=["address", "address-group", "service", "service-group", "tag", "security-rule"])
    p_delete.add_argument("--name", required=True, help="Name of the object or rule to delete")
    
    args = parser.parse_args(argv)
    print(f"[cli] parsed command: {args.command}", flush=True)

    # --- Command Dispatch Logic ---
    api_key = os.getenv(API_KEY_ENV)
    if not api_key:
        print(f"Error: environment variable {API_KEY_ENV} is not set", file=sys.stderr, flush=True)
        return 2

    if not os.path.isfile(args.inventory):
        print(f"Error: inventory file not found: {args.inventory}", file=sys.stderr, flush=True)
        return 2

    try:
        if args.command == "apply":
            _vprint(bool(args.verbose), "[apply] starting ...")
            apply_inventory(
                inventory_path=args.inventory, device_name=args.device, api_key=api_key,
                verify_ssl_flag=bool(args.verify_ssl), do_commit=not args.no_commit,
                verbose=bool(args.verbose)
            )
            print("Apply completed.", flush=True)

        elif args.command == "health":
            data = load_yaml(args.inventory)
            devices = data.get("devices") or []
            if not devices: raise ValueError("No devices in inventory")
            dev = devices[0]
            if args.device:
                matches = [d for d in devices if str(d.get("name")) == args.device]
                if not matches: raise KeyError(f"Device '{args.device}' not found")
                dev = matches[0]
            host = str(dev.get("host") or "").strip()
            if not host: raise ValueError("Device host missing")
            verify_ssl = bool(dev.get("verify_ssl", False)) or bool(args.verify_ssl)
            print(f"[health] contacting {host} (verify_ssl={verify_ssl}) ...", flush=True)
            _op_show_system_info(host, api_key, verify_ssl)
            print("[health] success: API reachable and authenticated.", flush=True)

        elif args.command == "delete-all":
            delete_all_from_inventory(
                inventory_path=args.inventory, device_name=args.device, api_key=api_key,
                verify_ssl_flag=bool(args.verify_ssl), do_commit=not args.no_commit,
                strict=bool(args.strict)
            )

        elif args.command == "delete":
            data = load_yaml(args.inventory)
            devices = data.get("devices") or []
            if not devices: raise ValueError("No devices in inventory")
            dev = devices[0]
            if args.device:
                matches = [d for d in devices if str(d.get("name")) == args.device]
                if not matches: raise KeyError(f"Device '{args.device}' not found")
                dev = matches[0]
            host, vsys = str(dev.get("host") or "").strip(), str(dev.get("vsys") or DEFAULT_VSYS)
            verify_ssl = bool(dev.get("verify_ssl", False)) or bool(args.verify_ssl)

            delete_map = {
                "address": delete_address, "address-group": delete_address_group,
                "service": delete_service, "service-group": delete_service_group,
                "tag": delete_tag, "security-rule": delete_security_rule,
            }
            delete_func = delete_map[args.kind]
            delete_func(host, api_key, vsys, args.name, verify_ssl)
            
            if not args.no_commit:
                _api_op(host, api_key, "<commit/>", verify_ssl=verify_ssl)
                print("Deletion committed.", flush=True)
            else:
                print("Deleted (commit skipped by --no-commit).", flush=True)

    except Exception as e:
        if getattr(args, "debug", False):
            traceback.print_exc()
        print(f"Error: {e}", file=sys.stderr, flush=True)
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
