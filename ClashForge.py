# -*- coding: utf-8 -*-
import base64
import urllib.parse
import json
import re
import yaml
import random
import string
from itertools import chain
from typing import Dict, List
import sys
import requests
import os
from datetime import datetime

# Constants
CONFIG_FILE = 'data/clash_config.yaml'
# INPUT 目录相关函数已被删除，但 BAN 列表等仍保留
BAN = ["中国", "China", "CN", "电信", "移动", "联通"] # 节点名称过滤列表
HEADERS = {
    'Accept-Charset': 'utf-8',
    'Accept': 'text/html,application/x-yaml,*/*',
    'User-Agent': 'Clash Verge/1.7.7'
}

# Clash Configuration Template
CLASH_CONFIG_TEMPLATE = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "geodata-mode": True,
    "dns": {
        "enable": True,
        "ipv6": False,
        "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    },
    "proxies": [],
    "proxy-groups": [
        {"name": "节点选择", "type": "select", "proxies": []},
        {"name": "自动选择", "type": "url-test", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": []},
        {"name": "Fallback", "type": "fallback", "url": "http://www.gstatic.com/generate_204", "interval": 300, "proxies": []},
        {"name": "DIRECT", "type": "direct"},
        {"name": "REJECT", "type": "reject"}
    ],
    "rules": [
        "MATCH,节点选择"
    ]
}

# --- 代理解析函数 ---

def parse_hysteria2_link(link):
    """Parses a Hysteria2 link."""
    try:
        parsed_url = urllib.parse.urlparse(link)
        server = parsed_url.hostname
        port = parsed_url.port
        params = urllib.parse.parse_qs(parsed_url.query)
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{server}:{port}"
        password = parsed_url.username or params.get('password', [''])[0]
        obfs = params.get('obfs', [''])[0]
        alpn = params.get('alpn', [''])[0]
        fast_open = params.get('fast-open', ['false'])[0].lower() == 'true'

        return {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'obfs': obfs if obfs else None,
            'alpn': [a.strip() for a in alpn.split(',')] if alpn else None,
            'fast-open': fast_open,
        }
    except Exception as e:
        print(f"Error parsing Hysteria2 link {link}: {e}")
        return None

def parse_ss_link(link):
    """Parses a Shadowsocks link."""
    try:
        parsed_url = urllib.parse.urlparse(link)
        encoded_userinfo = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{server}:{port}"

        method, password = None, None
        if encoded_userinfo:
            missing_padding = len(encoded_userinfo) % 4
            if missing_padding: encoded_userinfo += '=' * (4 - missing_padding)
            decoded_userinfo = base64.b64decode(encoded_userinfo).decode('utf-8')
            method, password = decoded_userinfo.split(':', 1)
            
        return {
            'name': name, 'type': 'ss', 'server': server, 'port': port,
            'cipher': method, 'password': password,
        }
    except Exception as e:
        print(f"Error parsing SS link {link}: {e}")
        return None


def parse_trojan_link(link):
    """Parses a Trojan link."""
    try:
        parsed_url = urllib.parse.urlparse(link)
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{server}:{port}"
        params = urllib.parse.parse_qs(parsed_url.query)

        sni = params.get('sni', [None])[0]
        alpn = params.get('alpn', [None])[0]
        allow_insecure = params.get('allowInsecure', ['0'])[0] 
        skip_cert_verify = params.get('skip-cert-verify', ['false'])[0].lower() == 'true' or allow_insecure == '1'
        
        type_param = params.get('type', ['tcp'])[0]
        host = params.get('host', [None])[0]
        path = params.get('path', [None])[0]
        
        network_settings = {}
        if type_param == 'ws':
             network_settings = {
                 'network': 'ws',
                 'ws-path': path,
                 'ws-headers': {'Host': host} if host else None
             }

        proxy_dict = {
            'name': name, 'type': 'trojan', 'server': server, 'port': port, 'password': password,
            'sni': sni if sni else None,
            'alpn': [a.strip() for a in alpn.split(',')] if alpn else None,
            'skip-cert-verify': skip_cert_verify,
            **network_settings
        }
        return {k: v for k, v in proxy_dict.items() if v is not None}
    except Exception as e:
        print(f"Error parsing Trojan link {link}: {e}")
        return None


def parse_vless_link(link):
    """Parses a VLESS link."""
    try:
        parsed_url = urllib.parse.urlparse(link)
        uuid = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{server}:{port}"
        params = urllib.parse.parse_qs(parsed_url.query)

        security = params.get('security', [None])[0]
        sni = params.get('sni', [None])[0]
        alpn = params.get('alpn', [None])[0]
        type_param = params.get('type', ['tcp'])[0]
        ws_path = params.get('path', [None])[0]
        ws_headers_str = params.get('host', [None])[0]

        tls_settings = {}
        if security == 'tls' or security == 'xtls':
             tls_settings = {
                 'serverName': sni if sni else server,
                 'sni': sni if sni else None,
                 'alpn': [a.strip() for a in alpn.split(',')] if alpn else None,
                 'skip-cert-verify': params.get('allowInsecure', ['0'])[0] == '1' 
             }
        
        network_settings = {}
        if type_param == 'ws':
             network_settings = {'path': ws_path, 'headers': {'Host': ws_headers_str} if ws_headers_str else None}

        proxy_dict = {
            'name': name, 'type': 'vless', 'server': server, 'port': port, 'uuid': uuid, 
            'encryption': params.get('encryption', ['none'])[0], 'network': type_param,
            **tls_settings, **network_settings
        }
        return {k: v for k, v in proxy_dict.items() if v is not None}

    except Exception as e:
        print(f"Error parsing VLESS link {link}: {e}")
        return None


def parse_vmess_link(link):
    """Parses a VMESS link."""
    try:
        if not link.startswith("vmess://"): return None
        encoded_json = link[8:]
        missing_padding = len(encoded_json) % 4
        if missing_padding: encoded_json += '=' * (4 - missing_padding)

        config = json.loads(base64.b64decode(encoded_json).decode('utf-8'))
        
        name = config.get('ps', f"{config.get('add')}:{config.get('port')}")
        server = config.get('add')
        port = config.get('port')
        uuid = config.get('id')
        alterId = config.get('aid', 0)
        network = config.get('net', 'tcp')
        tls = config.get('tls', '').lower() == 'tls'
        
        proxy_dict = {
            'name': name, 'type': 'vmess', 'server': server, 'port': port, 
            'uuid': uuid, 'alterId': alterId, 'cipher': config.get('scy', 'auto'),
            'network': network, 'tls': tls, 
            'skip-cert-verify': config.get('allowInsecure', 0) == 1,
            'ws-path': config.get('path') if network == 'ws' else None,
            'ws-headers': {'Host': config.get('host')} if network == 'ws' and config.get('host') else None,
            'servername': config.get('sni') or (config.get('host') if network == 'ws' else None),
        }

        return {k: v for k, v in proxy_dict.items() if v is not None}

    except Exception as e:
        print(f"Error parsing VMESS link {link}: {e}")
        return None

def parse_ss_sub(link):
    """Parses a Shadowsocks subscription link (base64 encoded SS links)."""
    print(f"Parsing SS sub link: {link}")
    try:
        response = requests.get(link, headers=HEADERS, timeout=10)
        response.raise_for_status()
        content = response.text.strip()

        missing_padding = len(content) % 4
        if missing_padding: content += '=' * (4 - missing_padding)

        decoded_content = base64.b64decode(content).decode('utf-8')
        ss_links = [line.strip() for line in decoded_content.splitlines() if line.strip()]
        
        return [parse_ss_link(ss_link) for ss_link in ss_links if ss_link.startswith("ss://")]
    except Exception as e:
        print(f"Error processing SS subscription link {link}: {e}")
        return []

def process_url(url):
    """Processes a general URL to find proxy links using regex."""
    print(f"Processing general URL (using regex): {url}")
    try:
        response = requests.get(url, headers=HEADERS, timeout=10)
        response.raise_for_status()
        content = response.text
        
        full_link_pattern = r"(ss|vmess|vless|trojan|hysteria2):\/\/[^\s]+"
        final_links = re.findall(full_link_pattern, content)
        
        return final_links
    except Exception as e:
        print(f"Error processing URL {url}: {e}")
        return []

def parse_proxy_link(link):
    """Parses a single proxy link based on its scheme."""
    link = link.strip()
    if link.startswith("ss://"): return parse_ss_link(link)
    elif link.startswith("vmess://"): return parse_vmess_link(link)
    elif link.startswith("vless://"): return parse_vless_link(link)
    elif link.startswith("trojan://"): return parse_trojan_link(link)
    elif link.startswith("hysteria2://"): return parse_hysteria2_link(link)
    else: return None

# --- 辅助功能函数 ---

def deduplicate_proxies(proxies_list):
    """Deduplicates a list of proxy dictionaries based on a unique key."""
    seen_keys = set()
    unique_proxies = []
    for proxy in proxies_list:
        if not isinstance(proxy, dict): continue
        proxy_type = proxy.get('type')
        server = proxy.get('server')
        port = proxy.get('port')
        identifier = proxy.get('uuid') or proxy.get('password') or f"{proxy.get('cipher')}"
        proxy_key = (proxy_type, server, port, identifier)
        if None not in proxy_key and proxy_key not in seen_keys:
            unique_proxies.append(proxy)
            seen_keys.add(proxy_key)

    print(f"Deduplicated {len(proxies_list)} proxies to {len(unique_proxies)}")
    return unique_proxies

def add_random_suffix(name, existing_names):
    """Adds a random suffix to a name to avoid conflicts."""
    original_name = name
    name_to_check = original_name
    
    if name_to_check in existing_names:
        print(f"Conflict found for name: {original_name}. Resolving...")
        while name_to_check in existing_names:
            suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=4))
            name_to_check = f"{original_name}_{suffix}"
    
    existing_names.add(name_to_check)
    return name_to_check

def filter_by_types_alt(allowed_types, nodes):
    """Filters a list of nodes by their type."""
    if not allowed_types: return nodes
    return [x for x in nodes if isinstance(x, dict) and x.get('type') in allowed_types]

def merge_lists(*lists):
    """Merges multiple lists, filtering out empty strings."""
    return [item for item in chain.from_iterable(lists) if item != '']

def not_contains(s):
    """Checks if a string contains any banned keywords."""
    if not isinstance(s, str): return True
    return not any(k in s for k in BAN)

# --- 核心逻辑函数 ---

def generate_clash_config(links, allowed_types):
    """
    Generates Clash configuration only from the provided links list.
    """
    print("Generating Clash configuration...")
    all_collected_proxies = []
    existing_names = set()

    def add_proxy_with_name_check(node):
        if not isinstance(node, dict): return
        if not node.get('name'):
             node['name'] = f"{node.get('type', 'unknown')}-{node.get('server', 'unknown')}:{node.get('port', 'unknown')}"
        original_name = str(node["name"])
        if not_contains(original_name):
            node["name"] = add_random_suffix(original_name, existing_names)
            all_collected_proxies.append(node)
        else:
            print(f"Skipping node with banned keyword in name: {original_name}")

    # Process links from the input list
    for link in links:
        link = link.strip()
        if not link: continue
            
        if link.startswith(("ss://", "vmess://", "vless://", "trojan://", "hysteria2://")):
            # Case 1: Raw, single proxy link - direct parsing
            node = parse_proxy_link(link)
            if node:
                add_proxy_with_name_check(node)
        
        elif link.startswith(("http://", "https://")):
            # Case 2: Subscription or file URL
            if link.endswith(('.txt', '.list', '.conf')):
                print(f"尝试从 raw 链接列表文件下载并解析: {link}")
                try:
                    response = requests.get(link, headers=HEADERS, timeout=10)
                    response.raise_for_status()
                    content_lines = [line.strip() for line in response.text.splitlines() if line.strip()]
                    
                    print(f"文件中检测到 {len(content_lines)} 条潜在链接。")
                    for found_link in content_lines:
                        node = parse_proxy_link(found_link) 
                        if node:
                            add_proxy_with_name_check(node)
                except requests.exceptions.RequestException as re:
                    print(f"请求错误处理 raw 链接列表 URL {link}: {re}")
                except Exception as e:
                    print(f"Error fetching/processing raw link list URL {link}: {e}")
                    
            elif 'base64' in link.lower() and link.startswith('http'):
                if 'ss' in link.lower() or 'sub' in link.lower():
                     print(f"尝试处理 SS Base64 订阅: {link}")
                     nodes = parse_ss_sub(link) 
                     for node in nodes:
                         if node: add_proxy_with_name_check(node)
                
            else:
                print(f"Processing general URL (using regex): {link}")
                found_links = process_url(link)
                for found_link in found_links:
                    node = parse_proxy_link(found_link)
                    if node: add_proxy_with_name_check(node)

        elif link.strip(): 
            print(f"跳过无法解析的链接或行: {link}")

    # Deduplicate, filter, and save config
    final_proxies = deduplicate_proxies(all_collected_proxies)
    if allowed_types:
        final_proxies = filter_by_types_alt(allowed_types, final_proxies)
        print(f"Filtered to {len(final_proxies)} nodes by types: {allowed_types}")

    config = CLASH_CONFIG_TEMPLATE.copy()
    config["proxies"] = final_proxies
    proxy_names = [p['name'] for p in final_proxies]

    # Populate proxy groups
    for group in config["proxy-groups"]:
        if group.get("name") == "节点选择": group["proxies"] = ["自动选择", "Fallback", "DIRECT", "REJECT"] + proxy_names
        elif group.get("name") == "自动选择": group["proxies"] = proxy_names
        elif group.get("name") == "Fallback": group["proxies"] = proxy_names
    
    # Save files
    data_dir = os.path.dirname(CONFIG_FILE)
    if data_dir and not os.path.exists(data_dir): os.makedirs(data_dir, exist_ok=True)

    if config["proxies"]:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False) 
            print(f"✅ 已生成Clash配置文件: {CONFIG_FILE}")
            json_config_file = f'{CONFIG_FILE}.json'
            with open(json_config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            print(f"✅ 已生成Clash配置文件: {json_config_file}")
        except Exception as e:
            print(f"Error saving config files: {e}")
    else:
        print('❌ 没有节点数据更新，未生成配置文件。')


def work_no_check(links, allowed_types=[]):
    """
    Main function. 只处理 links 列表中的链接。
    """
    try:
        # 只使用传入的 links 列表，并清理空字符串
        all_links = merge_lists(links)
        
        print(f"总共收集到 {len(all_links)} 条待处理链接。")

        if all_links:
            generate_clash_config(all_links, allowed_types)
        else:
            print("没有链接可供处理，退出。")

    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        print(f"程序执行失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # Define initial links
    links = [
        "https://raw.githubusercontent.com/qjlxg/pin/refs/heads/main/base64.txt", 
    ]

    # Define allowed proxy types for filtering (optional)
    allowed_types_filter = ["ss", "hysteria2", "vless", "vmess", "trojan"]

    # Run the main work function
    work_no_check(links, allowed_types=allowed_types_filter)
