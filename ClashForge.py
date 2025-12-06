# -*- coding: utf-8 -*-
import base64
import subprocess
import threading
import time
import urllib.parse
import json
import glob
import re
import yaml
import random
import string
from itertools import chain
from typing import Dict, List, Optional
import sys
import requests
import zipfile
import gzip
import shutil
import platform
import os
from datetime import datetime

# Constants
LIMIT = 286 
CONFIG_FILE = 'data/clash_config.yaml'
INPUT = "input" # 目录定义保留，但此脚本中不使用
BAN = ["中国", "China", "CN", "电信", "移动", "联通"] # 节点名称过滤列表
HEADERS = {
    'Accept-Charset': 'utf-8',
    'Accept': 'text/html,application/x-yaml,*/*',
    'User-Agent': 'Clash Verge/1.7.7'
}

# Clash Configuration Template - 简化版
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

# --- 代理解析函数 (保持不变) ---

def parse_hysteria2_link(link):
    """Parses a Hysteria2 link into a proxy dictionary."""
    # print(f"Parsing Hysteria2 link: {link}")
    try:
        parsed_url = urllib.parse.urlparse(link)
        server = parsed_url.hostname
        port = parsed_url.port
        params = urllib.parse.parse_qs(parsed_url.query)
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{server}:{port}"
        password = parsed_url.username or params.get('password', [''])[0]
        obfs = params.get('obfs', [''])[0]
        obfs_param = params.get('obfs-param', [''])[0]
        protocol = params.get('protocol', ['udp'])[0]
        up = params.get('up', [''])[0]
        down = params.get('down', [''])[0]
        alpn = params.get('alpn', [''])[0]
        fast_open = params.get('fast-open', ['false'])[0].lower() == 'true'
        mptcp = params.get('mptcp', ['false'])[0].lower() == 'true'

        return {
            'name': name,
            'type': 'hysteria2',
            'server': server,
            'port': port,
            'password': password,
            'obfs': obfs if obfs else None,
            'obfs-param': obfs_param if obfs_param else None,
            'protocol': protocol,
            'up': up if up else None,
            'down': down if down else None,
            'alpn': [a.strip() for a in alpn.split(',')] if alpn else None,
            'fast-open': fast_open,
            'mptcp': mptcp,
        }
    except Exception as e:
        print(f"Error parsing Hysteria2 link {link}: {e}")
        return None

def parse_ss_link(link):
    """Parses a Shadowsocks link into a proxy dictionary."""
    # print(f"Parsing SS link: {link}")
    try:
        parsed_url = urllib.parse.urlparse(link)
        encoded_userinfo = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{server}:{port}"

        if encoded_userinfo:
            missing_padding = len(encoded_userinfo) % 4
            if missing_padding:
                encoded_userinfo += '=' * (4 - missing_padding)

            decoded_userinfo = base64.b64decode(encoded_userinfo).decode('utf-8')
            method, password = decoded_userinfo.split(':', 1)
        else:
            method = None
            password = None
            
        return {
            'name': name,
            'type': 'ss',
            'server': server,
            'port': port,
            'cipher': method,
            'password': password,
        }
    except Exception as e:
        print(f"Error parsing SS link {link}: {e}")
        return None


def parse_trojan_link(link):
    """Parses a Trojan link into a proxy dictionary."""
    # print(f"Parsing Trojan link: {link}")
    try:
        parsed_url = urllib.parse.urlparse(link)
        password = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{server}:{port}"
        params = urllib.parse.parse_qs(parsed_url.query)

        sni = params.get('sni', [None])[0]
        alpn = params.get('alpn', [None])[0]
        # Trojan link often uses 'allowInsecure' which maps to 'skip-cert-verify' in Clash
        allow_insecure = params.get('allowInsecure', ['0'])[0] 
        skip_cert_verify = params.get('skip-cert-verify', ['false'])[0].lower() == 'true' or allow_insecure == '1'
        
        # Handle transport (network type) parameters if present in query
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
        # Add other types if necessary

        proxy_dict = {
            'name': name,
            'type': 'trojan',
            'server': server,
            'port': port,
            'password': password,
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
    """Parses a VLESS link into a proxy dictionary."""
    # print(f"Parsing VLESS link: {link}")
    try:
        parsed_url = urllib.parse.urlparse(link)
        uuid = parsed_url.username
        server = parsed_url.hostname
        port = parsed_url.port
        name = urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f"{server}:{port}"
        params = urllib.parse.parse_qs(parsed_url.query)

        flow = params.get('flow', [None])[0]
        encryption = params.get('encryption', [None])[0]
        security = params.get('security', [None])[0]
        sni = params.get('sni', [None])[0]
        alpn = params.get('alpn', [None])[0]
        fp = params.get('fp', [None])[0]
        type_param = params.get('type', ['tcp'])[0]

        ws_path = params.get('path', [None])[0]
        ws_headers_str = params.get('host', [None])[0]
        ws_headers = {}
        if ws_headers_str:
             ws_headers['Host'] = ws_headers_str.strip()


        grpc_service_name = params.get('serviceName', [None])[0]

        tls_settings = {}
        if security == 'tls' or security == 'xtls':
             tls_settings = {
                 'serverName': sni if sni else server,
                 'sni': sni if sni else None,
                 'alpn': [a.strip() for a in alpn.split(',')] if alpn else None,
                 'fingerprint': fp if fp else None,
                 'skip-cert-verify': params.get('allowInsecure', ['0'])[0] == '1' 
             }
             if security == 'xtls':
                 tls_settings['enable_xtls'] = True
                 tls_settings['flow'] = flow if flow else 'xtls-rprx-vision'

        network_settings = {}
        if type_param == 'ws':
             network_settings = {
                 'path': ws_path,
                 'headers': ws_headers if ws_headers else None
             }
        elif type_param == 'grpc':
             network_settings = {
                 'serviceName': grpc_service_name,
             }

        proxy_dict = {
            'name': name,
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'encryption': encryption if encryption else 'none',
            'network': type_param,
            **tls_settings,
            **network_settings
        }

        return {k: v for k, v in proxy_dict.items() if v is not None}

    except Exception as e:
        print(f"Error parsing VLESS link {link}: {e}")
        return None


def parse_vmess_link(link):
    """Parses a VMESS link into a proxy dictionary."""
    # print(f"Parsing VMESS link: {link}")
    try:
        if not link.startswith("vmess://"):
            return None

        encoded_json = link[8:]
        missing_padding = len(encoded_json) % 4
        if missing_padding:
            encoded_json += '=' * (4 - missing_padding)

        decoded_json_str = base64.b64decode(encoded_json).decode('utf-8')
        config = json.loads(decoded_json_str)

        name = config.get('ps', f"{config.get('add')}:{config.get('port')}")
        server = config.get('add')
        port = config.get('port')
        uuid = config.get('id')
        alterId = config.get('aid', 0)
        cipher = config.get('scy', 'auto')
        network = config.get('net', 'tcp')
        host = config.get('host')
        path = config.get('path')
        tls = config.get('tls', '')
        sni = config.get('sni')
        alpn = config.get('alpn')
        skip_cert_verify = config.get('allowInsecure', 0) == 1

        proxy_dict = {
            'name': name,
            'type': 'vmess',
            'server': server,
            'port': port,
            'uuid': uuid,
            'alterId': alterId,
            'cipher': cipher,
            'network': network,
            'tls': tls.lower() == 'tls',
            'skip-cert-verify': skip_cert_verify,
            
            # Network specific settings
            'ws-path': path if network == 'ws' else None,
            'ws-headers': {'Host': host} if network == 'ws' and host else None,
            'grpc-serviceName': path if network == 'grpc' else None,
            
            # TLS specific settings
            'servername': sni if sni else (host if network == 'ws' else None),
            'alpn': [a.strip() for a in alpn.split(',')] if alpn else None,
            'host': host if network != 'ws' else None
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
        if missing_padding:
            content += '=' * (4 - missing_padding)

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
    if link.startswith("ss://"):
        return parse_ss_link(link)
    elif link.startswith("vmess://"):
        return parse_vmess_link(link)
    elif link.startswith("vless://"):
        return parse_vless_link(link)
    elif link.startswith("trojan://"):
        return parse_trojan_link(link)
    elif link.startswith("hysteria2://"):
        return parse_hysteria2_link(link)
    else:
        # print(f"Unsupported link scheme: {link}") # Suppress repetitive output
        return None

# --- 辅助功能函数 (保持不变) ---

def deduplicate_proxies(proxies_list):
    """Deduplicates a list of proxy dictionaries based on a unique key."""
    seen_keys = set()
    unique_proxies = []
    # ... (deduplication logic)
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

def read_txt_files(folder_path):
    # 保持原函数，但 work_no_check 将不再调用它
    all_lines = []
    txt_files = glob.glob(os.path.join(folder_path, '*.txt'))
    for file_path in txt_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                all_lines.extend(line.strip() for line in file.readlines() if line.strip())
        except Exception as e:
            print(f"Error reading txt file {file_path}: {e}")
    return all_lines

def read_yaml_files(folder_path):
    # 保持原函数，但 work_no_check 将不再调用它
    load_nodes = []
    yaml_files = glob.glob(os.path.join(folder_path, '*.yaml')) + glob.glob(os.path.join(folder_path, '*.yml'))
    for file_path in yaml_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file)
                if isinstance(config, dict) and "proxies" in config and isinstance(config["proxies"], list):
                    load_nodes.extend(config["proxies"])
                else:
                    print(f"Warning: {file_path} does not contain a valid 'proxies' list.")
        except Exception as e:
            print(f"Error reading yaml file {file_path}: {e}")
    return load_nodes

def filter_by_types_alt(allowed_types, nodes):
    """Filters a list of nodes by their type."""
    if not allowed_types:
        return nodes
    return [x for x in nodes if isinstance(x, dict) and x.get('type') in allowed_types]

def merge_lists(*lists):
    """Merges multiple lists, filtering out empty strings."""
    return [item for item in chain.from_iterable(lists) if item != '']

def not_contains(s):
    """Checks if a string contains any banned keywords."""
    if not isinstance(s, str):
        return True
    return not any(k in s for k in BAN)

# --- 核心逻辑函数 (已修复链接处理和简化输入) ---

def generate_clash_config(links, load_nodes, allowed_types):
    """
    Generates Clash configuration from links and loaded nodes.
    注意：links 中传入的应该是经过 merge_lists 清理后的列表。
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

    # Process nodes loaded from YAML files (这里 load_nodes 应该为空)
    for node in load_nodes:
        add_proxy_with_name_check(node)

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
                # --- 针对 raw 文本链接列表文件：下载并按行解析 ---
                print(f"尝试从 raw 链接列表文件下载并解析: {link}")
                try:
                    response = requests.get(link, headers=HEADERS, timeout=10)
                    response.raise_for_status()
                    content_lines = [line.strip() for line in response.text.splitlines() if line.strip()]
                    
                    print(f"文件中检测到 {len(content_lines)} 条潜在链接。")
                    for found_link in content_lines:
                        # 尝试解析每一行，这会解决您遇到的 'Unsupported link scheme: trojan' 问题
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
                         if node:
                            add_proxy_with_name_check(node)
                
            else:
                # Fallback to general URL processing (e.g., web scraping)
                print(f"Processing general URL (using regex/match_nodes): {link}")
                found_links = process_url(link)
                for found_link in found_links:
                    node = parse_proxy_link(found_link)
                    if node:
                        add_proxy_with_name_check(node)

        elif link.strip(): 
            print(f"跳过无法解析的链接或行: {link}")


    # 后续的去重、过滤、配置生成逻辑保持不变
    final_proxies = deduplicate_proxies(all_collected_proxies)

    if allowed_types:
        final_proxies = filter_by_types_alt(allowed_types, final_proxies)
        print(f"Filtered to {len(final_proxies)} nodes by types: {allowed_types}")

    config = CLASH_CONFIG_TEMPLATE.copy()
    config["proxies"] = final_proxies
    proxy_names = [p['name'] for p in final_proxies]

    select_group_index = -1
    auto_select_group_index = -1
    fallback_group_index = -1

    for i, group in enumerate(config["proxy-groups"]):
        if group.get("name") == "节点选择": select_group_index = i
        elif group.get("name") == "自动选择": auto_select_group_index = i
        elif group.get("name") == "Fallback": fallback_group_index = i

    if select_group_index != -1: config["proxy-groups"][select_group_index]["proxies"] = ["自动选择", "Fallback", "DIRECT", "REJECT"] + proxy_names
    else: print("Warning: '节点选择' proxy group not found in template.")

    if auto_select_group_index != -1: config["proxy-groups"][auto_select_group_index]["proxies"] = proxy_names
    else: print("Warning: '自动选择' proxy group not found in template.")

    if fallback_group_index != -1: config["proxy-groups"][fallback_group_index]["proxies"] = proxy_names
    else: print("Warning: 'Fallback' proxy group not found in template.")

    data_dir = os.path.dirname(CONFIG_FILE)
    if data_dir and not os.path.exists(data_dir): os.makedirs(data_dir, exist_ok=True)

    if config["proxies"]:
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False) 
            print(f"✅ 已生成Clash配置文件: {CONFIG_FILE}")
        except Exception as e:
            print(f"Error saving YAML config {CONFIG_FILE}: {e}")

        try:
            json_config_file = f'{CONFIG_FILE}.json'
            with open(json_config_file, "w", encoding="utf-8") as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
            print(f"✅ 已生成Clash配置文件: {json_config_file}")
        except Exception as e:
            print(f"Error saving JSON config {json_config_file}: {e}")

    else:
        print('❌ 没有节点数据更新，未生成配置文件。')


def work_no_check(links, allowed_types=[]):
    """
    Main function to handle the work without node availability checks.
    只处理 links 列表中的链接，忽略 input 目录。
    """
    try:
        # 1. 忽略 INPUT 目录的现有节点和本地链接
        load_nodes = [] # 不从 INPUT 目录加载现有节点
        
        # 2. 只使用传入的 links 列表，并清理空字符串
        all_links = merge_lists(links)
        
        print(f"已忽略 INPUT 目录内容。")
        print(f"总共收集到 {len(all_links)} 条待处理链接。")

        # Generate Clash configuration directly from collected links and nodes
        if all_links or load_nodes:
            generate_clash_config(all_links, load_nodes, allowed_types)
        else:
            print("没有链接或现有节点可供处理，退出。")

    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        print(f"程序执行失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    # Define initial links (can be subscription URLs, raw proxy links, or file URLs)
    links = [
        "", 
        "https://raw.githubusercontent.com/qjlxg/pin/refs/heads/main/trojan_links.txt", # 示例原始链接文件
        # 添加更多链接或 URL...
    ]

    # Define allowed proxy types for filtering (optional)
    allowed_types_filter = ["ss", "hysteria2", "vless", "vmess", "trojan"]

    # Run the main work function without node checking
    work_no_check(links, allowed_types=allowed_types_filter)
