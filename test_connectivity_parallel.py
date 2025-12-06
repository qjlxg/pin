# test_connectivity_parallel.py（终极完整版 - 支持 Trojan / VLess / VMess / Hysteria2 - 2025-12-06）
import os
import sys
import datetime
import pytz
import re
import base64
import json
import tempfile
import shutil
import threading
import time
from concurrent.futures import ThreadPoolExecutor
import subprocess
import requests
from urllib.parse import quote, unquote, urlparse, parse_qs

# --- 配置 ---
REMOTE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/pin/refs/heads/main/trojan_links.txt",
]

TEST_URLS = [
    "http://www.google.com/generate_204",
    "http://www.youtube.com",
    "http://www.microsoft.com",
]

MAX_WORKERS = 38       
NODE_TIMEOUT = 10
MAX_RETRIES = 2
VERBOSE = True          # ← 新增：全局详细日志开关（默认开）

def fetch_and_parse_nodes():
    print("--- 1. 正在获取和解析所有节点 ---")
    all_content = []
    for url in REMOTE_CONFIG_URLS:
        try:
            print(f"下载: {url}")
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            all_content.append(response.text)
        except Exception as e:
            print(f"⚠️ 下载失败: {e}", file=sys.stderr)
    all_lines = "\n".join(all_content).split('\n')
    unique_nodes = set()
    protocol_regex = r'(://|@|\b(vmess|ss|trojan|vless|hysteria2|hy2|tuic)\b|server\s*:\s*.)'
    for line in all_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and re.search(protocol_regex, stripped, re.IGNORECASE):
            cleaned = stripped.replace("ss://ss://", "ss://").replace("vmess://vmess://", "vmess://")
            unique_nodes.add(cleaned)
    all_nodes = list(unique_nodes)
    print(f"修复并过滤后，发现 {len(all_nodes)} 个潜在节点链接。")
    return all_nodes

def test_single_node(node_link):
    temp_dir = None
    clash_process = None
    try:
        temp_dir = tempfile.mkdtemp(prefix="mihomo_test_")
        
        # 提取备注名称（用于日志更清晰）
        proxy_name_final = "UNKNOWN_NODE"
        remark_match = re.search(r'#(.+)', node_link)
        if remark_match:
            try:
                proxy_name_final = re.sub(r'[\'\":\[\]]', '', unquote(remark_match.group(1)).strip())[:60]
            except:
                pass

        if VERBOSE:
            print(f"开始测试 → {proxy_name_final} | {node_link[:80]}{'...' if len(node_link)>80 else ''}")

        for attempt in range(MAX_RETRIES):
            if VERBOSE and MAX_RETRIES > 1:
                print(f"  └─ 第 {attempt+1}/{MAX_RETRIES} 次尝试")

            seed_str = f"{node_link}_{attempt}_{threading.get_ident()}_{int(time.time()*100000)}"
            seed = abs(hash(seed_str)) % 25000
            api_port = 30000 + seed
            proxy_port = 40000 + seed
            unique_id = f"t{threading.get_ident()}_a{attempt}_{seed}"
            config_path = os.path.join(temp_dir, f"config_{unique_id}.yaml")
            log_path = os.path.join(temp_dir, f"mihomo_{unique_id}.log")

            proxy_config_yaml = ""
            protocol = ""

            try:
                url_parts = urlparse(node_link)
                raw_protocol = url_parts.scheme.lower()
                protocol = raw_protocol
                if raw_protocol in ['hy2', 'hysteria2']:
                    protocol = 'hysteria2'

                # ==================== Trojan ====================
                if protocol == 'trojan':
                    # （保持不变，已极稳）
                    password = url_parts.username
                    server = url_parts.hostname
                    port = url_parts.port or 443
                    if not (password and server and port):
                        raise ValueError("Trojan 必要字段缺失")
                    params = parse_qs(url_parts.query)
                    tls_config = "  tls: true\n  skip-cert-verify: false\n"
                    sni = params.get('sni', params.get('peer', ['']))[0] or server
                    if sni:
                        tls_config += f"  servername: {sni}\n"
                    if params.get('allowInsecure', params.get('allowinsecure', ['0']))[0] in ['1', 'true']:
                        tls_config = tls_config.replace("false", "true")
                    ws_config = ""
                    if params.get('type', [''])[0].lower() == 'ws':
                        path = unquote(params.get('path', ['/'])[0])
                        host_header = params.get('host', [sni])[0]
                        ws_config = f"""
  network: ws
  ws-opts:
    path: {path}
    headers:
      Host: {host_header}
"""
                    proxy_config_yaml = f"""
  - name: {proxy_name_final}
    type: trojan
    server: {server}
    port: {port}
    password: {password}
{tls_config}{ws_config}
"""

                # ==================== VLess ====================
                elif protocol == 'vless':
                    # （保持不变，已极稳）
                    uuid = url_parts.username
                    server = url_parts.hostname
                    port = url_parts.port or 443
                    params = parse_qs(url_parts.query)
                    security = params.get('security', ['none'])[0].lower()
                    flow = params.get('flow', [''])[0]
                    network = params.get('type', ['tcp'])[0].lower()
                    sni = params.get('sni', params.get('peer', ['']))[0] or server
                    allow_insecure = params.get('allowInsecure', ['0'])[0] in ['1', 'true']

                    tls_config = ""
                    if security in ['tls', 'reality']:
                        skip_verify = "true" if security == 'reality' or allow_insecure else "false"
                        if security == 'reality':
                            pbk = params.get('pbk', [''])[0]
                            short_id = params.get('sid', params.get('shortId', ['']))[0]
                            if not pbk:
                                raise ValueError("Reality 需要 pbk")
                            tls_config = f"""
    tls: true
    skip-cert-verify: true
    reality-opts:
      public-key: {pbk}
      short-id: {short_id or '0'}
    servername: {sni}
"""
                        else:
                            tls_config = f"""
    tls: true
    skip-cert-verify: {skip_verify}
    servername: {sni}
"""

                    flow_config = f"    flow: {flow}\n" if flow else ""
                    transport_config = ""
                    if network == 'ws':
                        path = unquote(params.get('path', ['/'])[0])
                        host = params.get('host', [sni])[0]
                        transport_config = f"""
    network: ws
    ws-opts:
      path: {path}
      headers:
        Host: {host}
"""
                    elif network == 'grpc':
                        service_name = params.get('serviceName', ['GunService'])[0]
                        transport_config = f"""
    network: grpc
    grpc-opts:
      grpc-service-name: {service_name}
"""

                    proxy_config_yaml = f"""
  - name: {proxy_name_final}
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: true
{flow_config}{tls_config}{transport_config}
"""

                # ==================== VMess ====================
                elif protocol == 'vmess':
                    # （保持不变，已极稳）
                    body = node_link[8:].split('#')[0]
                    body += '=' * ((4 - len(body) % 4) % 4)
                    vmess_json = json.loads(base64.b64decode(body).decode('utf-8'))
                    server = vmess_json['add']
                    port = int(vmess_json['port'])
                    uuid = vmess_json['id']
                    aid = int(vmess_json.get('aid', 0))
                    scy = vmess_json.get('scy', 'auto')
                    net = vmess_json.get('net', 'tcp')
                    tls = vmess_json.get('tls', '')
                    sni = vmess_json.get('sni', vmess_json.get('host', server))
                    path = vmess_json.get('path', '')
                    host = vmess_json.get('host', '')
                    ps = vmess_json.get('ps', '')
                    if ps and proxy_name_final == "UNKNOWN_NODE":
                        proxy_name_final = re.sub(r'[\'\":\[\]]', '', unquote(ps)[:60])

                    tls_config = ""
                    if tls == 'tls':
                        tls_config = f"""
    tls: true
    skip-cert-verify: false
    servername: {sni}
"""

                    network_config = ""
                    if net == 'ws':
                        headers = f"\n        Host: {host or sni}" if host or sni else ""
                        network_config = f"""
    network: ws
    ws-opts:
      path: {path or '/'}{headers}
"""
                    elif net == 'grpc':
                        network_config = f"""
    network: grpc
    grpc-opts:
      grpc-service-name: {path or 'GunService'}
"""

                    proxy_config_yaml = f"""
  - name: {proxy_name_final}
    type: vmess
    server: {server}
    port: {port}
    uuid: {uuid}
    alterId: {aid}
    cipher: {scy}
    udp: true
{tls_config}{network_config}
"""

                # ==================== Hysteria2（新增完整支持）===================
                elif protocol == 'hysteria2':
                    password = url_parts.username or ""
                    server = url_parts.hostname
                    port = url_parts.port or 443
                    if not (server and port):
                        raise ValueError("Hysteria2 必要字段缺失")
                    params = parse_qs(url_parts.query)

                    # 密码可能在 query 的 auth 参数里（部分客户端这样写）
                    if not password:
                        password = params.get('auth', [''])[0] or params.get('password', [''])[0]

                    sni = params.get('sni', params.get('peer', ['']))[0] or server
                    insecure = params.get('insecure', params.get('allowInsecure', ['0']))[0] in ['1', 'true']
                    
                    up_mbps = params.get('up', params.get('upmbps', ['100']))[0]
                    down_mbps = params.get('down', params.get('downmbps', ['100']))[0]

                    obfs_type = params.get('obfs', [''])[0]
                    obfs_password = params.get('obfs-password', params.get('obfsPassword', ['']))[0]

                    tls_config = f"""
    tls: true
    servername: {sni}
    skip-cert-verify: {str(insecure).lower()}
    alpn:
      - h3
"""

                    obfs_config = ""
                    if obfs_type and obfs_type == 'salamander':
                        obfs_config = f"""
    obfs:
      type: salamander
      salamander-password: {obfs_password or 'crybaby'}
"""

                    proxy_config_yaml = f"""
  - name: {proxy_name_final}
    type: hysteria2
    server: {server}
    port: {port}
    password: {password}
    up-mbps: {up_mbps}
    down-mbps: {down_mbps}
{tls_config}{obfs_config}
    fast-open: true
"""

                else:
                    if VERBOSE:
                        print(f"  ⚠️  跳过不支持的协议: {raw_protocol}")
                    return False, node_link

            except Exception as e:
                if VERBOSE:
                    print(f"  ❌ 解析失败 [{protocol.upper()}]: {e}")
                return False, node_link

            # === 写入配置文件 ===
            yaml_content = f"""log-level: info
allow-lan: false
mode: rule
mixed-port: {proxy_port}
external-controller: 127.0.0.1:{api_port}
secret: githubactions

proxies:
{proxy_config_yaml}

proxy-groups:
  - name: NODE_TEST_GROUP
    type: select
    proxies:
      - {proxy_name_final}
"""
            with open(config_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)

            # === 启动 mihomo ===
            clash_process = subprocess.Popen(
                ["./mihomo-linux-amd64", "-f", config_path, "-d", temp_dir],
                stdout=open(log_path, 'w'),
                stderr=subprocess.STDOUT
            )

            # === 等待 API ===
            api_url = f"http://127.0.0.1:{api_port}/version"
            headers = {'Authorization': 'Bearer githubactions'}
            api_started = False
            for _ in range(20):
                try:
                    r = requests.get(api_url, headers=headers, timeout=1)
                    if r.status_code == 200:
                        api_started = True
                        break
                except:
                    time.sleep(0.5)
            if not api_started:
                if VERBOSE:
                    print(f"  ❌ API 启动超时（尝试 {attempt+1}）")
                continue

            time.sleep(1.8)

            # === 延迟测试 ===
            encoded_name = quote(proxy_name_final)
            success = False
            for test_url in TEST_URLS:
                delay_url = f"http://127.0.0.1:{api_port}/proxies/{encoded_name}/delay?url={quote(test_url)}&timeout={NODE_TIMEOUT * 1000}"
                try:
                    r = requests.get(delay_url, headers=headers, timeout=NODE_TIMEOUT + 2)
                    delay = r.json().get('delay', 0)
                    if delay > 0:
                        if VERBOSE:
                            print(f"  ✅ 成功！延迟 {delay}ms → {test_url.split('/')[2]}")
                        success = True
                        break
                except Exception as e:
                    pass

            if success:
                return True, node_link

            # 失败时打印完整 mihomo 日志（更详细）
            if os.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                if log_content.strip():
                    print(f"\n--- ❌ {proxy_name_final} 第 {attempt+1} 次失败日志 ---", file=sys.stderr)
                    print(log_content[:3000], file=sys.stderr)
                    if len(log_content) > 3000:
                        print("...（日志已截断）", file=sys.stderr)
                    print("-" * 60, file=sys.stderr)

    except Exception as e:
        print(f"💥 未知异常: {e}", file=sys.stderr)
    finally:
        if clash_process:
            clash_process.kill()
            clash_process.wait(timeout=3)
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    return False, node_link

def run_parallel_tests(all_nodes):
    print("--- 2. 正在并行连通性测试（详细日志模式）---")
    valid_nodes = [n for n in all_nodes if n.strip()]
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_single_node, node): node for node in valid_nodes}
        for i, future in enumerate(futures, 1):
            status, link = future.result()
            results.append((status, link))
            # 实时进度美化
            success_mark = "✅" if status else "❌"
            print(f"[{i:>{len(str(len(valid_nodes)))}}/{len(valid_nodes)}] {success_mark} ", end="")
            if status:
                print(f"成功 → {link.split('#')[-1][:40] if '#' in link else '无备注'}")
            else:
                print(f"失败 → {link.split('#')[-1][:40] if '#' in link else '无备注'}")
    return results

def save_results(results):
    shanghai_tz = pytz.timezone('Asia/Shanghai')
    now_shanghai = datetime.datetime.now(shanghai_tz)
    output_dir = now_shanghai.strftime('%Y/%m')
    output_filename = 'success-nodes-parallel.txt'
    output_path = os.path.join(output_dir, output_filename)
    successful_nodes = [link for status, link in results if status]
    
    print("\n--- 3. 测试完成，生成报告 ---")
    print(f"总计测试节点: {len(results)}")
    print(f"成功节点数  : {len(successful_nodes)}  ({len(successful_nodes)/len(results)*100:.1f}%)" if results else "0%")
    
    if not successful_nodes:
        print("⚠️ 没有节点测试成功，不生成文件。")
        return None
        
    os.makedirs(output_dir, exist_ok=True)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# 节点连通性测试成功结果（支持 Trojan/VLess/VMess/Hysteria2 并行测试）\n")
        f.write(f"# 测试时间 (上海): {now_shanghai.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"# 成功率: {len(successful_nodes)}/{len(results)} ({len(successful_nodes)/len(results*100):.1f}%)\n")
        f.write("---\n")
        for link in successful_nodes:
            f.write(f"{link}\n")
    print(f"✅ 成功节点已保存至: {output_path}")
    return output_path

if __name__ == "__main__":
    if not os.path.exists("./mihomo-linux-amd64"):
        print("❌ 未找到 mihomo-linux-amd64 可执行文件", file=sys.stderr)
        sys.exit(1)
    
    os.system("chmod +x ./mihomo-linux-amd64")
    
    all_nodes = fetch_and_parse_nodes()
    if not all_nodes:
        print("没有发现节点，退出。")
        sys.exit(0)
    
    results = run_parallel_tests(all_nodes)
    final_path = save_results(results)
    if final_path:
        print(f"\nREPORT_PATH={final_path}")
