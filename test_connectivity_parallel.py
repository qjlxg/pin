# test_connectivity_parallel.py（终极完整版 - 支持 Trojan / VLess / VMess - 2025-12-06）
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
    # 可继续添加其他订阅源
]

TEST_URLS = [
    "http://www.google.com/generate_204",
    "http://www.youtube.com",
    "http://www.microsoft.com",
]

MAX_WORKERS = 25        # 彻底稳定后建议 20-30，速度极快
NODE_TIMEOUT = 12
MAX_RETRIES = 2

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
    protocol_regex = r'(://|@|\b(vmess|ss|trojan|vless|hysteria|hy2|tuic)\b|server\s*:\s*.)'
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
        
        for attempt in range(MAX_RETRIES):
            seed_str = f"{node_link}_{attempt}_{threading.get_ident()}_{int(time.time()*100000)}"
            seed = abs(hash(seed_str)) % 25000
            api_port = 30000 + seed
            proxy_port = 40000 + seed
            unique_id = f"t{threading.get_ident()}_a{attempt}_{seed}"
            config_path = os.path.join(temp_dir, f"config_{unique_id}.yaml")
            log_path = os.path.join(temp_dir, f"mihomo_{unique_id}.log")

            # === 统一提取节点名称 ===
            proxy_name_final = "TEST_NODE"
            remark_match = re.search(r'#(.+)', node_link)
            if remark_match:
                try:
                    proxy_name_final = re.sub(r'[\'\":\[\]]', '', unquote(remark_match.group(1)).strip())[:60]
                except:
                    pass

            proxy_config_yaml = ""
            try:
                url_parts = urlparse(node_link)
                protocol = url_parts.scheme.lower()

                if protocol not in ['trojan', 'vless', 'vmess']:
                    return False, node_link

                # ==================== Trojan ====================
                if protocol == 'trojan':
                    password = url_parts.username
                    server = url_parts.hostname
                    port = url_parts.port or 443
                    if not (password and server and port):
                        raise ValueError("Trojan 链接缺失必要字段")
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
                    uuid = url_parts.username
                    server = url_parts.hostname
                    port = url_parts.port or 443
                    if not (uuid and server and port):
                        raise ValueError("VLess 链接缺失必要字段")
                    params = parse_qs(url_parts.query)

                    security = params.get('security', ['none'])[0].lower()
                    flow = params.get('flow', [''])[0]
                    network = params.get('type', ['tcp'])[0].lower()
                    sni = params.get('sni', params.get('peer', ['']))[0] or server
                    allow_insecure = params.get('allowInsecure', params.get('allowinsecure', ['0']))[0] in ['1', 'true']

                    tls_config = ""
                    if security == 'tls':
                        tls_config = f"""
    tls: true
    skip-cert-verify: {str(allow_insecure).lower()}
    servername: {sni}
"""
                    elif security == 'reality':
                        # 基础 Reality 支持
                        pbk = params.get('pbk', [''])[0]
                        short_id = params.get('sid', [''])[0]
                        if not pbk:
                            raise ValueError("Reality 需要 pbk")
                        tls_config = f"""
    tls: true
    skip-cert-verify: true
    reality-opts:
      public-key: {pbk}
      short-id: {short_id or '0'}
"""

                    flow_config = f"    flow: {flow}\n" if flow else ""

                    ws_grpc_config = ""
                    if network == 'ws':
                        path = unquote(params.get('path', ['/'])[0])
                        host = params.get('host', [sni])[0]
                        ws_grpc_config = f"""
    network: ws
    ws-opts:
      path: {path}
      headers:
        Host: {host}
"""
                    elif network == 'grpc':
                        service_name = params.get('serviceName', ['GunService'])[0]
                        ws_grpc_config = f"""
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
{flow_config}{tls_config}{ws_grpc_config}
"""

                # ==================== VMess ====================
                elif protocol == 'vmess':
                    body = node_link[8:]
                    if '#' in body:
                        body, extra_remark = body.split('#', 1)
                        if not proxy_name_final:
                            proxy_name_final = re.sub(r'[\'\":\[\]]', '', unquote(extra_remark).strip())[:60]

                    # 补 padding
                    body += '=' * ((4 - len(body) % 4) % 4)
                    try:
                        vmess_json = json.loads(base64.b64decode(body).decode('utf-8'))
                    except Exception as e:
                        raise ValueError(f"VMess base64 解码失败: {e}")

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
                    if not proxy_name_final:
                        proxy_name_final = re.sub(r'[\'\":\[\]]', '', unquote(ps).strip())[:60]

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
                    elif net == 'http':
                        network_config = f"""
    network: http
    http-opts:
      path: [{path or '/'}]
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

            except Exception as e:
                print(f"\n❌ 解析失败 {protocol.upper()} {node_link[:60]}: {e}", file=sys.stderr)
                return False, node_link

            if not proxy_config_yaml.strip():
                return False, node_link

            # === 写入完整配置文件 ===
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

            # === 等待 API 就绪 ===
            api_url = f"http://127.0.0.1:{api_port}/version"
            headers = {'Authorization': 'Bearer githubactions'}
            api_started = False
            for _ in range(16):
                try:
                    r = requests.get(api_url, headers=headers, timeout=1)
                    if r.status_code == 200:
                        api_started = True
                        break
                except:
                    time.sleep(0.5)
            if not api_started:
                continue

            time.sleep(1.5)

            # === 延迟测试 ===
            encoded_name = quote(proxy_name_final)
            for test_url in TEST_URLS:
                delay_url = f"http://127.0.0.1:{api_port}/proxies/{encoded_name}/delay?url={quote(test_url)}&timeout={NODE_TIMEOUT * 1000}"
                try:
                    r = requests.get(delay_url, headers=headers, timeout=NODE_TIMEOUT + 2)
                    if r.json().get('delay', 0) > 0:
                        return True, node_link
                except:
                    pass

            # 失败打印日志
            if os.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8') as f:
                    log_content = f.read()
                if log_content.strip():
                    print(f"\n--- ❌ 节点 {proxy_name_final} 失败 (尝试 {attempt+1}/{MAX_RETRIES}) ---", file=sys.stderr)
                    print(log_content[:2500], file=sys.stderr)
                    print("-" * 50, file=sys.stderr)

    except Exception as e:
        print(f"未知异常: {e}", file=sys.stderr)
    finally:
        if clash_process:
            clash_process.kill()
            try:
                clash_process.wait(timeout=3)
            except:
                pass
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
    
    return False, node_link

def run_parallel_tests(all_nodes):
    print("--- 2. 正在并行连通性测试 ---")
    valid_nodes = [n for n in all_nodes if n.strip()]
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_single_node, node): node for node in valid_nodes}
        for i, future in enumerate(futures, 1):
            print(f"[{i}/{len(valid_nodes)}] Testing... \r", end="")
            sys.stdout.flush()
            status, link = future.result()
            results.append((status, link))
    print(" " * 80 + "\r", end="")
    return results

def save_results(results):
    shanghai_tz = pytz.timezone('Asia/Shanghai')
    now_shanghai = datetime.datetime.now(shanghai_tz)
    output_dir = now_shanghai.strftime('%Y/%m')
    output_filename = 'success-nodes-parallel.txt'
    output_path = os.path.join(output_dir, output_filename)
    successful_nodes = [link for status, link in results if status]
    
    print("--- 3. 正在生成报告 ---")
    if not successful_nodes:
        print("⚠️ 没有节点测试成功。不生成报告文件。")
        return None
    os.makedirs(output_dir, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# 节点连通性测试成功结果 (支持 Trojan/VLess/VMess 并行测试)\n")
        f.write(f"测试时间 (上海): {now_shanghai.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总节点数: {len(results)}\n")
        f.write(f"成功连接数: {len(successful_nodes)}\n")
        f.write(f"测试目标: {', '.join(TEST_URLS)} (任一成功即通过)\n")
        f.write(f"最大重试次数: {MAX_RETRIES}\n")
        f.write("---\n")
        for link in successful_nodes:
            f.write(f"{link}\n")
    print(f"✅ 测试完成。成功节点列表已保存到: {output_path}")
    return output_path

if __name__ == "__main__":
    if not os.path.exists("./mihomo-linux-amd64"):
        print("❌ 未找到 mihomo-linux-amd64", file=sys.stderr)
        sys.exit(1)
    
    os.system("chmod +x ./mihomo-linux-amd64")
    
    all_nodes = fetch_and_parse_nodes()
    if not all_nodes:
        print("没有节点，退出。")
        sys.exit(0)
    
    results = run_parallel_tests(all_nodes)
    
    final_path = save_results(results)
    if final_path:
        print(f"REPORT_PATH={final_path}")
