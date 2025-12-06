# test_connectivity_parallel.py（GitHub Actions 完美稳定版 V5 - 共享 GeoData/GeoLoader）

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
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import requests
from urllib.parse import quote, unquote, urlparse, parse_qs
from requests.exceptions import Timeout, ConnectionError

# 强制日志实时刷新
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)

# --- 配置 ---
REMOTE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/pin/refs/heads/main/trojan_links.txt",
]

TEST_URLS = [
    "http://www.google.com/generate_204",
    "http://www.youtube.com",
    "http://www.microsoft.com",
]

# 核心调整：根据您要求设置
MAX_WORKERS = 8       # 线程数
MAX_API_WAIT_TIME = 30 # 最大 API 等待时间 (秒)
NODE_TIMEOUT = 15
MAX_RETRIES = 2
VERBOSE = True
# 共享 GeoData 目录
SHARED_GEO_DIR = "./geodata_cache"

# 将 API 启动检测的循环次数调整到匹配 MAX_API_WAIT_TIME
API_WAIT_LOOPS = int(MAX_API_WAIT_TIME / 0.5) 

# --- GeoData 检查和下载（在主线程中运行） ---
def check_and_download_geodata():
    """检查并确保 GeoData 存在，如果不存在则启动 mihomo 下载。"""
    os.makedirs(SHARED_GEO_DIR, exist_ok=True)
    geoip_path = os.path.join(SHARED_GEO_DIR, "geoip.dat")
    geosite_path = os.path.join(SHARED_GEO_DIR, "geosite.dat")
    
    # 检查 GeoData 文件是否存在
    if os.path.exists(geoip_path) and os.path.exists(geosite_path):
        print(f"✅ GeoData 文件已存在于 {SHARED_GEO_DIR}，跳过下载。", flush=True)
        return True

    print(f"⚠️ GeoData 文件不存在，正在通过 mihomo 下载 GeoIP/GeoSite...", flush=True)
    temp_config_path = os.path.join(SHARED_GEO_DIR, "temp_config_download.yaml")
    
    # 创建一个极简配置，目的是触发 mihomo 下载 GeoData 到 SHARED_GEO_DIR
    temp_yaml = f"""
log-level: info
mixed-port: 50000
geodata-dir: {SHARED_GEO_DIR}
proxies:
  - name: dummy
    type: http
    server: 127.0.0.1
    port: 1
"""
    with open(temp_config_path, 'w', encoding='utf-8') as f:
        f.write(temp_yaml)
        
    # 启动 mihomo 进程，下载完成后会自动退出
    try:
        download_process = subprocess.Popen(
            ["./mihomo-linux-amd64", "-f", temp_config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        # 最多等待 60 秒下载 GeoData
        download_process.wait(timeout=60) 
    except Exception as e:
        print(f"❌ GeoData 下载失败: {e}", file=sys.stderr, flush=True)
        return False
    finally:
        if os.path.exists(temp_config_path):
            os.remove(temp_config_path)

    if os.path.exists(geoip_path) and os.path.exists(geosite_path):
        print(f"✅ GeoData 下载完成，文件保存在 {SHARED_GEO_DIR}。", flush=True)
        return True
    else:
        print("❌ GeoData 下载失败，请检查网络。", file=sys.stderr, flush=True)
        return False

# --- 节点获取函数（未变动） ---
def fetch_and_parse_nodes():
    """从远程 URL 获取并解析节点链接，强化网络超时处理。"""
    print("--- 1. 正在获取和解析所有节点 ---", flush=True)
    all_content = []
    
    NETWORK_TIMEOUT = (3, 12) 
    
    for url in REMOTE_CONFIG_URLS:
        try:
            print(f"DEBUG: 准备下载 {url}", flush=True)
            response = requests.get(url, timeout=NETWORK_TIMEOUT)
            print(f"DEBUG: 下载完成 {url}, 状态码: {response.status_code}", flush=True)
            response.raise_for_status()
            all_content.append(response.text)
        except (Timeout, ConnectionError) as e:
            print(f"⚠️ 下载失败 (网络错误): {url} | 错误: {e.__class__.__name__}", file=sys.stderr, flush=True)
        except Exception as e:
            print(f"⚠️ 下载失败 (HTTP/其他错误): {url} | 错误: {e}", file=sys.stderr, flush=True)
            
    all_lines = "\n".join(all_content).split('\n')
    unique_nodes = set()
    protocol_regex = r'(://|@|\b(vmess|ss|trojan|vless|hysteria2|hy2|tuic)\b|server\s*:\s*.)'
    
    for line in all_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith('#') and re.search(protocol_regex, stripped, re.IGNORECASE):
            cleaned = stripped.replace("ss://ss://", "ss://").replace("vmess://vmess://", "vmess://")
            unique_nodes.add(cleaned)
            
    all_nodes = list(unique_nodes)
    print(f"修复并过滤后，发现 {len(all_nodes)} 个潜在节点链接。", flush=True)
    return all_nodes


def test_single_node(node_link):
    # temp_dir 现在只用于存放 config 和 log 文件，GeoData 在共享目录
    temp_dir = None
    clash_process = None
    
    try:
        # 使用 tempfile.TemporaryDirectory 确保自动清理 config/log
        with tempfile.TemporaryDirectory(prefix="mihomo_test_") as temp_dir: 
            
            proxy_name_final = "NODE"
            remark_match = re.search(r'#(.+)', node_link)
            if remark_match:
                try:
                    proxy_name_final = re.sub(r'[\'\":\[\]]', '', unquote(remark_match.group(1)).strip())[:60]
                except:
                    pass

            if VERBOSE:
                print(f"\n开始测试 → {proxy_name_final}", flush=True)

            for attempt in range(MAX_RETRIES):
                if VERBOSE and MAX_RETRIES > 1:
                    print(f"  第 {attempt+1}/{MAX_RETRIES} 次尝试", flush=True)
                
                # --- 每次尝试前，确保上一个进程已清理 ---
                if clash_process:
                    clash_process.terminate() 
                    try:
                        clash_process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        clash_process.kill()
                        clash_process.wait()
                    clash_process = None

                seed_str = f"{node_link}_{attempt}_{threading.get_ident()}_{int(time.time()*100000)}"
                seed = abs(hash(seed_str)) % 25000
                api_port = 30000 + seed
                proxy_port = 40000 + seed
                unique_id = f"t{threading.get_ident()}_a{attempt}_{seed}"
                config_path = os.path.join(temp_dir, f"config_{unique_id}.yaml")
                log_path = os.path.join(temp_dir, f"mihomo_{unique_id}.log")

                proxy_config_yaml = ""
                protocol = ""

                # --- 协议解析与配置生成 (略，保持 V4 一致) ---
                try:
                    url_parts = urlparse(node_link)
                    raw_protocol = url_parts.scheme.lower()
                    protocol = raw_protocol
                    if raw_protocol in ['hy2', 'hysteria2']:
                        protocol = 'hysteria2'

                    if protocol == 'trojan':
                        password = url_parts.username or ""
                        server = url_parts.hostname
                        port = url_parts.port or 443
                        params = parse_qs(url_parts.query)
                        sni = params.get('sni', params.get('peer', ['']))[0] or server
                        allow_insecure = params.get('allowInsecure', params.get('allowinsecure', ['0']))[0] in ['1', 'true']
                        tls_config = f"  tls: true\n  servername: {sni}\n  skip-cert-verify: {str(allow_insecure).lower()}\n"
                        ws_config = ""
                        if params.get('type', [''])[0].lower() == 'ws':
                            path = unquote(params.get('path', ['/'])[0])
                            host_header = params.get('host', [sni])[0]
                            ws_config = f"  network: ws\n  ws-opts:\n    path: {path}\n    headers:\n      Host: {host_header}\n"
                        proxy_config_yaml = f"""  - name: {proxy_name_final}
    type: trojan
    server: {server}
    port: {port}
    password: {password}
{tls_config}{ws_config}"""

                    elif protocol == 'vless':
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
                                short_id = params.get('sid', [''])[0]
                                if not pbk: raise ValueError("Reality 需要 pbk")
                                tls_config = f"    tls: true\n    skip-cert-verify: true\n    servername: {sni}\n    reality-opts:\n      public-key: {pbk}\n      short-id: {short_id or '0'}\n"
                            else:
                                tls_config = f"    tls: true\n    skip-cert-verify: {skip_verify}\n    servername: {sni}\n"
                        transport_config = ""
                        if network == 'ws':
                            path = unquote(params.get('path', ['/'])[0])
                            host = params.get('host', [sni])[0]
                            transport_config = f"    network: ws\n    ws-opts:\n      path: {path}\n      headers:\n        Host: {host}\n"
                        elif network == 'grpc':
                            service_name = params.get('serviceName', ['GunService'])[0]
                            transport_config = f"    network: grpc\n    grpc-opts:\n      grpc-service-name: {service_name}\n"
                        flow_config = f"    flow: {flow}\n" if flow else ""
                        proxy_config_yaml = f"""  - name: {proxy_name_final}
    type: vless
    server: {server}
    port: {port}
    uuid: {uuid}
    udp: true
{flow_config}{tls_config}{transport_config}"""

                    elif protocol == 'vmess':
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
                        tls_config = f"    tls: true\n    servername: {sni}\n    skip-cert-verify: false\n" if tls == 'tls' else ""
                        network_config = ""
                        if net == 'ws':
                            headers = f"\n        Host: {host or sni}" if host or sni else ""
                            network_config = f"    network: ws\n    ws-opts:\n      path: {path or '/'}{headers}\n"
                        elif net == 'grpc':
                            network_config = f"    network: grpc\n    grpc-opts:\n      grpc-service-name: {path or 'GunService'}\n"
                        proxy_config_yaml = f"""  - name: {proxy_name_final}
    type: vmess
    server: {server}
    port: {port}
    uuid: {uuid}
    alterId: {aid}
    cipher: {scy}
    udp: true
{tls_config}{network_config}"""

                    elif protocol == 'hysteria2':
                        password = url_parts.username or ""
                        server = url_parts.hostname
                        port = url_parts.port or 443
                        params = parse_qs(url_parts.query)
                        if not password: password = params.get('auth', [''])[0] or params.get('password', [''])[0]
                        sni = params.get('sni', params.get('peer', ['']))[0] or server
                        insecure = params.get('insecure', params.get('allowInsecure', ['0']))[0] in ['1', 'true']
                        up_mbps = params.get('up', ['100'])[0]
                        down_mbps = params.get('down', ['100'])[0]
                        obfs_type = params.get('obfs', [''])[0]
                        obfs_password = params.get('obfs-password', [''])[0]
                        obfs_config = ""
                        if obfs_type == 'salamander':
                            obfs_config = f"    obfs:\n      type: salamander\n      salamander-password: {obfs_password or 'crybaby'}\n"
                        proxy_config_yaml = f"""  - name: {proxy_name_final}
    type: hysteria2
    server: {server}
    port: {port}
    password: {password}
    up-mbps: {up_mbps}
    down-mbps: {down_mbps}
    tls: true
    servername: {sni}
    skip-cert-verify: {str(insecure).lower()}
    alpn:
      - h3
{obfs_config}    fast-open: true
"""
                    else:
                        return False, node_link, 99999

                except Exception as e:
                    if VERBOSE:
                        print(f"  ❌ 解析失败: {e}", flush=True)
                    return False, node_link, 99999

                # --- 写入配置并启动 mihomo (新增 GeoData 配置) ---
                yaml_content = f"""log-level: info
allow-lan: false
mode: rule
mixed-port: {proxy_port}
external-controller: 127.0.0.1:{api_port}
secret: githubactions
geodata-dir: {SHARED_GEO_DIR}
geodata-loader: memconservative

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

                clash_process = subprocess.Popen(
                    ["./mihomo-linux-amd64", "-f", config_path, "-d", temp_dir],
                    stdout=open(log_path, 'w'),
                    stderr=subprocess.STDOUT
                )

                # --- API 启动检测 (使用更长的等待时间) ---
                api_url = f"http://127.0.0.1:{api_port}/version"
                headers = {'Authorization': 'Bearer githubactions'}
                api_started = False
                
                # 等待 MAX_API_WAIT_TIME
                for _ in range(API_WAIT_LOOPS): 
                    try:
                        r = requests.get(api_url, headers=headers, timeout=1)
                        if r.status_code == 200:
                            api_started = True
                            break
                    except:
                        time.sleep(0.5)

                if not api_started:
                    if VERBOSE:
                        # 使用 API_WAIT_LOOPS * 0.5 来显示实际等待时间
                        print(f"  ❌ API 启动失败 (超时 {MAX_API_WAIT_TIME}秒)（第 {attempt+1} 次）", flush=True) 
                    
                    if clash_process:
                        clash_process.terminate()
                        try:
                            clash_process.wait(timeout=1)
                        except subprocess.TimeoutExpired:
                            clash_process.kill()
                            clash_process.wait()
                    continue

                time.sleep(1.8) # 启动后稳定延迟

                # --- 连通性测试 ---
                encoded_name = quote(proxy_name_final)
                success = False
                delay_ms = 99999

                for test_url in TEST_URLS:
                    delay_url = f"http://127.0.0.1:{api_port}/proxies/{encoded_name}/delay?url={quote(test_url)}&timeout={NODE_TIMEOUT * 1000}"
                    try:
                        r = requests.get(delay_url, headers=headers, timeout=NODE_TIMEOUT + 2)
                        delay_ms = r.json().get('delay', 0)
                        if delay_ms > 0:
                            if VERBOSE:
                                print(f"  ✅ 成功！延迟 {delay_ms}ms", flush=True)
                            success = True
                            break
                    except:
                        pass

                if success:
                    return True, node_link, delay_ms

                # 节点测试失败，打印核心日志并清理
                if os.path.exists(log_path):
                    with open(log_path, 'r', encoding='utf-8') as f:
                        log_content = f.read()[:3000]
                    if log_content.strip():
                        print(f"\n--- ❌ {proxy_name_final} 第 {attempt+1} 次失败日志 ---", file=sys.stderr, flush=True)
                        print(log_content, file=sys.stderr, flush=True)
                        print("-" * 60, file=sys.stderr, flush=True)

                if clash_process:
                    clash_process.terminate()
                    try:
                        clash_process.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        clash_process.kill()
                        clash_process.wait()

    except Exception as e:
        print(f"未知异常: {e}", file=sys.stderr, flush=True)
    finally:
        # 最终清理确保没有残留
        if clash_process:
            clash_process.terminate()
            try:
                clash_process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                clash_process.kill()
                clash_process.wait()
        # 注意：这里不再需要手动清理 temp_dir，因为使用了 TemporaryDirectory

    return False, node_link, 99999

# --- run_parallel_tests 和 save_results 函数（保持 V4 一致） ---
def run_parallel_tests(all_nodes):
    print(f"\n=== 开始并行测试 Workers={MAX_WORKERS} ===", flush=True)
    valid_nodes = [n for n in all_nodes if n.strip()]
    results = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_single_node, node): node for node in valid_nodes}
        
        for completed, future in enumerate(as_completed(futures), 1):
            try:
                status, link, delay_ms = future.result()
                results.append((status, link))
                
                remark = link.split('#')[-1][:40] if '#' in link else '无备注'
                mark = "✅" if status else "❌"
                delay_str = f"{delay_ms}ms" if status else "失败"
                print(f"[{completed:>{len(str(len(valid_nodes)))}}/{len(valid_nodes)}] {mark} {delay_str} → {remark}", flush=True)

            except Exception as e:
                print(f"💥 线程执行失败 (未知错误): {e}", file=sys.stderr, flush=True)
                continue

    print("=== 并行测试结束 ===", flush=True)
    return results

def save_results(results):
    shanghai_tz = pytz.timezone('Asia/Shanghai')
    now_shanghai = datetime.datetime.now(shanghai_tz)
    output_dir = now_shanghai.strftime('%Y/%m')
    output_filename = 'success-nodes-parallel.txt'
    output_path = os.path.join(output_dir, output_filename)
    
    successful_nodes = [link for status, link in results if status]
    total = len(results)
    rate = len(successful_nodes) / total * 100 if total else 0

    print(f"\n--- 测试完成 ---")
    print(f"总节点: {total}  成功: {len(successful_nodes)}  成功率: {rate:.1f}%", flush=True)

    if successful_nodes:
        os.makedirs(output_dir, exist_ok=True)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(f"# 测试时间: {now_shanghai.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"# 成功率: {len(successful_nodes)}/{total} ({rate:.1f}%)\n---\n")
            for link in successful_nodes:
                f.write(f"{link}\n")
        print(f"✅ 成功节点已保存: {output_path}", flush=True)
        return output_path
    else:
        print("⚠️ 无成功节点")
        return None

if __name__ == "__main__":
    if not os.path.exists("./mihomo-linux-amd64"):
        print("❌ 未找到 mihomo-linux-amd64", file=sys.stderr)
        sys.exit(1)

    os.system("chmod +x ./mihomo-linux-amd64")
    
    # 步骤 1：检查并下载 GeoData
    if not check_and_download_geodata():
        print("❌ 无法获取 GeoData 文件，测试无法继续。", file=sys.stderr)
        sys.exit(1)

    # 步骤 2：获取节点
    all_nodes = fetch_and_parse_nodes()
    if not all_nodes:
        print("无节点，退出")
        sys.exit(0)

    # 步骤 3：并行测试
    results = run_parallel_tests(all_nodes)
    
    # 步骤 4：保存结果
    final_path = save_results(results)
    if final_path:
        print(f"\nREPORT_PATH={final_path}")
