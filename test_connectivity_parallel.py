# test_connectivity_parallel.py (最终稳定运行版：修复 Trojan-WS 解析和线程端口溢出)
import os
import sys
import datetime
import pytz
import re
import base64
from concurrent.futures import ThreadPoolExecutor
import subprocess
import requests
import time
import threading 
from urllib.parse import quote, unquote, urlparse, parse_qs 

# --- 配置 ---
REMOTE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/pin/refs/heads/main/trojan_links.txt",
]

# 增加测试目标列表，提高可用性判断
TEST_URLS = [
    "http://www.google.com/generate_204",  
    "http://www.youtube.com",             
    "http://www.microsoft.com",           
]

# 核心调试设置：降低并发，解决资源耗尽问题
MAX_WORKERS = 4 
# 核心调试设置：增加超时时间
NODE_TIMEOUT = 10 
# 最大重试次数
MAX_RETRIES = 2 

# --- 核心功能 ---

def fetch_and_parse_nodes():
    """
    下载远程文件，解析出潜在的节点链接。
    """
    print("--- 1. 正在获取和解析所有节点 ---")
    
    all_content = []
    
    for url in REMOTE_CONFIG_URLS:
        try:
            print(f"下载: {url}")
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            all_content.append(response.text)
        except requests.exceptions.RequestException as e:
            print(f"⚠️ 警告: 下载 {url} 失败: {e}", file=sys.stderr)

    all_lines = "\n".join(all_content).split('\n')
    unique_nodes = set()
    
    # 协议过滤已更新：加入 hysteria 和 hy2
    protocol_regex = r'(://|@|\b(vmess|ss|trojan|vless|hysteria|hy2|tuic)\b|server\s*:\s*.)'
    
    for line in all_lines:
        stripped_line = line.strip()
        if stripped_line and not stripped_line.startswith('#'):
            if re.search(protocol_regex, stripped_line, re.IGNORECASE):
                cleaned_line = stripped_line.replace("ss://ss://", "ss://").replace("vmess://vmess://", "vmess://")
                unique_nodes.add(cleaned_line)

    all_nodes = list(unique_nodes)
    print(f"修复并过滤后，发现 {len(all_nodes)} 个潜在节点链接。")
    return all_nodes

def test_single_node(node_link):
    """
    使用 Mihomo 核心作为子进程，进行多目标、多重试的连通性测试。
    """
    
    for attempt in range(MAX_RETRIES):
        clash_process = None
        
        try:
            # === 核心修复：使用线程ID和链接哈希结合，并约束端口范围 (< 65535) ===
            thread_id = threading.get_ident()
            link_hash = hash(node_link)
            
            # 使用异或(^)结合 thread_id 和 link_hash，并对结果取绝对值
            combined_hash = abs(thread_id ^ link_hash)
            
            # 约束端口种子范围 (例如 0 到 39999)，确保最终端口号不超过 65535
            # MAX_PORT_SEED = 40000
            constrained_seed = combined_hash % 40000 
            
            # 加上尝试次数以确保重试时端口不同
            port_seed = constrained_seed + attempt 
            
            # 使用高位端口范围，确保唯一性: 25000 + 40000 = 65000 (安全范围)
            api_port = 25000 + port_seed 
            PROXY_PORT = 15000 + port_seed # 15000 + 40000 = 55000 
            
            unique_id = f"{thread_id}_{attempt}" 
            # ===============================================
        except Exception:
            # 回退逻辑
            unique_id = f"fallback_{attempt}_{int(time.time()*1000)}"
            api_port = 19190 + attempt
            PROXY_PORT = 7890 + attempt
        
        CLASH_EXEC = "mihomo-linux-amd64"
        CONFIG_PATH = f"config_{unique_id}.yaml"
        LOG_PATH = f"mihomo_{unique_id}.log"
        API_HOST = "127.0.0.1"
        proxy_name_final = node_link.split('://')[0].upper() # 默认名称
        
        # 1. 构造配置 - 确保代理名称安全
        proxy_label_match = re.search(r'#(.+)', node_link)
        if proxy_label_match:
            try:
                raw_name = unquote(proxy_label_match.group(1).strip())
                proxy_name_final = raw_name.replace("'", "").replace("\"", "").replace(":", "").replace("[", "(").replace("]", ")")
            except Exception:
                pass
        
        GROUP_NAME = "NODE_TEST_GROUP" 

        # --- 核心：手动解析链接并构造 Mihomo YAML 格式 (支持 Trojan-WS) ---
        proxy_config_yaml = ""

        try:
            url_parts = urlparse(node_link)
            protocol = url_parts.scheme.lower()
            
            if protocol == 'trojan':
                # 提取基础组件
                password = url_parts.username
                server = url_parts.hostname
                port = url_parts.port
                
                if not (password and server and port):
                    return False, node_link 

                # 解析查询参数
                params = parse_qs(url_parts.query)
                
                # --- TLS 配置 ---
                tls_config = ""
                tls_setting = "true" 
                
                # SNI
                sni = params.get('sni', [''])[0].strip()
                if sni:
                    tls_config += f"    sni: {sni}\n"
                
                tls_config += f"    tls: {tls_setting}\n    skip-cert-verify: false\n"
                
                allow_insecure_param = params.get('allowinsecure', params.get('allowlnsecure', [''])[0])
                if allow_insecure_param.lower() in ['1', 'true']:
                     tls_config = tls_config.replace("skip-cert-verify: false", "skip-cert-verify: true")
                
                # --- WebSocket 配置 ---
                ws_config = ""
                if params.get('type', [''])[0].lower() == 'ws':
                    path = unquote(params.get('path', ['/'])[0])
                    host_header = params.get('host', [server])[0] 
                    
                    ws_config = f"""
    network: ws
    ws-opts:
      path: {path}
      headers:
        Host: {host_header}
"""
                
                # --- 最终 YAML 组合 ---
                proxy_config_yaml = f"""
  - name: {proxy_name_final}
    type: trojan
    server: {server}
    port: {port}
    password: {password}
{tls_config}
{ws_config}
"""
            if not proxy_config_yaml:
                return False, node_link 

        except Exception as e:
            print(f"\n❌ FATAL PARSE ERROR (Trojan): 处理 {node_link[:50]}... 失败: {e}", file=sys.stderr)
            return False, node_link 


        # 2. 保存配置
        yaml_content = f"""
mixed-port: {PROXY_PORT} 
external-controller: {API_HOST}:{api_port}
secret: githubactions
proxies:
{proxy_config_yaml}
proxy-groups:
  - name: {GROUP_NAME}
    type: select
    proxies:
      - {proxy_name_final}
"""
        try:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                f.write(yaml_content)
        except Exception:
            continue 
            
        is_successful = False
        api_started = False
        mihomo_log_content = "" 

        try:
            # 3. 启动 Mihomo 核心
            clash_process = subprocess.Popen(
                [f"./{CLASH_EXEC}", '-f', CONFIG_PATH, '-d', '.'],
                stdout=open(LOG_PATH, 'w'), 
                stderr=subprocess.STDOUT
            )
            
            # 4. 等待 API 启动
            api_url = f"http://{API_HOST}:{api_port}/version"
            headers = {'Authorization': 'Bearer githubactions'}
            
            for _ in range(10): 
                try:
                    response = requests.get(api_url, headers=headers, timeout=0.5)
                    if response.status_code == 200:
                        api_started = True
                        break
                except requests.exceptions.RequestException:
                    pass
                time.sleep(0.5)
            
            if not api_started:
                continue 
            
            time.sleep(1) 
            
            # 5. --- 多目标 URL 连通性测试 ---
            encoded_proxy_name_for_delay = quote(proxy_name_final)
            
            for test_url in TEST_URLS:
                api_delay_url = f"http://{API_HOST}:{api_port}/proxies/{encoded_proxy_name_for_delay}/delay?url={quote(test_url)}&timeout={NODE_TIMEOUT}000"
                
                try:
                    response = requests.get(api_delay_url, headers=headers, timeout=NODE_TIMEOUT + 2) 
                    response.raise_for_status()
                    delay_data = response.json()
                    
                    if delay_data.get('delay', -1) > 0:
                        is_successful = True
                        break 
                except Exception:
                    pass

            if is_successful:
                return True, node_link 
                
        except Exception:
            pass
            
        finally:
            # 失败时打印 Mihomo 日志
            if not is_successful:
                if os.path.exists(LOG_PATH):
                    try:
                        with open(LOG_PATH, 'r', encoding='utf-8') as f:
                            mihomo_log_content = f.read()
                        
                        if mihomo_log_content.strip():
                            print(f"\n--- ❌ 节点 {proxy_name_final} 调试日志 (尝试 {attempt+1}/{MAX_RETRIES}) ---", file=sys.stderr)
                            print(mihomo_log_content[:2000], file=sys.stderr)
                            print("..." if len(mihomo_log_content) > 2000 else "", file=sys.stderr)
                            print("-" * 50, file=sys.stderr)
                            
                    except Exception:
                        pass 

            # 7. 清理
            if clash_process:
                clash_process.terminate()
                
            for path in [CONFIG_PATH, LOG_PATH]:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
        
        if attempt < MAX_RETRIES - 1:
            time.sleep(1) 

    return False, node_link 


def run_parallel_tests(all_nodes):
    """
    使用线程池并行测试所有节点。
    """
    print("--- 2. 正在并行连通性测试 ---")
    results = []
    valid_nodes = [n for n in all_nodes if n.strip()]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(test_single_node, node_link): node_link for node_link in valid_nodes}
        
        for i, future in enumerate(futures):
            sys.stdout.write(f"[{i+1}/{len(valid_nodes)}] Testing... \r")
            sys.stdout.flush()
            
            try:
                status, link = future.result()
                results.append((status, link))
            except Exception as exc:
                print(f"\n❌ ERROR: 并行执行出错: {exc}", file=sys.stderr)
                
    sys.stdout.write(" " * 50 + "\r")
    sys.stdout.flush()
    
    return results


def save_results(results):
    """
    生成并保存成功的节点链接到固定的文件。
    """
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
        f.write("# 节点连通性测试成功结果 (并行测试)\n")
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
        print("❌ 错误：Mihomo 核心文件 ./mihomo-linux-amd64 未找到。", file=sys.stderr)
        sys.exit(1)
    
    try:
        subprocess.run(['chmod', '+x', './mihomo-linux-amd64'], check=True)
    except:
        pass 
        
    all_nodes = fetch_and_parse_nodes()
    
    if not all_nodes:
        print("没有找到任何节点，退出。")
        sys.exit(0)
    
    results = run_parallel_tests(all_nodes)
    
    final_path = save_results(results)
    
    if final_path:
        print(f"REPORT_PATH={final_path}")
