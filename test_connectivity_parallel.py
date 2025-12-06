# test_connectivity_parallel.py (最终稳定版：修复 API 稳定性问题)
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
from urllib.parse import quote, unquote

# --- 配置 ---
REMOTE_CONFIG_URLS = [
    # 请确保此处的 URL 列表与您实际运行的节点源列表一致
    "https://raw.githubusercontent.com/qjlxg/pin/refs/heads/main/trojan_links.txt",

]

# 增加测试目标列表，提高可用性判断
TEST_URLS = [
    "http://www.google.com/generate_204",  # 基础连通性
    "http://www.youtube.com",              # 媒体/GFW 穿透性
    "http://www.microsoft.com",            # 微软服务连通性
]

# 最大并行工作线程数 
MAX_WORKERS = 32
# 每个节点的连接超时时间 (秒)
NODE_TIMEOUT = 3 
# 最大重试次数 - 解决瞬时网络波动导致的假失败
MAX_RETRIES = 2 

# --- 核心功能 ---

def fetch_and_parse_nodes():
    """
    下载远程文件，解析出潜在的节点链接。
    """
    print("--- 1. 正在获取和解析所有节点 ---")
    
    all_content = []
    
    # 下载远程文件
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
    
    for line in all_lines:
        stripped_line = line.strip()
        if stripped_line and not stripped_line.startswith('#'):
            # 过滤主流协议链接
            if re.search(r'(://|@|\b(vmess|ss|trojan|vless)\b|server\s*:\s*.)', stripped_line, re.IGNORECASE):
                cleaned_line = stripped_line.replace("ss://ss://", "ss://").replace("vmess://vmess://", "vmess://")
                unique_nodes.add(cleaned_line)

    all_nodes = list(unique_nodes)
    print(f"修复并过滤后，发现 {len(all_nodes)} 个潜在节点链接。")
    return all_nodes

def test_single_node(node_link):
    """
    使用 Mihomo 核心作为子进程，进行多目标、多重试的连通性测试。
    """
    
    # 尝试所有重试次数
    for attempt in range(MAX_RETRIES):
        clash_process = None
        
        # 确保每个线程/尝试都有独特的端口和文件，解决高并发冲突
        try:
            # 使用进程 ID 和尝试次数来创建唯一的 ID
            unique_id = f"{os.getpid()}_{attempt}_{int(time.time()*1000)}" 
            # 确保尝试之间使用不同端口
            api_port = 19190 + os.getpid() % 100 + hash(node_link) % 1000 + attempt 
        except:
            unique_id = f"fallback_{attempt}_{int(time.time()*1000)}"
            api_port = 19190 + attempt
        
        CLASH_EXEC = "mihomo-linux-amd64"
        CONFIG_PATH = f"config_{unique_id}.yaml"
        LOG_PATH = f"mihomo_{unique_id}.log"
        API_HOST = "127.0.0.1"

        # 1. 构造配置
        # 尝试解析节点名称，如果失败，则使用安全的默认名称
        proxy_name_final = node_link.split('://')[0].upper() # 默认名称 (e.g., TROJAN)
        proxy_name_match = re.search(r'name=([^&]+)', node_link)
        if proxy_name_match:
            try:
                # 提取并解码名称。使用 quote() 来编码空格等特殊字符
                raw_name = unquote(proxy_name_match.group(1).split('#')[-1])
                # 替换掉 Mihomo 不支持的 YAML 敏感字符，避免 YAML 解析错误
                proxy_name_final = raw_name.replace("'", "").replace("\"", "").replace(":", "").replace("[", "(").replace("]", ")")
            except Exception:
                # 编码失败，使用默认名称
                pass
        
        yaml_content = f"""
mixed-port: 7890
external-controller: {API_HOST}:{api_port}
secret: githubactions
proxies:
  - {node_link}
proxy-groups:
  - name: {quote(proxy_name_final)} # 使用 URL 编码后的名称作为组名
    type: select
    proxies:
      - {proxy_name_final}
"""
        
        # 2. 保存配置
        try:
            with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
                f.write(yaml_content)
        except Exception:
            continue 
            
        is_successful = False
        api_started = False

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
            
            for _ in range(5): 
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
            
            # === 核心修复：API 稳定延迟 ===
            time.sleep(1) # 强制等待 1 秒，确保 Mihomo 核心完全稳定
            
            # 5. --- 多目标 URL 连通性测试 ---
            
            # Mihomo API 需要对代理名称进行 URL 编码
            encoded_proxy_name = quote(proxy_name_final)
            
            for test_url in TEST_URLS:
                # 触发延迟测试
                api_delay_url = f"http://{API_HOST}:{api_port}/proxies/{encoded_proxy_name}/delay?url={quote(test_url)}&timeout={NODE_TIMEOUT}000"
                
                try:
                    response = requests.get(api_delay_url, headers=headers, timeout=NODE_TIMEOUT)
                    response.raise_for_status()
                    delay_data = response.json()
                    
                    # 6. 检查结果
                    delay = delay_data.get('delay', -1)
                    if delay > 0:
                        is_successful = True
                        break 
                except Exception:
                    pass

            if is_successful:
                return True, node_link # 成功返回，跳出重试循环
                
        except Exception:
            pass
            
        finally:
            # 7. 清理
            if clash_process:
                clash_process.terminate()
                
            # 清理文件
            for path in [CONFIG_PATH, LOG_PATH]:
                try:
                    if os.path.exists(path):
                        os.remove(path)
                except Exception:
                    pass
        
        # 如果当前尝试失败，并且不是最后一次尝试，则等待 1 秒后重试
        if attempt < MAX_RETRIES - 1:
            time.sleep(1) 

    # 所有重试次数都失败
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
            # 实时显示进度
            sys.stdout.write(f"[{i+1}/{len(valid_nodes)}] Testing... \r")
            sys.stdout.flush()
            
            try:
                status, link = future.result()
                results.append((status, link))
            except Exception as exc:
                print(f"\n❌ ERROR: 并行执行出错: {exc}", file=sys.stderr)
                
    # 清除进度条
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
