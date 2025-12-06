# test_connectivity_parallel.py (最终版本 - 并行测试)
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

# --- 配置 ---
REMOTE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/pin/refs/heads/main/trojan_links.txt",
   
]

# 最大并行工作线程数 (推荐 32 或更高)
MAX_WORKERS = 32
# 测试 URL
TEST_URL = "http://www.google.com/generate_204"
# 每个节点的连接超时时间 (秒)
NODE_TIMEOUT = 10 

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
                # 修复重复协议前缀，例如 vmess://vmess://
                cleaned_line = stripped_line.replace("ss://ss://", "ss://").replace("vmess://vmess://", "vmess://")
                unique_nodes.add(cleaned_line)

    all_nodes = list(unique_nodes)
    print(f"修复并过滤后，发现 {len(all_nodes)} 个潜在节点链接。")
    return all_nodes

def test_single_node(node_link):
    """
    使用 Clash/Mihomo 核心作为子进程，测试单个节点连通性。
    此方法比直接使用 requests 库更准确，因为它能处理复杂的 Vmess/Trojan/VLESS 协议。
    """
    
    # 随机生成一个端口用于 Mihomo API
    try:
        api_port = 19190 + os.getpid() % 100 
    except:
        api_port = 19190 # Fallback 
        
    CLASH_EXEC = "mihomo-linux-amd64"
    CONFIG_PATH = f"config_{api_port}.yaml"
    LOG_PATH = f"mihomo_{api_port}.log"
    API_HOST = "127.0.0.1"
    
    # 1. 构造一个包含单个节点的 Clash YAML 配置
    yaml_content = f"""
mixed-port: 7890
external-controller: {API_HOST}:{api_port}
secret: githubactions
proxies:
  - {node_link}
proxy-groups:
  - name: TEST_GROUP
    type: select
    proxies:
      - {node_link.split('://')[0].upper()} # 使用节点类型作为名称，例如 SS/VMESS/TROJAN
      
"""
    
    # 尝试解析节点名称以获得代理名
    proxy_name_match = re.search(r'name=([^&]+)', node_link)
    if proxy_name_match:
        proxy_name = requests.utils.unquote(proxy_name_match.group(1).split('#')[-1])
        yaml_content = yaml_content.replace(f"- {node_link.split('://')[0].upper()}", f"- {proxy_name}")

    # 替换代理组中的代理名称
    proxy_name_final = yaml_content.split('proxies:')[1].split('\n')[1].strip().replace('- ', '')
    yaml_content = yaml_content.replace('TEST_GROUP', proxy_name_final)

    # 2. 保存配置
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
    except Exception as e:
        print(f"❌ 错误: 写入配置失败: {e}", file=sys.stderr)
        return False, node_link
    
    clash_process = None
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
        
        # 尝试 5 次，每次间隔 0.5s，总共等待 2.5s
        for _ in range(5): 
            try:
                response = requests.get(api_url, headers=headers, timeout=0.5)
                if response.status_code == 200:
                    break
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.5)
        else:
            # API 启动失败，视为测试失败
            return False, node_link 
            
        # 5. 触发延迟测试
        api_delay_url = f"http://{API_HOST}:{api_port}/proxies/{requests.utils.quote(proxy_name_final)}/delay?url={TEST_URL}&timeout={NODE_TIMEOUT}000"
        
        response = requests.get(api_delay_url, headers=headers, timeout=NODE_TIMEOUT)
        response.raise_for_status()
        delay_data = response.json()
        
        # 6. 检查结果
        delay = delay_data.get('delay', -1)
        if delay > 0:
            print(f"✅ SUCCESS ({delay}ms): {proxy_name_final}")
            return True, node_link
        else:
            return False, node_link
            
    except Exception as e:
        # print(f"❌ FAIL ({proxy_name_final}): {e}", file=sys.stderr)
        return False, node_link
        
    finally:
        # 7. 清理
        if clash_process:
            clash_process.terminate()
        if os.path.exists(CONFIG_PATH):
            os.remove(CONFIG_PATH)
        if os.path.exists(LOG_PATH):
            os.remove(LOG_PATH)


def run_parallel_tests(all_nodes):
    """
    使用线程池并行测试所有节点。
    """
    print("--- 2. 正在并行连通性测试 ---")
    results = []
    
    # 使用 ThreadPoolExecutor 并行执行测试
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有任务
        futures = {executor.submit(test_single_node, node_link): node_link for node_link in all_nodes}
        
        # 收集结果
        for i, future in enumerate(futures):
            # 实时显示进度
            sys.stdout.write(f"[{i+1}/{len(all_nodes)}] Testing... \r")
            sys.stdout.flush()
            
            try:
                status, link = future.result()
                results.append((status, link))
            except Exception as exc:
                print(f"[{i+1}/{len(all_nodes)}] ❌ ERROR: 并行执行出错: {exc}", file=sys.stderr)
                
    return results


def save_results(results):
    """
    生成并保存成功的节点链接到固定的文件 (无时间戳)。
    """
    shanghai_tz = pytz.timezone('Asia/Shanghai')
    now_shanghai = datetime.datetime.now(shanghai_tz)
    
    # 目录格式: YYYY/MM/
    output_dir = now_shanghai.strftime('%Y/%m')
    
    # 文件名: success-nodes-parallel.txt (与之前的 Subconverter 报告区分)
    output_filename = 'success-nodes-parallel.txt' 
    output_path = os.path.join(output_dir, output_filename)

    successful_nodes = [link for status, link in results if status]
    
    print("\n--- 3. 正在生成报告 ---")
    
    if not successful_nodes:
        print("⚠️ 没有节点测试成功。不生成报告文件。")
        return None

    os.makedirs(output_dir, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# 节点连通性测试成功结果 (并行测试)\n")
        f.write(f"测试时间 (上海): {now_shanghai.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总节点数: {len(results)}\n")
        f.write(f"成功连接数: {len(successful_nodes)}\n")
        f.write("---\n")
        
        for link in successful_nodes:
            f.write(f"{link}\n")

    print(f"✅ 测试完成。成功节点列表已保存到: {output_path}")
    return output_path

if __name__ == "__main__":
    
    # 检查 Mihomo 核心是否存在
    if not os.path.exists("./mihomo-linux-amd64"):
        print("❌ 错误：Mihomo 核心文件 ./mihomo-linux-amd64 未找到。", file=sys.stderr)
        sys.exit(1)
    
    # 授权执行
    try:
        subprocess.run(['chmod', '+x', './mihomo-linux-amd64'], check=True)
    except:
        pass # 假设工作流已经授权
        
    all_nodes = fetch_and_parse_nodes()
    
    if not all_nodes:
        print("没有找到任何节点，退出。")
        sys.exit(0)
    
    results = run_parallel_tests(all_nodes)
    
    final_path = save_results(results)
    
    if final_path:
        # 将结果路径输出到 GitHub Actions 变量
        print(f"REPORT_PATH={final_path}")
