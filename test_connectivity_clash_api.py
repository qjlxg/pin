# test_connectivity_clash_api.py (已修复 Argument list too long 和编码错误)
import os
import sys
import datetime
import pytz
import re
import base64 
import json
import subprocess
import requests
import time

# --- 配置 ---
REMOTE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt",
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/all_unique_nodes.txt",
    "https://raw.githubusercontent.com/qjlxg/go/refs/heads/main/nodes.txt",
]

# *** 核心：本地可执行文件路径 ***
LOCAL_MIHOMO_FILENAME = "mihomo-linux-amd64" 
LOCAL_SUB_EXECUTABLE = "./subconverter-linux64" 

CLASH_EXECUTABLE = f"./{LOCAL_MIHOMO_FILENAME}"
CLASH_CONFIG_PATH = "mihomo_config.yaml"
CLASH_LOG_PATH = "mihomo.log"
API_HOST = "127.0.0.1"
API_PORT = 19090
TEST_URL = "http://www.google.com/generate_204"

# --- 核心功能 ---

def download_clash_core():
    """检查本地 Mihomo 核心文件是否存在。"""
    print("--- 1. 正在检查本地 Mihomo 核心 ---")
    
    if not os.path.exists(CLASH_EXECUTABLE):
        print(f"❌ 错误：本地 Mihomo 核心文件未找到，路径：{CLASH_EXECUTABLE}", file=sys.stderr)
        return False
        
    print(f"✅ Mihomo 核心检查成功：{CLASH_EXECUTABLE}")
    return True

def fetch_and_parse_nodes():
    """下载并解析所有潜在的节点链接，返回原始文本格式的节点字符串。"""
    print("--- 2. 正在获取和解析所有节点 ---")
    all_content = []
    for url in REMOTE_CONFIG_URLS:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            all_content.append(response.text)
        except:
            print(f"⚠️ 警告: 下载 {url} 失败。", file=sys.stderr)

    all_lines = "\n".join(all_content).split('\n')
    unique_nodes = set()
    for line in all_lines:
        stripped_line = line.strip()
        if stripped_line and not stripped_line.startswith('#'):
            # 过滤主流协议链接
            if re.search(r'(://|@|\b(vmess|ss|trojan|vless)\b|server\s*:\s*.)', stripped_line, re.IGNORECASE):
                cleaned_line = stripped_line.replace("ss://ss://", "ss://").replace("vmess://vmess://", "vmess://")
                unique_nodes.add(cleaned_line)

    print(f"修复并过滤后，发现 {len(unique_nodes)} 个潜在节点链接。")
    # 直接返回原始节点字符串
    raw_nodes_string = '\n'.join(unique_nodes)
    return raw_nodes_string 

def convert_nodes_with_local_subconverter(raw_nodes_string):
    """
    通过本地 Subconverter 可执行文件将原始节点列表通过 stdin 转换为 Clash YAML。
    此方法彻底解决了 Argument list too long 的错误和编码冲突错误。
    """
    print("--- 3. 正在调用本地 Subconverter 转换配置 (通过 stdin 输入) ---")
    
    if not os.path.exists(LOCAL_SUB_EXECUTABLE):
        print(f"❌ 错误：本地 Subconverter 文件未找到。", file=sys.stderr)
        return False

    # 构建 Subconverter 命令行参数
    # -f text: 告诉 Subconverter 输入是 text 格式（raw 节点链接列表）
    # -e false: 确保输出是可读的 YAML，而不是 Base64
    command = [
        LOCAL_SUB_EXECUTABLE,
        '-r', 'https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online.ini', 
        '-f', 'text', 
        '-e', 'false',
    ]
    
    try:
        # 核心修复：通过 input 参数传递字符串对象，text=True 会自动处理编码
        result = subprocess.run(
            command, 
            input=raw_nodes_string, # 直接传递字符串 (str) 对象
            capture_output=True, 
            text=True, 
            check=True, 
            timeout=120
        )
        yaml_content = result.stdout
        
        if 'proxy-groups' not in yaml_content:
            raise ValueError("Subconverter 输出似乎不是有效的 Clash YAML 配置。")
            
        # --- 注入 Mihomo API 配置并优化测试 ---
        
        # 注入本地外部控制器
        controller_config = f"external-controller: {API_HOST}:{API_PORT}\nsecret: githubactions\n"
        yaml_content = yaml_content.replace("external-controller: 127.0.0.1:9090", controller_config) 
        if controller_config not in yaml_content:
             yaml_content = controller_config + "\n" + yaml_content

        # 将配置中所有 'select' 类型的组改为 'url-test' 以触发测试
        yaml_content = re.sub(r'type:\s*select', 'type: url-test', yaml_content)
        yaml_content = yaml_content.replace("url: http://www.gstatic.com/generate_204", f"url: {TEST_URL}")
        yaml_content = yaml_content.replace("interval: 3600", "interval: 300") 
        
        with open(CLASH_CONFIG_PATH, 'w', encoding='utf-8') as f:
            f.write(yaml_content)
        
        print(f"✅ Clash 配置本地转换并保存成功到: {CLASH_CONFIG_PATH}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Subconverter 执行失败 (错误代码: {e.returncode})", file=sys.stderr)
        print(f"Subconverter 错误输出: {e.stderr}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"❌ 转换或保存配置失败: {e}", file=sys.stderr)
        return False

def start_clash():
    """启动 Mihomo 核心并等待 API 准备就绪。"""
    print(f"--- 4. 正在启动 Mihomo 核心 ({CLASH_EXECUTABLE}) ---")
    
    clash_process = subprocess.Popen(
        [CLASH_EXECUTABLE, '-f', CLASH_CONFIG_PATH, '-d', '.'],
        stdout=open(CLASH_LOG_PATH, 'w'), 
        stderr=subprocess.STDOUT
    )
    
    api_url = f"http://{API_HOST}:{API_PORT}/version"
    headers = {'Authorization': 'Bearer githubactions'}
    
    print("等待 Mihomo API 启动...")
    for _ in range(20): 
        try:
            response = requests.get(api_url, headers=headers, timeout=0.5)
            if response.status_code == 200:
                print("✅ Mihomo API 启动成功。")
                return clash_process
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)

    print("❌ Mihomo API 启动超时或失败。请检查日志。")
    clash_process.terminate()
    return None

def run_clash_test(clash_process):
    """通过 Mihomo API 触发 URL 测试并获取结果。"""
    print("--- 5. 正在执行 URL 连通性测试 ---")
    
    api_group_names_url = f"http://{API_HOST}:{API_PORT}/configs"
    headers = {'Authorization': 'Bearer githubactions'}
    
    try:
        response = requests.get(api_group_names_url, headers=headers, timeout=10)
        config_data = response.json()
        
        test_group_name = None
        for group in config_data['proxyGroups']:
            if group['type'].lower() == 'urltest': 
                test_group_name = group['name']
                break
                
        if not test_group_name:
             raise ValueError("未在配置中找到 URL-Test 代理组。")
             
        encoded_group_name = requests.utils.quote(test_group_name)
        api_select_url = f"http://{API_HOST}:{API_PORT}/proxies/{encoded_group_name}"
        
        print(f"触发代理组 '{test_group_name}' URL 测试...")
        response = requests.get(api_select_url + f"/delay?url={TEST_URL}&timeout=5000", headers=headers, timeout=30)
        response.raise_for_status()
        time.sleep(5) 

        api_proxy_providers_url = f"http://{API_HOST}:{API_PORT}/providers/proxies"
        response = requests.get(api_proxy_providers_url, headers=headers, timeout=10)
        response.raise_for_status()
        proxy_data = response.json()
        
        successful_nodes = []
        
        for provider_name, provider_data in proxy_data.items():
            for proxy in provider_data.get('proxies', []):
                if 'delay' in proxy and isinstance(proxy['delay'], int) and proxy['delay'] > 0:
                    successful_nodes.append(proxy['name'])
                    
        print(f"✅ 成功找到 {len(successful_nodes)} 个可用节点。")
        return successful_nodes
        
    except Exception as e:
        print(f"❌ 执行 URL 测试或获取结果失败: {e}", file=sys.stderr)
        return []
        
def save_results(successful_node_names):
    """保存成功的节点名称。"""
    shanghai_tz = pytz.timezone('Asia/Shanghai')
    now_shanghai = datetime.datetime.now(shanghai_tz)
    output_dir = now_shanghai.strftime('%Y/%m')
    output_filename = 'success-nodes-mihomo-local.txt' 
    output_path = os.path.join(output_dir, output_filename)

    if not successful_node_names:
        print("⚠️ 没有节点测试成功。不生成报告文件。")
        return None

    os.makedirs(output_dir, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# 节点连通性测试成功结果 (Mihomo/Clash.Meta 本地 Subconverter 转换)\n")
        f.write(f"测试时间 (上海): {now_shanghai.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"成功连接数: {len(successful_node_names)}\n")
        f.write("---\n")
        
        for name in successful_node_names:
            f.write(f"{name}\n")

    print(f"✅ 测试完成。成功节点列表已保存到: {output_path}")
    return output_path

if __name__ == "__main__":
    
    if not download_clash_core():
        sys.exit(1)
    
    raw_nodes = fetch_and_parse_nodes()
    
    if not raw_nodes:
        sys.exit(0)
    
    # ！！！ 调用本地 Subconverter 转换函数 ！！！
    if not convert_nodes_with_local_subconverter(raw_nodes):
        sys.exit(1)
        
    clash_process = start_clash()
    
    if not clash_process:
        print("❌ Mihomo 核心启动失败，无法进行测试。")
        sys.exit(1)
        
    try:
        successful_names = run_clash_test(clash_process)
        final_path = save_results(successful_names)
        
        if final_path:
            print(f"REPORT_PATH={final_path}")
            
    finally:
        if 'clash_process' in locals() and clash_process:
            clash_process.terminate()
            print("Mihomo 进程已终止。")
