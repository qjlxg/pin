# test_connectivity_parallel.py (更新版本)
import os
import sys
import datetime
import pytz
import re
import base64
from concurrent.futures import ThreadPoolExecutor
import subprocess
import requests

# 远程配置文件链接
REMOTE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt",
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/config.yaml",
]

# 最大并行工作线程数
MAX_WORKERS = 32

def fetch_and_parse_nodes():
    """
    下载远程文件，并解析出潜在的节点链接。
    加入了更严格的行过滤。
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
    
    # === 强化过滤逻辑 ===
    for line in all_lines:
        stripped_line = line.strip()
        
        # 排除空行、注释行 (#)
        if not stripped_line or stripped_line.startswith('#'):
            continue
            
        # 排除明显是噪音的行：太短的行（低于 10 个字符）或包含中文、时间戳、常见 URL 等
        if len(stripped_line) < 10 or \
           re.search(r'[\u4e00-\u9fff]', stripped_line) or \
           re.search(r'\d{1,2}:\d{2}', stripped_line) or \
           re.search(r'(play\.google\.com|github\.com|K)', stripped_line, re.IGNORECASE):
           continue
        
        # 检查是否包含 URL 协议头或 host:port 结构
        is_link = re.search(r'(://|@|\b(vmess|ss|trojan|vless)\b)', stripped_line, re.IGNORECASE)
        is_host_port = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:[0-9]{2,5}\b', stripped_line) # 匹配 IP:端口

        if is_link or is_host_port:
            unique_nodes.add(stripped_line)
        # else:
            # print(f"Skipping potential noise: {stripped_line[:50]}...") # 调试用

    print(f"过滤后，发现 {len(unique_nodes)} 个潜在节点链接。")
    return list(unique_nodes)


def extract_host_port(node_link):
    """
    尝试从节点链接中解析出 Host 和 Port。
    """
    # 1. 尝试匹配常见的 base64 编码
    match_b64 = re.search(r'//([a-zA-Z0-9+/=]+)', node_link)
    if match_b64:
        try:
            decoded_data = match_b64.group(1)
            # 自动添加 Base64 填充符
            padding_needed = 4 - (len(decoded_data) % 4)
            if padding_needed < 4:
                decoded_data += '=' * padding_needed
                
            # 使用 base64.urlsafe_b64decode 增加兼容性
            decoded = base64.urlsafe_b64decode(decoded_data).decode('utf-8', 'ignore')
            
            # 尝试从 JSON (如 Vmess) 中提取 "add" 和 "port"
            match_json = re.search(r'"add"\s*:\s*"(.*?)",\s*"port"\s*:\s*"(.*?)"', decoded)
            if match_json:
                return match_json.group(1), match_json.group(2)
            
            # 尝试从URL格式中提取 host:port (如 SS)
            match_url = re.search(r'^(.*?)@([0-9a-zA-Z\.\-]+):([0-9]+)', decoded)
            if match_url:
                return match_url.group(2), match_url.group(3)
                
        except:
            # Base64 解码或内部解析失败，忽略
            pass
    
    # 2. 尝试匹配非编码的 host:port (VLESS/Trojan/非编码SS)
    match_plain = re.search(r'([0-9a-zA-Z\.\-]+):([0-9]+)', node_link)
    if match_plain:
        return match_plain.groups()[-2], match_plain.groups()[-1]
        
    return None, None


def test_connectivity(node_link):
    """
    使用 nc (Netcat) 命令检查 TCP 端口是否开放。
    """
    host, port = extract_host_port(node_link)
    
    if not host or not port:
        # 如果解析失败，返回 False，并记录原始链接片段
        return False, node_link, f"无法解析主机/端口。原始链接片段: {node_link[:50]}..."

    try:
        # 使用 Netcat (nc) 检查端口连通性，超时 3 秒
        result = subprocess.run(
            ['nc', '-z', '-w', '3', host, port], 
            capture_output=True, 
            text=True
        )
        
        if result.returncode == 0:
            return True, node_link, f"✅ TCP端口开放: {host}:{port}"
        else:
            return False, node_link, f"❌ TCP端口关闭或超时: {host}:{port}"

    except Exception as e:
        return False, node_link, f"测试时发生内部错误: {e}"


def run_tests_parallel(all_nodes):
    """
    使用线程池并行运行测试。
    """
    print("--- 2. 正在并行测试节点 ---")
    
    # ... (与之前版本相同)
    results = []
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_node = {executor.submit(test_connectivity, node): node for node in all_nodes}
        
        for i, future in enumerate(future_to_node):
            try:
                status, link, message = future.result()
                results.append((status, link))
                print(f"[{i+1}/{len(all_nodes)}] {'SUCCESS' if status else 'FAIL'}: {message}")
            except Exception as exc:
                print(f"[{i+1}/{len(all_nodes)}] ❌ ERROR: 并行执行出错: {exc}", file=sys.stderr)
                
    return results


def save_results(results):
    """
    生成并保存成功的节点链接到带时间戳的文件。
    """
    shanghai_tz = pytz.timezone('Asia/Shanghai')
    now_shanghai = datetime.datetime.now(shanghai_tz)
    
    output_dir = now_shanghai.strftime('%Y/%m')
    output_filename = now_shanghai.strftime('%Y-%m-%d-%H-%M-%S') + '-success-nodes.txt'
    output_path = os.path.join(output_dir, output_filename)

    successful_nodes = [link for status, link in results if status]
    
    print("--- 3. 正在生成报告 ---")
    
    if not successful_nodes:
        print("⚠️ 没有节点测试成功。不生成报告文件。")
        return None

    os.makedirs(output_dir, exist_ok=True)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("# 节点连通性测试成功结果\n")
        f.write(f"测试时间 (上海): {now_shanghai.strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"总节点数: {len(results)}\n")
        f.write(f"成功连接数: {len(successful_nodes)}\n")
        f.write("---\n")
        
        for link in successful_nodes:
            f.write(f"{link}\n")

    print(f"✅ 测试完成。成功节点列表已保存到: {output_path}")
    return output_path

if __name__ == "__main__":
    
    # 1. 获取所有节点
    all_nodes = fetch_and_parse_nodes()
    
    if not all_nodes:
        sys.exit(0)
        
    # 2. 并行测试
    results = run_tests_parallel(all_nodes)
    
    # 3. 保存结果
    final_path = save_results(results)
    
    # 4. 传回输出文件名供 GitHub Actions 使用
    if final_path:
        print(f"REPORT_PATH={final_path}")
