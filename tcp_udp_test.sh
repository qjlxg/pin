#!/bin/bash

# --- 配置 ---
# 要测试的远程配置文件链接
CONFIG_URLS=(
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt"
)
# 减少超时时间为 3 秒
TIMEOUT_SECONDS=3
# 提高并行度到 32
PARALLEL_JOBS=32

# 临时文件和最终文件
TEMP_URI_FILE="temp_raw_uris.txt"
HOSTS_PORTS_FILE="temp_hosts_to_test.txt"
TCP_SUCCESS_FILE="tcp_success_list.txt"
OUTPUT_FILE="working_nodes_full.txt"

# 计算文件的绝对路径，确保 xargs 子进程能够找到并写入
ABS_TCP_SUCCESS_FILE="$(pwd)/$TCP_SUCCESS_FILE"
ABS_OUTPUT_FILE="$(pwd)/$OUTPUT_FILE"

# --- 依赖检查函数 ---
check_dependency() {
    local cmd="$1"
    local hint="$2"
    if ! command -v "$cmd" &> /dev/null; then
        echo "错误: 缺少依赖工具 '$cmd'."
        echo "提示: 请安装 $hint 才能运行此脚本。"
        exit 1
    fi
}

# --- 检查依赖 ---
check_dependency "curl" "curl (用于下载配置)"
check_dependency "yq" "yq (用于解析 YAML 配置，例如: sudo apt install yq 或 brew install yq)"
check_dependency "jq" "jq (用于解析 JSON/Base64 节点信息，例如: sudo apt install jq 或 brew install jq)"
check_dependency "nc" "netcat/nc (用于 UDP 测试，例如: sudo apt install netcat-openbsd 或 brew install netcat)"

# 清理旧文件
rm -f "$TEMP_URI_FILE" "$HOSTS_PORTS_FILE" "$TCP_SUCCESS_FILE" "$OUTPUT_FILE"

# 确保成功文件存在，即使为空，防止后续 wc -l 和 cat 命令报错
touch "$TCP_SUCCESS_FILE" "$OUTPUT_FILE"

echo "--- 开始下载并解析节点配置 ---"

# --- 1. 下载并初步解析节点 (支持 URI 和 YAML 格式) ---
for url in "${CONFIG_URLS[@]}"; do
    echo "正在处理链接: $url"
    
    # 尝试下载配置，最多重试 3 次
    config_content=$(curl -s --retry 3 --fail "$url")
    if [ $? -ne 0 ]; then
        echo "警告: 无法下载 $url。跳过。"
        continue
    fi
    
    if [[ "$url" =~ \.(yaml|yml)$ ]]; then
        echo " -> 识别为 YAML 格式，尝试使用 yq 解析..."
        # 使用 yq 提取 host 和 port，并写入 hosts/ports 文件
        echo "$config_content" | yq -r '.proxies[] | select(.server != null and .port != null) | "\(.server) \(.port)"' >> "$HOSTS_PORTS_FILE"
    else
        echo " -> 识别为 URI 列表或纯文本格式。"
        # 写入 URI 临时文件
        echo "$config_content" | grep '://' >> "$TEMP_URI_FILE"
    fi

done

if [ ! -s "$TEMP_URI_FILE" ] && [ ! -s "$HOSTS_PORTS_FILE" ]; then
    echo "错误: 未找到任何节点链接或解析失败。退出。"
    exit 1
fi

# --- 2. 提取 IP/Domain 和 Port (去重逻辑) ---
declare -A UNIQUE_HOSTS
echo "--- 提取唯一的 HOST:PORT (来自 YAML 和 URI) ---"

# A. 处理来自 YAML 的结果 (已在 HOSTS_PORTS_FILE 中)
while read -r host port; do
    HOST_PORT_KEY="$host:$port"
    UNIQUE_HOSTS["$HOST_PORT_KEY"]=1
done < "$HOSTS_PORTS_FILE" # <-- 修正的重定向

# B. 处理来自 URI 的结果
while read -r line; do
    host=""
    port=""
    
    # 1. 匹配 Vmess/Shadowsocks/Trojan 等 URI 格式
    if [[ "$line" =~ @([0-9a-zA-Z\.\-_]+):([0-9]+)# ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
    # 2. 尝试解析 V2ray Base64 格式 (如果 URI 包含 Base64 部分)
    elif [[ "$line" =~ ://([a-zA-Z0-9+/=]+) ]]; then
        base64_part="${BASH_REMATCH[1]}"
        # 使用 base64 -d 解码，并检查是否为有效的 JSON 结构
        decoded_json=$(echo "$base64_part" | base64 -d 2>/dev/null)
        if echo "$decoded_json" | jq -e '.add' &>/dev/null; then
            host=$(echo "$decoded_json" | jq -r '.add')
            port=$(echo "$decoded_json" | jq -r '.port')
        fi
    fi

    # 检查并去重
    if [[ -n "$host" && -n "$port" ]]; then
        # 跳过内网 IP
        if [[ "$host" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
            continue
        fi
        
        HOST_PORT_KEY="$host:$port"
        if [[ -z "${UNIQUE_HOSTS[$HOST_PORT_KEY]}" ]]; then
            UNIQUE_HOSTS["$HOST_PORT_KEY"]=1
            echo "$host $port" >> "$HOSTS_PORTS_FILE"
        fi
    fi
    unset host port
    
done < "$TEMP_URI_FILE" # <-- 修正的重定向

TOTAL_TESTS=$(wc -l < "$HOSTS_PORTS_FILE")
echo "总共找到并去重 $TOTAL_TESTS 个待测 HOST:PORT 组合。"
rm -f "$TEMP_URI_FILE"

# --- 3. 执行 TCP 连通性测试 (新增延迟测量) ---
echo "--- 开始 TCP 连通性测试 (超时: $TIMEOUT_SECONDS 秒, 并行度: $PARALLEL_JOBS) ---"

# 使用函数包装测试逻辑，以更好地处理时间和输出
tcp_test() {
    local host="$1"
    local port="$2"
    local abs_success_file="$3" # 接收绝对路径
    local start_time=$(date +%s%N) # 纳秒级开始时间
    local end_time

    # 使用 timeout 和 /dev/tcp 进行连接尝试
    timeout "${TIMEOUT_SECONDS}" bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null
    local exit_code=$?
    
    end_time=$(date +%s%N) # 纳秒级结束时间

    if [ $exit_code -eq 0 ]; then
        # 计算毫秒延迟 (ns / 1,000,000)
        # 注意：bash 默认不支持浮点数运算，这里使用整数除法
        local latency_ms=$(( (end_time - start_time) / 1000000 ))
        
        # 使用传入的绝对路径写入文件
        echo "$host $port $latency_ms" >> "$abs_success_file"
        echo "✅ TCP SUCCESS: $host:$port (Latency: ${latency_ms}ms)"
    fi
}
export -f tcp_test

# 使用 xargs -P 进行并行 TCP 测试
# 传递 $ABS_TCP_SUCCESS_FILE 作为第三个参数
cat "$HOSTS_PORTS_FILE" | xargs -n 2 -P "$PARALLEL_JOBS" bash -c 'tcp_test "$1" "$2" "'"$ABS_TCP_SUCCESS_FILE"'"' _

# 重新计算行数，确保读取到最新的写入结果
TCP_COUNT=$(wc -l < "$TCP_SUCCESS_FILE")

if [ "$TCP_COUNT" -eq 0 ]; then
    echo "---"
    echo "警告: 未找到 TCP 连通的节点，跳过 UDP 测试。"
    rm -f "$HOSTS_PORTS_FILE" "$TCP_SUCCESS_FILE" "$OUTPUT_FILE"
    exit 0
fi
echo "--- TCP 测试完成，共 $TCP_COUNT 个节点连通。---"

# --- 4. 执行 UDP 连通性测试 ---
echo "--- 开始 UDP 连通性测试 (超时: $TIMEOUT_SECONDS 秒, 并行度: $PARALLEL_JOBS) ---"

# UDP 测试逻辑，现在从 TCP_SUCCESS_FILE 读取 (包含 HOST PORT LATENCY)
cat "$TCP_SUCCESS_FILE" | xargs -n 3 -P "$PARALLEL_JOBS" bash -c '
    host="$1"
    port="$2"
    latency="$3"
    abs_output_file="'"$ABS_OUTPUT_FILE"'" # 获取绝对路径
    
    # UDP 连接测试 (使用 nc -zuv，注意: nc 的 UDP 连通性测试并不总是可靠，但这是常见的 bash 做法)
    if timeout '"$TIMEOUT_SECONDS"' nc -zuv $host $port 2>/dev/null; then
        # 使用绝对路径写入最终结果文件
        echo "$host:$port (TCP Latency: ${latency}ms)" >> "$abs_output_file"
        echo "🎉 DUAL SUCCESS: $host:$port (TCP/UDP 双通, 延迟: ${latency}ms)"
    fi
' _

# --- 5. 结果总结 ---
DUAL_SUCCESS_COUNT=$(wc -l < "$OUTPUT_FILE")
echo "---"
echo "✅ 测试完成!"
echo "总共测试了 $TOTAL_TESTS 个节点。"
echo "其中 $TCP_COUNT 个节点 TCP 连通。"
echo "最终 $DUAL_SUCCESS_COUNT 个节点 TCP 和 UDP 双向连通，结果已保存到 $OUTPUT_FILE"

# 清理临时文件
rm -f "$HOSTS_PORTS_FILE" "$TCP_SUCCESS_FILE"

# 退出码 0 表示成功运行
exit 0
