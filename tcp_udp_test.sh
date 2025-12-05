#!/bin/bash

# --- 配置 ---
# 要测试的远程配置文件链接
CONFIG_URLS=(
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt"
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/config.yaml"
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml"
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/520.yaml"
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/all_unique_nodes.txt"
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/link.yaml"
    "https://raw.githubusercontent.com/qjlxg/go/refs/heads/main/nodes.txt"
)
# 允许的最大超时时间（秒）
TIMEOUT_SECONDS=3

# 临时文件和最终文件
TEMP_URI_FILE="temp_raw_uris.txt" # 存储非YAML链接
HOSTS_PORTS_FILE="temp_hosts_to_test.txt"
TCP_SUCCESS_FILE="tcp_success_list.txt"
# 存储 TCP/UDP 双向连通节点的最终文件
OUTPUT_FILE="working_nodes_full.txt"

# 清理旧文件
rm -f "$TEMP_URI_FILE" "$HOSTS_PORTS_FILE" "$TCP_SUCCESS_FILE" "$OUTPUT_FILE"

echo "--- 开始下载并解析节点配置 ---"

# --- 1. 下载并初步解析节点 (支持 URI 和 YAML 格式) ---
for url in "${CONFIG_URLS[@]}"; do
    echo "正在处理链接: $url"
    
    # 使用 curl 下载内容
    config_content=$(curl -s --retry 3 --fail "$url")
    if [ $? -ne 0 ]; then
        echo "警告: 无法下载 $url。跳过。"
        continue
    fi
    
    # 【新增逻辑】判断是否为 YAML 文件并使用 yq 解析
    if [[ "$url" =~ \.(yaml|yml)$ ]]; then
        echo " -> 识别为 YAML 格式，尝试使用 yq 解析..."
        
        # 提取 Clash 格式中的 server 和 port (假设结构为 proxies: [...])
        echo "$config_content" | yq -r '.proxies[] | select(.server != null and .port != null) | "\(.server) \(.port)"' >> "$HOSTS_PORTS_FILE"
    else
        # 否则，视为 URI 订阅链接列表，查找包含 "://" 的行
        echo "$config_content" | grep '://' >> "$TEMP_URI_FILE"
    fi

done

# 确保至少有URI文件或YAML解析结果
if [ ! -s "$TEMP_URI_FILE" ] && [ ! -s "$HOSTS_PORTS_FILE" ]; then
    echo "错误: 未找到任何节点链接或解析失败。退出。"
    exit 1
fi

# --- 2. 提取 IP/Domain 和 Port (仅处理 URI 文件) ---
declare -A UNIQUE_HOSTS
echo "--- 提取唯一的 HOST:PORT (来自 URI 链接) ---"

# 统计当前从 YAML 解析的 HOST:PORT 数量，用于去重
while read -r host port; do
    HOST_PORT_KEY="$host:$port"
    UNIQUE_HOSTS["$HOST_PORT_KEY"]=1
done < "$HOSTS_PORTS_FILE"

# 处理 URI 文件 (ss://, vmess://, trojan:// 等)
while read -r line; do
    host=""
    port=""
    
    # 简单提取 HOST:PORT (适用于Trojan/SS/Vless的非Base64部分)
    if [[ "$line" =~ @([0-9a-zA-Z\.\-_]+):([0-9]+)# ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        
    # 尝试处理 Vmess/Vless (查找 base64 后的内容)
    elif [[ "$line" =~ ://([a-zA-Z0-9+/=]+) ]]; then
        base64_part="${BASH_REMATCH[1]}"
        # 尝试解码并提取 address 和 port (需要 jq)
        decoded_json=$(echo "$base64_part" | base64 -d 2>/dev/null)
        if echo "$decoded_json" | jq -e '.add' &>/dev/null; then
             host=$(echo "$decoded_json" | jq -r '.add')
             port=$(echo "$decoded_json" | jq -r '.port')
        fi
    fi

    # 进一步清理，如果提取成功
    if [[ -n "$host" && -n "$port" ]]; then
        # 排除私有 IP 范围
        if [[ "$host" =~ ^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.) ]]; then
            continue
        fi
        
        # 将 HOST:PORT 组合存储到关联数组中去重，并追加到测试文件
        HOST_PORT_KEY="$host:$port"
        if [[ -z "${UNIQUE_HOSTS[$HOST_PORT_KEY]}" ]]; then
            UNIQUE_HOSTS["$HOST_PORT_KEY"]=1
            echo "$host $port" >> "$HOSTS_PORTS_FILE"
        fi
    fi
    unset host port
    
done < "$TEMP_URI_FILE"

TOTAL_TESTS=${#UNIQUE_HOSTS[@]}
echo "总共找到并去重 $TOTAL_TESTS 个待测 HOST:PORT 组合。"
rm -f "$TEMP_URI_FILE"

# --- 3. 执行 TCP 连通性测试 ---
echo "--- 开始 TCP 连通性测试 ($TIMEOUT_SECONDS 秒超时) ---"

# 使用 xargs -P 8 进行并行 TCP 测试
cat "$HOSTS_PORTS_FILE" | xargs -n 2 -P 8 bash -c '
    host="$1"
    port="$2"
    
    # TCP 连接测试
    if timeout '"$TIMEOUT_SECONDS"' bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
        echo "$host $port" >> "'"$TCP_SUCCESS_FILE"'"
        echo "✅ TCP SUCCESS: $host:$port"
    fi
' _

TCP_COUNT=$(wc -l < "$TCP_SUCCESS_FILE")
if [ "$TCP_COUNT" -eq 0 ]; then
    echo "---"
    echo "警告: 未找到 TCP 连通的节点，跳过 UDP 测试。"
    rm -f "$HOSTS_PORTS_FILE"
    exit 0
fi
echo "--- TCP 测试完成，共 $TCP_COUNT 个节点连通。---"

# --- 4. 执行 UDP 连通性测试 (仅针对 TCP 成功的节点) ---
echo "--- 开始 UDP 连通性测试 ($TIMEOUT_SECONDS 秒超时) ---"

# 使用 xargs -P 8 进行并行 UDP 测试
cat "$TCP_SUCCESS_FILE" | xargs -n 2 -P 8 bash -c '
    host="$1"
    port="$2"
    
    # UDP 连接测试 (使用 nc -zuv)
    if timeout '"$TIMEOUT_SECONDS"' nc -zuv $host $port 2>/dev/null; then
        echo "$host:$port" >> "'"$OUTPUT_FILE"'"
        echo "🎉 DUAL SUCCESS: $host:$port (TCP/UDP 双通)"
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
