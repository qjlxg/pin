#!/bin/bash

# --- 配置 ---
# 要测试的远程配置文件链接 (已包含你新增的链接)
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
TEMP_NODES_FILE="temp_raw_nodes.txt"
HOSTS_PORTS_FILE="temp_hosts_to_test.txt"
TCP_SUCCESS_FILE="tcp_success_list.txt"
# 存储 TCP/UDP 双向连通节点的最终文件
OUTPUT_FILE="working_nodes_full.txt"

# 清理旧文件
rm -f "$TEMP_NODES_FILE" "$HOSTS_PORTS_FILE" "$TCP_SUCCESS_FILE" "$OUTPUT_FILE"

echo "--- 开始下载并解析节点配置 ---"

# --- 1. 下载并初步解析节点 ---
for url in "${CONFIG_URLS[@]}"; do
    echo "正在处理链接: $url"
    
    # 使用 curl 下载内容
    config_content=$(curl -s --retry 3 --fail "$url")
    if [ $? -ne 0 ]; then
        echo "警告: 无法下载 $url。跳过。"
        continue
    fi
    
    # 策略: 查找所有包含 "://" 的行，并将其添加到临时文件
    echo "$config_content" | grep '://' >> "$TEMP_NODES_FILE"
done

# 确保临时文件不为空
if [ ! -s "$TEMP_NODES_FILE" ]; then
    echo "错误: 未找到任何节点链接。退出。"
    exit 1
fi

# --- 2. 提取 IP/Domain 和 Port ---
declare -A UNIQUE_HOSTS
echo "--- 提取唯一的 HOST:PORT ---"
while read -r line; do
    host=""
    port=""
    
    # 简单提取 HOST:PORT (适用于Trojan/SS/Vless的非Base64部分)
    # 查找 @ 符号后的 HOST:PORT
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
        
        # 将 HOST:PORT 组合存储到关联数组中去重
        HOST_PORT_KEY="$host:$port"
        if [[ -z "${UNIQUE_HOSTS[$HOST_PORT_KEY]}" ]]; then
            UNIQUE_HOSTS["$HOST_PORT_KEY"]=1
            echo "$host $port" >> "$HOSTS_PORTS_FILE"
        fi
    fi
    unset host port
    
done < "$TEMP_NODES_FILE"

TOTAL_TESTS=${#UNIQUE_HOSTS[@]}
echo "总共找到并去重 $TOTAL_TESTS 个待测 HOST:PORT 组合。"
rm -f "$TEMP_NODES_FILE"

# --- 3. 执行 TCP 连通性测试 ---
echo "--- 开始 TCP 连通性测试 ($TIMEOUT_SECONDS 秒超时) ---"

# 使用 xargs -P 8 进行并行 TCP 测试
cat "$HOSTS_PORTS_FILE" | xargs -n 2 -P 8 bash -c '
    host="$1"
    port="$2"
    
    # TCP 连接测试
    if timeout '"$TIMEOUT_SECONDS"' bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
        # 成功则保存到临时文件供下一步 UDP 测试
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
    # nc -z: 零输入/输出模式 (只扫描)
    # nc -u: UDP 模式
    # 注意：UDP测试只检查端口是否开放并可达
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
