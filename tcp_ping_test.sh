#!/bin/bash

# --- 配置 ---
# 要测试的远程配置文件链接
CONFIG_URLS=(
    "https://github.com/qjlxg/HA/raw/refs/heads/main/merged_configs.txt"
    "https://github.com/qjlxg/HA/raw/refs/heads/main/link.yaml"
)
# 允许的最大超时时间（秒）
TIMEOUT_SECONDS=3
# 存储连通节点的最终文件
OUTPUT_FILE="working_nodes.txt"
# 临时文件
TEMP_NODES_FILE="temp_nodes.txt"

# 清理旧文件
> "$TEMP_NODES_FILE"
> "$OUTPUT_FILE"

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
    
    # 尝试解析 Vmess/Shadowsocks/Trojan/Vless/Hysteria/Tuic 等链接
    # 策略: 查找所有包含 "://" 的行，并将其添加到临时文件
    echo "$config_content" | grep '://' >> "$TEMP_NODES_FILE"
done

# 确保临时文件不为空
if [ ! -s "$TEMP_NODES_FILE" ]; then
    echo "错误: 未找到任何节点链接。退出。"
    exit 1
fi

# --- 2. 提取 IP/Domain 和 Port ---
# Vmess/SS/Vless/Trojan 等链接的地址和端口通常是BASE64编码或位于协议头之后
# 这个脚本将尝试从常见格式中提取 HOST:PORT
# 注意: Base64 解码后的复杂 JSON 结构需要更复杂的解析，这里只做基本处理

# 创建一个集合来存储唯一的 HOST:PORT 组合
declare -A UNIQUE_HOSTS
HOSTS_PORTS_FILE="hosts_to_test.txt"
> "$HOSTS_PORTS_FILE"

echo "--- 提取唯一的 HOST:PORT ---"
while read -r line; do
    # 1. 解码 Base64 部分 (适用于 Vmess, Trojan, 部分 SS)
    # 提取 "://" 到 "@" 之间的 Base64 或原始内容
    # 注意：这里的正则匹配很困难，仅做尝试性提取
    
    # 简单提取 HOST:PORT (适用于Trojan/SS/Vless的非Base64部分)
    # 查找 @ 符号后的 HOST:PORT
    if [[ "$line" =~ @([0-9a-zA-Z\.\-_]+):([0-9]+)# ]]; then
        host="${BASH_REMATCH[1]}"
        port="${BASH_REMATCH[2]}"
        
    # 尝试处理 Vmess/Vless (查找 base64 后的内容)
    elif [[ "$line" =~ ://([a-zA-Z0-9+/=]+) ]]; then
        base64_part="${BASH_REMATCH[1]}"
        # 尝试解码并提取 address 和 port (需要 jq，但 GitHub Actions 默认有)
        decoded_json=$(echo "$base64_part" | base64 -d 2>/dev/null)
        if echo "$decoded_json" | jq -e '.add' &>/dev/null; then
             host=$(echo "$decoded_json" | jq -r '.add')
             port=$(echo "$decoded_json" | jq -r '.port')
        fi
    fi

    # 进一步清理，如果提取成功
    if [[ -n "$host" && -n "$port" ]]; then
        # 排除私有 IP 范围，除非您确定要测试内部网络
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
    # 清理变量
    unset host port
    
done < "$TEMP_NODES_FILE"

echo "总共找到并去重 ${#UNIQUE_HOSTS[@]} 个待测 HOST:PORT 组合。"
rm -f "$TEMP_NODES_FILE"

# --- 3. 执行 TCP Ping 测试 ---

echo "--- 开始 TCP 连通性测试 ($TIMEOUT_SECONDS 秒超时) ---"
TOTAL_TESTS=${#UNIQUE_HOSTS[@]}
TEST_COUNT=0

# 使用 xargs 进行并行测试
# -P 8: 设置并行度为 8
# -I {}: 将每一行作为输入替换 {}
cat "$HOSTS_PORTS_FILE" | xargs -n 2 -P 8 bash -c '
    host="$1"
    port="$2"
    
    # 记录开始时间
    START_TIME=$(date +%s%N)
    
    # 使用 bash 的 /dev/tcp 进行 TCP 连接尝试 (比 netcat 更常用且更轻量)
    # 配合 timeout 来限制时间
    if timeout '"$TIMEOUT_SECONDS"' bash -c "exec 3<>/dev/tcp/$host/$port" 2>/dev/null; then
        # 记录结束时间
        END_TIME=$(date +%s%N)
        
        # 计算延迟 (ms)
        LATENCY_MS=$(echo "scale=2; ($END_TIME - $START_TIME) / 1000000" | bc)
        
        echo "✅ SUCCESS: $host:$port (延迟: ${LATENCY_MS}ms)"
        echo "$host:$port" >> "'"$OUTPUT_FILE"'"
    else
        # 失败不输出，保持日志整洁
        :
    fi
' _

# --- 4. 结果总结 ---
WORKING_COUNT=$(wc -l < "$OUTPUT_FILE")
echo "---"
echo "✅ 测试完成!"
echo "总共测试了 $TOTAL_TESTS 个节点。"
echo "其中 $WORKING_COUNT 个节点端口是连通的。"

# 提交结果文件 (GitHub Actions 后续步骤将处理 Git 提交)
if [ "$WORKING_COUNT" -gt 0 ]; then
    echo "连通的节点列表已保存到 $OUTPUT_FILE"
else
    echo "未找到连通的节点，不创建或更新 $OUTPUT_FILE。"
fi

rm -f "$HOSTS_PORTS_FILE"
