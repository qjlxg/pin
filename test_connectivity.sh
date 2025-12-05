#!/bin/bash

# 设置时区为上海
export TZ='Asia/Shanghai'

# 配置文件链接 (脚本将直接从这些链接下载最新内容)
CONFIG_URLS=(
    "https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/merged_configs.txt"
   
)

# 临时文件
TEMP_NODES_FILE=$(mktemp)
SUCCESS_NODES_FILE=$(mktemp)

# 1. 下载并合并节点信息
echo "--- 正在下载配置文件 ---"
for url in "${CONFIG_URLS[@]}"; do
    echo "下载: $url"
    # 使用 curl -sL 下载内容
    curl -sL "$url" >> "$TEMP_NODES_FILE"
done

# 2. 解析和测试节点连通性
echo "--- 正在解析和测试节点连通性 (使用 nc 检查端口开放性) ---"
# 注意: 以下解析逻辑针对常见代理链接格式进行简化提取，可能不适用于所有情况。
grep -vE '^\s*$' "$TEMP_NODES_FILE" | while IFS= read -r line; do
    HOST=""
    PORT=""

    # 尝试提取 @HOST:PORT 部分
    if [[ "$line" =~ @([0-9a-zA-Z\.\-]+):([0-9]+) ]]; then
        HOST="${BASH_REMATCH[1]}"
        PORT="${BASH_REMATCH[2]}"
    # 尝试提取 PROTOCOL://HOST:PORT/... 部分
    elif [[ "$line" =~ ://([0-9a-zA-Z\.\-]+):([0-9]+) ]]; then
        HOST="${BASH_REMATCH[1]}"
        PORT="${BASH_REMATCH[2]}"
    fi

    if [ -n "$HOST" ] && [ -n "$PORT" ]; then
        echo "测试节点: $HOST:$PORT"
        # 使用 nc -z -w 2 检查端口连通性 (TCP SYN check, 2秒超时)
        if nc -z -w 2 "$HOST" "$PORT" &> /dev/null; then
            echo "  ✅ 成功: $HOST:$PORT"
            # 记录原始的成功节点链接
            echo "$line" >> "$SUCCESS_NODES_FILE"
        else
            echo "  ❌ 失败: $HOST:$PORT"
        fi
    # else
    #     echo "  ⚠️ 警告: 无法从链接中解析主机和端口。跳过: $line"
    fi
done

# 3. 生成报告目录和文件名 (上海时区)
TIMESTAMP=$(date +'%Y-%m-%d-%H-%M-%S')
OUTPUT_DIR=$(date +'%Y/%m')
OUTPUT_PATH="$OUTPUT_DIR/$TIMESTAMP-success-nodes.txt"

# 4. 创建目录并保存结果
if [ -s "$SUCCESS_NODES_FILE" ]; then
    echo "--- 保存成功节点到报告文件 ---"
    mkdir -p "$OUTPUT_DIR"
    
    # 写入报告头
    echo "# 节点连通性测试成功结果" > "$OUTPUT_PATH"
    echo "---" >> "$OUTPUT_PATH"
    echo "测试时间 (上海): $(date +'%Y-%m-%d %H:%M:%S')" >> "$OUTPUT_PATH"
    echo "---" >> "$OUTPUT_PATH"
    
    # 写入成功的节点链接
    cat "$SUCCESS_NODES_FILE" >> "$OUTPUT_PATH"
    
    echo "✅ 报告已生成: $OUTPUT_PATH"
else
    echo "⚠️ 没有节点测试成功。不生成报告文件。"
fi

# 5. 清理临时文件
rm "$TEMP_NODES_FILE" "$SUCCESS_NODES_FILE"

# 6. 输出报告路径供 Actions 使用
if [ -f "$OUTPUT_PATH" ]; then
    echo "REPORT_PATH=$OUTPUT_PATH"
fi
