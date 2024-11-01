#!/bin/bash

# 版本号
VERSION="v1.0.0"

# 创建构建目录
mkdir -p dist

# 支持的系统和架构
PLATFORMS=("windows/amd64" "windows/386" "darwin/amd64" "darwin/arm64" "linux/amd64" "linux/386" "linux/arm64")

# 遍历每个平台进行构建
for PLATFORM in "${PLATFORMS[@]}"; do
    # 分割系统和架构
    IFS='/' read -r -a array <<< "$PLATFORM"
    GOOS="${array[0]}"
    GOARCH="${array[1]}"
    
    # 设置输出文件名
    OUTPUT="safewallet"
    if [ $GOOS = "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi
    
    # 构建文件名
    FILENAME="safewallet_${VERSION}_${GOOS}_${GOARCH}"
    if [ $GOOS = "windows" ]; then
        FILENAME="${FILENAME}.exe"
    fi
    
    # 设置环境变量并执行构建
    echo "Building for $GOOS/$GOARCH..."
    GOOS=$GOOS GOARCH=$GOARCH go build -o "dist/${FILENAME}" -ldflags="-s -w"
    
    # 检查构建是否成功
    if [ $? -ne 0 ]; then
        echo "Error building for $GOOS/$GOARCH"
        exit 1
    fi
    
    # 为Unix系统添加执行权限
    if [ $GOOS != "windows" ]; then
        chmod +x "dist/${FILENAME}"
    fi
    
    echo "Done building for $GOOS/$GOARCH"
done

echo "All builds completed!" 