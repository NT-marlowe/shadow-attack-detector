# ベースイメージを指定
FROM ubuntu:22.04

# 必要なツールをインストール
RUN apt-get update && \
    apt-get install -y \
    clang-14 \
    llvm-14 \
    make \
    # llvm-strip-14 \
    libbpf-dev \
    linux-headers-generic \
    # bpftool \
    curl \
    gnupg && \
    ln -sf /usr/bin/clang-14 /usr/bin/clang && \
    ln -sf /usr/bin/llvm-strip-14 /usr/bin/llvm-strip && \
    ln -sf /usr/include/asm-generic /usr/include/asm

# Goのインストール
RUN curl -OL https://golang.org/dl/go1.20.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz && \
    rm go1.20.5.linux-amd64.tar.gz

# 環境変数を設定
ENV PATH=$PAHT:"/usr/local/go/bin:${PATH}"

# 作業ディレクトリを設定
WORKDIR /workspace
