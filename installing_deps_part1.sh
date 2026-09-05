#!/bin/bash

# halt on errors
set -e

if command -v apt-get >/dev/null 2>&1; then
    PKG_MANAGER="apt"
elif command -v pacman >/dev/null 2>&1; then
    PKG_MANAGER="pacman"
else
    echo "Unsupported system: neither apt-get nor pacman is available."
    exit 1
fi

SUDO=""
if command -v sudo >/dev/null 2>&1; then
    SUDO="sudo"
fi

install_packages() {
    local packages="$1"

    if [ "$PKG_MANAGER" = "apt" ]; then
        $SUDO apt-get update
        $SUDO apt-get install -y $packages
    elif [ "$PKG_MANAGER" = "pacman" ]; then
        $SUDO pacman -Syu --noconfirm --needed $packages
    else
        echo "No supported package manager found."
        exit 1
    fi
}

if [ "$PKG_MANAGER" = "apt" ]; then
    install_packages "python3-pip virtualenv python3-dev python3-tk libfreetype6-dev screen g++ unzip libsnappy-dev cmake"
    install_packages "automake libtool make gcc pkg-config"
    install_packages "wget"
    install_packages "libssl-dev libfreetype6-dev python3-numpy"
    install_packages "protobuf-compiler libprotobuf-dev"
    install_packages "python3-opencv libzbar0"
    install_packages "libadns1 libadns1-dev"
    install_packages "libev-dev libgmp-dev"
    install_packages "graphviz"
    install_packages "libfuzzy-dev"
    install_packages "build-essential libffi-dev autoconf"
    install_packages "p7zip-full"
else
    install_packages "python-pip python-virtualenv python freetype2 screen gcc unzip snappy cmake tk"
    install_packages "automake libtool make gcc pkg-config"
    install_packages "wget"
    install_packages "openssl freetype2 python-numpy"
    install_packages "protobuf"
    install_packages "opencv zbar"
    install_packages "adns"
    install_packages "libev gmp"
    install_packages "graphviz"
    install_packages "ssdeep"
    install_packages "base-devel libffi autoconf"
    install_packages "p7zip"
fi

# SUBMODULES #
git submodule update --init --recursive

# REDIS #
test ! -d redis/ && git clone https://github.com/redis/redis.git
pushd redis/
git checkout 5.0
make
popd

# tlsh
test ! -d tlsh && git clone https://github.com/trendmicro/tlsh.git
pushd tlsh/
./make.sh
pushd build/release/
sudo make install
sudo ldconfig
popd
popd

# pgpdump
test ! -d pgpdump && git clone https://github.com/kazu-yamamoto/pgpdump.git
pushd pgpdump/
autoreconf -fiW all
./configure
make
sudo make install
popd

# Yara
YARA_VERSION="4.3.0"
mkdir yara_temp
wget https://github.com/VirusTotal/yara/archive/v${YARA_VERSION}.zip -O yara_temp/yara.zip
unzip yara_temp/yara.zip -d yara_temp/
pushd yara_temp/yara-${YARA_VERSION}
./bootstrap.sh
./configure
make
sudo make install
make check
popd
rm -rf yara_temp
