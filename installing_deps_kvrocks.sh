#!/bin/bash

# halt on errors
set -e

DEFAULT_HOME=$(pwd)

#### KVROCKS ####
test ! -d kvrocks/ && git clone https://github.com/apache/incubator-kvrocks.git kvrocks
pushd kvrocks
# Low parallelism on purpose: kvrocks' heavy fmt/spdlog headers use a lot of
# RAM per translation unit and -j4 can OOM-kill the Docker build VM.
./x.py build -j 1
popd

DEFAULT_KVROCKS_DATA=$DEFAULT_HOME/DATA_KVROCKS
mkdir -p $DEFAULT_KVROCKS_DATA

sed -i "s|dir /tmp/kvrocks|dir ${DEFAULT_KVROCKS_DATA}|1" $DEFAULT_HOME/configs/6383.conf
##-- KVROCKS --##
