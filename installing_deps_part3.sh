#!/bin/bash

# halt on errors
set -e

# Config File
if [ ! -f configs/core.cfg ]; then
    cp configs/core.cfg.sample configs/core.cfg
fi

# create AILENV + install python packages
./install_virtualenv.sh

# force virtualenv activation
if [ -z "$VIRTUAL_ENV" ]; then
    . ./AILENV/bin/activate
fi

pushd ${AIL_HOME}/tools/gen_cert
./gen_root.sh
wait
./gen_cert.sh
wait
popd

cp ${AIL_HOME}/tools/gen_cert/server.crt ${AIL_FLASK}/server.crt
cp ${AIL_HOME}/tools/gen_cert/server.key ${AIL_FLASK}/server.key

mkdir -p $AIL_HOME/PASTES

#### DB SETUP ####

# init update version
pushd ${AIL_HOME}
# shallow clone
git fetch --depth=500 --tags --prune || true
if [ ! -z "$TRAVIS" ]; then
    echo "Travis detected"
    git fetch --unshallow || true
fi
git describe --abbrev=0 --tags 2>/dev/null | tr -d '\n' > ${AIL_HOME}/update/current_version || echo -n "v5.5" > ${AIL_HOME}/update/current_version
echo "AIL current version:"
cat ${AIL_HOME}/update/current_version
popd

# LAUNCH Kvrocks
bash ${AIL_BIN}/LAUNCH.sh -lkv &
wait
echo ""

# create default user
pushd ${AIL_FLASK}
python3 create_default_user.py
popd

bash ${AIL_BIN}/LAUNCH.sh -k &
wait
echo ""
