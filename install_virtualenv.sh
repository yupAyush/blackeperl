#!/bin/bash

# halt on errors
set -e

## bash debug mode toggle below
#set -x

if [ -z "$VIRTUAL_ENV" ]; then

    virtualenv -p python3 AILENV

    echo export AIL_HOME=$(pwd) >> ./AILENV/bin/activate
    echo export AIL_BIN=$(pwd)/bin/ >> ./AILENV/bin/activate
    echo export AIL_FLASK=$(pwd)/var/www/ >> ./AILENV/bin/activate
    echo export AIL_REDIS=$(pwd)/redis/src/ >> ./AILENV/bin/activate
    echo export AIL_KVROCKS=$(pwd)/kvrocks/src/ >> ./AILENV/bin/activate

fi


# activate virtual environment
. ./AILENV/bin/activate


pip3 install -U pip
pip3 install 'git+https://github.com/D4-project/BGP-Ranking.git/@7e698f87366e6f99b4d0d11852737db28e3ddc62#egg=pybgpranking&subdirectory=client'

# easyocr (in requirements.txt) depends on torch. On Linux, plain pip resolves
# the default CUDA-enabled torch build, which drags in several GB of NVIDIA
# CUDA wheels this container will never use (no GPU passthrough is set up).
# Install the much smaller CPU-only build first so the resolver considers it
# already satisfied.
pip3 install torch torchvision --index-url https://download.pytorch.org/whl/cpu

pip3 install -U -r requirements.txt

# Py tlsh
pushd tlsh/py_ext
python3 setup.py build
python3 setup.py install

# Download the necessary NLTK corpora and sentiment vader
HOME=$(pwd) python3 -m textblob.download_corpora
python3 -m nltk.downloader vader_lexicon
python3 -m nltk.downloader punkt
popd

pushd ${AIL_FLASK}
./update_thirdparty.sh
popd
