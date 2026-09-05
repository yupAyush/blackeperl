#!/bin/bash
signalListener() {
    "$@" &
    pid="$!"
    trap "echo 'Stopping'; kill -SIGTERM $pid" SIGINT SIGTERM

    while kill -0 $pid > /dev/null 2>&1; do
        wait
    done
}


source ./AILENV/bin/activate

# Start Tor so the De-anonymization scanner can reach .onion services over
# SOCKS (127.0.0.1:9050). Must be up before the Flask app initialises the
# TorMisconfigScanner, which detects the SOCKS port at construction time.
if command -v tor >/dev/null 2>&1; then
    echo "        * Launching Tor SOCKS proxy (9050)"
    tor --RunAsDaemon 1 --Log "notice file /tmp/tor.log" >/dev/null 2>&1 || true
fi

cd bin
./LAUNCH.sh -l

signalListener tail -f /dev/null $@

./LAUNCH.sh -k
