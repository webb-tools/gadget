#!/bin/bash
set -e
# ensure we kill all child processes when we exit
trap "trap - SIGTERM && kill -- -$$" SIGINT SIGTERM EXIT

echo "*** Start Gadget ***"
# Stage gadget for Alice
./target/release/blueprint-manager \
  --protocols-config ./global_protocols.toml \
  --shell-config shell-configs/local-testnet-0.toml &

# Stage gadget for Bob
./target/release/blueprint-manager \
  --protocols-config ./global_protocols.toml \
  --shell-config shell-configs/local-testnet-1.toml &

# Stage gadget for Charlie
./target/release/blueprint-manager \
  --protocols-config ./global_protocols.toml \
  --shell-config shell-configs/local-testnet-2.toml \
  -vvv

popd
