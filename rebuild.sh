#!/bin/bash

set -e

echo "[INFO] Cleaning old build..."
make clean

echo "[INFO] Rebuilding project..."
make -j16 && make install

echo "[INFO] Removing any old copies of librapidsnark.so from /usr/local/lib..."
if [ -f "/usr/local/lib/librapidsnark.so" ] || [ -L "/usr/local/lib/librapidsnark.so" ]; then
    sudo rm -f /usr/local/lib/librapidsnark.so
fi

echo "[INFO] Updating symlink in /usr/local/lib/"
sudo ln -sf $(pwd)/src/librapidsnark.so /usr/local/lib/librapidsnark.so
sudo ldconfig