#!/bin/bash
BASEDIR=$(dirname "$0")
cd $BASEDIR

workPath="../install"

# build type Debug, Release, RelWithDebInfo and MinSizeRel

mkdir build
cd build
cmake ../ \
    -DCMAKE_INSTALL_PREFIX=${workPath} \
    -DWITH_OPENSSL=on \


num=$(cat /proc/cpuinfo  | grep process | wc -l)
make -j${num} 
make install
