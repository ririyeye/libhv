#!/bin/bash
BASEDIR=$(dirname "$0")
cd $BASEDIR

workPath="../install"

# build type Debug, Release, RelWithDebInfo and MinSizeRel

mkdir build
cd build
cmake ../ \
    -DCMAKE_INSTALL_PREFIX=${workPath} \
    -DBUILD_SHARED=off \
    -DWITH_OPENSSL=on \
    -DWITH_DTLS=on \
    -DCMAKE_BUILD_TYPE="Debug"


num=$(cat /proc/cpuinfo  | grep process | wc -l)
make -j${num} 
make install
