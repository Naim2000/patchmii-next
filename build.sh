#!/usr/bin/env bash

make clean
make
cp patchmii-next.a test/lib/
pushd test
make clean
make
popd
