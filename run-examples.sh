#!/bin/bash

for i in examples-bin/* ; do
        echo "Running spleen x86_64 emulator on binary $i."
        bash ./spleen.bash "$i"
done