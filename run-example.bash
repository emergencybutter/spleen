#!/bin/bash

mkdir -p examples-bin
for i in examples/* ; do
        gcc -o examples-bin/$(basename "${i%%.c}") "${i}"
done

for i in examples-bin/* ; do
        echo "Running spleen x86_64 emulator on binary $i."
        bash ./spleen.bash "$i"
done