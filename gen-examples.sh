#!/bin/bash

mkdir -p examples-bin
for i in examples/* ; do
        cc -o examples-bin/$(basename "${i%%.c}") "${i}"
done
