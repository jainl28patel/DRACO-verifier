#!/bin/bash

for d in $(find . -mindepth 1 -maxdepth 1 -type d) ; do 
  cd "$d" && rm -rf klee-* && rm *.bc && rm *.ll && cd ../
done