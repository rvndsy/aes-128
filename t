#!/bin/bash

cd ./build/ &&
cmake .. &&
make &&
clear &&
cd ./tests/ &&
./aes-core-128 &&
./file-test

# echo
# echo "Exit: $?"
