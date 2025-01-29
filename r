#!/bin/bash

cd ./build/ &&
cmake .. &&
make &&
./gui/gui
