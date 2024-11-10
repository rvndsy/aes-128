#!/bin/bash

# Key from NIST FIPS 197 Appendix A
EX_KEY=2b7e151628aed2a6abf7158809cf4f3c
EX_PTXT=ffddeeccbbaa00998877665544332211

./b &&
cd ./build &&
./aes $EX_PTXT $EX_KEY

echo
echo "Exit: $?"
