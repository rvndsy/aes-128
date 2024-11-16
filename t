#!/bin/bash

## Key from NIST FIPS 197 Appendix A
#EX_KEY=2B7E151628AED2A6ABF7158809CF4F3C
#EX_PTXT=6BC1BEE22E409F96E93D7E117393172A
#EX_ENCR=3AD77BB40D7A3660A89ECAF32466EF97 # Should be the ptxt above

#./b &&
#cd ./build &&
#./aes $EX_PTXT $EX_KEY

clear &&
cd ./src/tests &&
./t $1

echo
echo "Exit: $?"
