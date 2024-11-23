#!/bin/bash

cd ./build/ &&
cmake .. &&
make &&
clear &&
cd ./tests/ &&
./aes-byte-test &&
./aes-file-test

echo "RUNNING DIFF (no output is good)"
echo "FOR ECB ENCRYPTED FILES..."
diff ./ecb-128-encrypted.pdf ./samples/ecb-128-encrypted.pdf.dat
echo "FOR ECB DECRYPTED FILES..."
diff ./ecb-128-decrypted.pdf ./samples/file.pdf
echo "FOR CBC ENCRYPTED FILES..."
diff ./cbc-128-encrypted.pdf ./samples/cbc-128-encrypted.pdf.dat
echo "FOR CBC DECRYPTED FILES..."
diff ./cbc-128-decrypted.pdf ./samples/file.pdf
