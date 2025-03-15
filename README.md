## What?

DISCLAIMER: This was done purely as an educational exercise. It is NOT MEANT for real-world encryption and decryption of files. Use this program at your own risk!

This is a demonstration of my implementation of AES-128 cryptographic algorithm that is used for encryption and decryption of digital data. With the provided GUI you can encrypt and decrypt any file on your computer using AES-128 in ECB (Electronic Code Book) or CBC (Cipher Block Chaining) mode.

## Compile

### Linux

Compilation is done with the help of CMake. Create directory `build` and run the following command(s):

```
cd ./build/ &&\
cmake .. &&\
make &&\
./gui/gui
```

### Windows

Compilation on Windows is tricky but can be done with Visual Studio or Qt Creator. Just make sure to open the CMakeLists.txt as the project in Visual Studio and link Qt libraries dynamically after compilation of the executable with `qmake`. Detailed instructions are missing as of now... You can use the `./releases/win64-0.0.1/gui.exe` pre-compiled executable for now.

## Usage

See **Compilation** first.

DISCLAIMER: Please for the love of god do not encrypt your own personal files using this application thinking it is secure. It can lead to corruption of data, security vulnerabilities and loss of the original file.

1. Run `gui` in `./build/gui/gui` or, alternatively, run `./releases/win64-0.0.1/gui.exe`

2. Choose the file you wish to encrypt/decrypt in top-left
    - Files encrypted by this program end with `.dat`

3. Choose ECB or CBC mode;

4. Enter the key and iV as 16 hexadecimal characters (these are your *keys* or *passwords*)
    - Note: iV is only required for CBC mode!

5. Write the output file name in top-right. The output file name must contain the original extension!

6. Click decrypt or encrypt respectively.

## Notes on Qt development on Linux using Neovim with Clang as the LSP

Check `./DEVGUIDE.md`.
