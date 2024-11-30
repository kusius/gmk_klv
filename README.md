# Single header uas dataset parsing

Based on [KLVP](https://github.com/jimcavoy/klvp/tree/main) algorithm.
This header library is based on the [stb style](https://github.com/nothings/stb/blob/master/docs/stb_howto.txt) guidelines. 

# Usage
Copy the `code/klv/klv.h` file in your project and use it with your build system of choice.

In **one** implementation (compile unit aka: cpp, c file) in your project do:
```C
#define KLV_IMPLEMENTATION
#include "klv.h"
```

You can `#include "klv.h"` in as many other files as you want. It will only act as a header and the implementation code will be ommited.

For usage of the API, see `test.c` in this repo. TL;DR
```C
// your_main.c

void onEndSetCallback(KLVElement *klvSet, int size) {
    // Do something with the parsed data.
    // This callback is called in the same thread the parse()
    // function was called. 
}

int main {
    // Get your binary KLV data from somewhere (it can also be in a loop)
    uint8_t data*; // your data buffer
    size_t dataSize; // the size of your data buffer

    struct KLVParser parser = klvParser();
    parse(&parser, data, bytesRead, onEndSetCallback);
}
```

## Compile the test of this repo 

`cd build` 

### Unix & MacOs
Compile and link the test

`clang -DTESTDATA_SVT_IMPLEMENTATION -g ../code/test.c -o test`

Run the test 

`./test`

### Windows
Compile and link the test

`clang -DTESTDATA_SVT_IMPLEMENTATION -g ../code/test.c -o test.exe`

or (MSVC compiler)

`cl /nologo /Zi /DTESTDATA_SVT_IMPLEMENTATION ../code/test.c /link /out:test.exe`
Run the test

`./test.exe`


## For interesting usages see
... todo, put usages of library in KMP project