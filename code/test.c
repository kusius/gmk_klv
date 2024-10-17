#define KLV_IMPLEMENTATION
#include "klv/klv.h"
#define GMK_FILES_IMPLEMENTATION
#include "thirdparty/files.h"

int main(void) {
    FILE *file;
    file = fopen("./test.txt", "r");
    if(!file) {
        return -1;
    }

    char *data; 
    size_t bytesRead;

    int res = readall(file, &data, &bytesRead);

    if(res != READALL_OK) {
        printf("Error: %d\n", res);
        return res;
    }

    int i;
    for(char *c = data, i = 0; *c != '\0' && i < bytesRead; c++, i++) {
        printf("%c", *c);
    }
    printf("\n");

    return 0;
}