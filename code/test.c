#define KLV_IMPLEMENTATION
#include "klv/klv.h"
#define GMK_FILES_IMPLEMENTATION
#include "thirdparty/files.h"

int main(void) {
    KLVParser parser;
    FILE *file;
    file = fopen("./svt_testset_420 720p50_KLVED 4774.klv", "r");
    // file = fopen("./test.txt", "r");
    if(!file) {
        return -1;
    }

    uint8_t *data; 
    size_t bytesRead;

    int res = readall(file, &data, &bytesRead);

    if(res != READALL_OK) {
        printf("Error: %d\n", res);
        return res;
    }

    parse(&parser, data, bytesRead);
    for(int i = 0; i < MAX_UAS_TAGS; i++) {
        KLVElement *klv = &parser.uasDataSet[i];

        if(key(*klv) == 4) {
            for(int k = 0; k < klv->length; k++) {
                printf("%c", klv->value[k]);
            }
            printf("\n");
        }
    }

    int i;
    for(uint8_t *c = data, i = 0; i < bytesRead; c++, i++) {
        printf("%hhx ", *c);
    }
    printf("\n");

    
    return 0;
}