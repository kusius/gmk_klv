#include "testdata.c"
#define KLV_IMPLEMENTATION
#include "klv/klv.h"
#define GMK_FILES_IMPLEMENTATION
#include "thirdparty/files.h"
#include <assert.h>

void klvValueAsString(KLVElement klv, char *out, int size) {

    switch (klv.valueType)
    {
        case KLV_VALUE_STRING:
        if(size <= klv.length) {
            memcpy(out, klv.value, klv.length);       
        }
        break;

        case KLV_VALUE_INT: sprintf(out, "%d", klv.intValue); break;
        case KLV_VALUE_UINT64: sprintf(out, "%llu", klv.uint64Value) ; break;
        case KLV_VALUE_DOUBLE: sprintf(out, "%lf", klv.doubleValue); break;
        case KLV_VALUE_FLOAT: sprintf(out, "%f", klv.floatValue); break;
        case KLV_VALUE_UNKNOWN: printf("Unknown value type for key %d", key(klv)); break;
        case KLV_VALUE_PARSE_ERROR: {
            printf("Parse error for key: %d", key(klv));
            assert(1==0);
        } break;

        default: break;
    }
}

// Prints KLV as : 
// Key(xx)
// Length(xx)
// Value(binary)(readable data type)
void printKlvSet(KLVElement *klvSet, int size) {
        for(int i = 0; i < size; i++) {
            KLVElement klv = klvSet[i];

            if(klv.length != 0) {
                printf("Key(%d)\nLength(%d)\nValue(", key(klv), klv.length);

                // print value as hex
                for(int j = 0; j < klv.length; j++) {
                    printf("%hhx ",  klv.value[j]);
                }
                printf(")(");

                // readable prints
                switch (klv.valueType)
                {
                    case KLV_VALUE_STRING:              
                    for(int j = 0; j < klv.length; j++) {
                        printf("%c", klv.value[j]);
                    }
                    break;

                    case KLV_VALUE_INT: printf("%d", klv.intValue); break;
                    case KLV_VALUE_UINT64: printf("%llu", klv.uint64Value); break;
                    case KLV_VALUE_DOUBLE: printf("%lf", klv.doubleValue); break;
                    case KLV_VALUE_FLOAT: printf("%f", klv.floatValue); break;

                    case KLV_VALUE_UNKNOWN: printf("Unknown value type for key %d", key(klv)); break;
                    case KLV_VALUE_PARSE_ERROR: {
                        printf("Parse error for key: %d", key(klv));
                        assert(1==0);
                    } break;

                    default: break;
                }

                printf(")\n\n");
            }
        }
}


void onEndSetCallback(KLVElement *klvSet, int size) {
    static int testSetIndex = 0;
    struct _Local_Set expectedLocalSet = KLV.Local_Set[testSetIndex]; 

    for(int i = 0; i < size; i++) {
        KLVElement klv = klvSet[i];
        int klvKey = key(klv);

        // Find the key in the expected test data set
        int testIndex = findIndexOfKey(expectedLocalSet, klvKey);

        // Test 1: Existence of key in test set
        // Parser should not parse a value that is not in the test set.
        if(testIndex < 0) {
            printf("Key %d was found by the parser by error!\n", klvKey);
            assert(false);
        }        

        // Test 2: Correct parsing of test key
    }
    
    printKlvSet(klvSet, size);
}

int main(void) {
    FILE *file;
    file = fopen("./svt_testset_420 720p50_KLVED 4774.klv", "r");
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

    // Parse all the test file bytes
    struct KLVParser parser = klvParser();
    parse(&parser, data, bytesRead, onEndSetCallback);
    
    free(data);
    return 0;
}