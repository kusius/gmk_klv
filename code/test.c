#include "testdata.c"
#define GMK_KLV_IMPLEMENTATION
#include "klv/klv.h"
#define GMK_FILES_IMPLEMENTATION
#include "thirdparty/files.h"
#include <assert.h>
#include <time.h>

// Floating point accuracies for this test
#define DOUBLE_EPSILON 0.000001
#define FLOAT_EPSILON 0.001

bool testEquality(gmk_KLVElement actual, _KLVELEMENT expected) {
    switch (actual.valueType)
    {
        case GMK_KLV_VALUE_STRING:
            for(int i = 0; i < actual.length; i++) {
                if((char)actual.value[i] != expected.TEXT[i])
                return false;
            }

            return true;
        break;

        case GMK_KLV_VALUE_INT: 
            return atoi(expected.TEXT) == actual.intValue; 
        break;

        case GMK_KLV_VALUE_UINT64: {
            // time is the enemy
            return true;
            break;
        }
        case GMK_KLV_VALUE_DOUBLE: {
            double expectedDouble = strtod(expected.TEXT, NULL);
            return fabs(expectedDouble - actual.doubleValue) <= DOUBLE_EPSILON; 
            break;
        }
        case GMK_KLV_VALUE_FLOAT: {
            float expectedFloat = strtof(expected.TEXT, NULL);
            return fabsf(expectedFloat - actual.floatValue) <= FLOAT_EPSILON; 
            break;
        }
        case GMK_KLV_VALUE_UNKNOWN: 
            return true; 
        break;
        case GMK_KLV_VALUE_PARSE_ERROR: {
            assert(1==0);
            return false;
        } break;

        default: 
            return false;
        break; 
    }
}

void klvValueAsString(gmk_KLVElement klv, char *out, int size) {

    switch (klv.valueType)
    {
        case GMK_KLV_VALUE_STRING:
        if(klv.length + 1 <= size) {
           for(int i = 0; i < klv.length; i++) {
            out[i] = (char)klv.value[i];
           }

           out[klv.length] = '\0';
        }
        break;

        case GMK_KLV_VALUE_INT: sprintf(out, "%d", klv.intValue); break;
        case GMK_KLV_VALUE_UINT64: sprintf(out, "%llu", klv.uint64Value) ; break;
        case GMK_KLV_VALUE_DOUBLE: sprintf(out, "%lf", klv.doubleValue); break;
        case GMK_KLV_VALUE_FLOAT: sprintf(out, "%f", klv.floatValue); break;
        case GMK_KLV_VALUE_UNKNOWN: printf("Unknown value type for key %d\n", gmk_klvKey(klv)); break;
        case GMK_KLV_VALUE_PARSE_ERROR: {
            printf("Parse error for key: %d", gmk_klvKey(klv));
            assert(1==0);
        } break;

        default: break;
    }
}

// Prints KLV as : 
// Key(xx)
// Length(xx)
// Value(binary)(readable data type)
void printKlvSet(gmk_KLVElement *klvSet, int size) {
        for(int i = 0; i < size; i++) {
            gmk_KLVElement klv = klvSet[i];

            if(klv.length != 0) {
                printf("Key(%d)\nLength(%d)\nValue(", gmk_klvKey(klv), klv.length);

                // print value as hex
                for(int j = 0; j < klv.length; j++) {
                    printf("%hhx ",  klv.value[j]);
                }
                printf(")(");

                // readable prints
                char buf[512];
                klvValueAsString(klv, buf, 512);
                printf("%s", buf);
                printf(")\n\n");
            }
        }
}


void onEndSetCallback(gmk_KLVElement *klvSet, int size) {
    static int testSetIndex = 0;
    LocalSet expectedSet;
    expectedSet.original = KLV.Local_Set[testSetIndex++];

    for(int i = 0; i < size; i++) {
        gmk_KLVElement klv = klvSet[i];
        int klvKey = gmk_klvKey(klv);

        // Find the key in the expected test data set
        int testIndex = findIndexOfKey(expectedSet.original, klvKey);

        // Test 1: Existence of key in test set
        // Parser should not parse a value that is not in the test set.
        if(testIndex < 0) {
            printf("Key %d was found by the parser by error!\n", klvKey);
            assert(false);
        }        

        // Test 2: Correct parsing of test key
        char buf[512];
        klvValueAsString(klv, buf, 512);
        if(!testEquality(klv, expectedSet.parseable.elements[testIndex])) {
            printf("ERROR for key (%d) Expected value %s, got value %s\n", klvKey, expectedSet.parseable.elements[testIndex].TEXT, buf);
            assert(false);
        } else {
            printf("Correct value %s for key %d\n", buf, klvKey);
        }
    }
    
    // printKlvSet(klvSet, size);
}

int main(void) {
    const char *testFilePath = "./svt_testset_420_720p50_klved_4774.klv";
    FILE *file = NULL;
    file = fopen(testFilePath, "rb");

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
    struct gmk_KLVParser parser = gmk_newKlvParser();
    gmk_klvParse(&parser, data, bytesRead, onEndSetCallback);
    
    free(data);
    return 0;
}