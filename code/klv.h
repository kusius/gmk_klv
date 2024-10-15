/**
 * Version History:
 * 
 * 0.0.1: 
 * Initial implementation and port of klvp library in an implementation without other dependencies.
 * For ease of use in other programs or embedded in other languages.
 */

#if !defined KLV_H
#define KLV_H

#if  defined(_WIN32) || defined(WIN32)
 #include <Winsock2.h>
#else 
 #include 
#endif

#include <stdint.h>
#include <string.h>

// The KLV set type
// enum TYPE;
// The internal state n
// enum PARSE_STATE;
struct KLVElement;
struct KLVParser;

int parse(struct KLVParser* parser, const uint8_t* chunk, const int length);


#endif // !KLV_H


#if defined KLV_IMPLEMENTATION

// In order to have fixed memory needs, we define the maximum number 
// of total bytes that we are able to be parsed by this library.
#define KILOBYTES(x) (x) * 1024
#define MEGABYTES(x) (KILOBYTES(x)) * 1024
#if !defined MAX_PARSE_BYTES
#define MAX_PARSE_BYTES MEGABYTES(1)
#endif

const uint8_t LocalSetKey[] = { 
    0x06,0x0E,0x2B,0x34,
	0x02,0x0B,0x01,0x01,
	0x0E,0x01,0x03,0x01,
	0x01,0x00,0x00,0x00 
};

const uint8_t SecurityMetadataUniversalSetKey[] = {
    0x06,0x0E,0x2B,0x34,
    0x02,0x01,0x01,0x01,
    0x02,0x08,0x02,0x00,
    0x00,0x00,0x00,0x00
};

const uint8_t UniversalMetadataSetKey[] = {
    0x06,0x0E,0x2B,0x34,
    0x02,0x01,0x01,0x01,
    0x0E,0x01,0x01,0x02,
    0x01,0x01,0x00,0x00
};

const uint8_t UniversalMetadataElementKey[] = { 
    0x06, 0x0E, 0x2B, 0x34, 0x01 
};

typedef enum TYPE {
    LOCAL_SET, 
    UNIVERSAL_SET,
    SECURITY_UNIVERSAL_SET,  
    UNIVERSAL_ELEMENT, 
    UNKNOWN 
} TYPE;

typedef enum STATE {
    START_SET_KEY,
    START_SET_LEN_FLAG,
    START_SET_LEN,
    LEXING,
    PARSING
} STATE;

typedef struct KLVElement {
    // maximum bytes a key can be is 16
    uint8_t key[16];
    int keyLength;
    int length;
    uint8_t value[256];
} KLVElement;

static uint8_t key(const KLVElement klv) {
    return klv.keyLength == 0 ? 0 : klv.key[0];
}

// The UAS dataset klv elements we parse
#define KLVChecksum (KLVElement) {.key = {1}};
#define KLVUnixTimeStamp (KLVElement) {.key = {2}};
#define KLVMissionID (KLVElement) {.key = {3}};
#define KLVPlatformTailNumber (KLVElement) {.key = {4}};
#define KLVPlatformHeadingAngle (KLVElement) {.key = {5}};
#define KLVPlatformPitchAngle (KLVElement) {.key = {6}};
#define KLVPlatformRollAngle (KLVElement) {.key = {7}};
#define KLVPlatformTrueAirspeed (KLVElement) {.key = {8}};
#define KLVPlatformIndicatedAirspeed (KLVElement) {.key = {9}};
#define KLVPlatformDesignation (KLVElement) {.key = {10}};
#define KLVImageSourceSensor (KLVElement) {.key = {11}};
#define KLVImageCoordinateSystem (KLVElement) {.key = {12}};
#define KLVSensorLatitude (KLVElement) {.key = {13}};
#define KLVSensorLongitude (KLVElement) {.key = {14}};
#define KLVSensorTrueAltitude (KLVElement) {.key = {15}};
#define KLVSensorHorizontalFieldOfView (KLVElement) {.key = {16}};
#define KLVSensorVerticalFieldOfView (KLVElement) {.key = {17}};
#define KLVSensorRelativeAzimuthAngle (KLVElement) {.key = {18}};
#define KLVSensorRelativeElevationAngle (KLVElement) {.key = {19}};
#define KLVSensorRelativeRollAngle (KLVElement) {.key = {20}};
#define KLVSlantRange (KLVElement) {.key = {21}};
#define KLVTargetWidth (KLVElement) {.key = {22}};
#define KLVFrameCenterLatitude (KLVElement) {.key = {23}};
#define KLVFrameCenterLongitude (KLVElement) {.key = {24}};
#define KLVFrameCenterElevation (KLVElement) {.key = {25}};
#define KLVOffsetCornerLatitudePoint1 (KLVElement) {.key = {26}};
#define KLVOffsetCornerLongitudePoint1 (KLVElement) {.key = {27}};
#define KLVOffsetCornerLatitudePoint2 (KLVElement) {.key = {28}};
#define KLVOffsetCornerLongitudePoint2 (KLVElement) {.key = {29}};
#define KLVOffsetLatitudePoint3 (KLVElement) {.key = {30}};
#define KLVOffsetLongitudePoint3 (KLVElement) {.key = {31}};
#define KLVOffsetLatitudePoint4 (KLVElement) {.key = {32}};
#define KLVOffsetLongitudePoint4 (KLVElement) {.key = {33}};
#define KLVIcingDetected (KLVElement) {.key = {34}};
#define KLVwindDirection (KLVElement) {.key = {35}};
#define KLVWindSpeed (KLVElement) {.key = {36}};
#define KLVStaticPressure (KLVElement) {.key = {37}};
#define KLVDensityAltitude (KLVElement) {.key = {38}};
#define KLVOutsideAirTemperature (KLVElement) {.key = {39}};
#define KLVTargetLocationLatitude (KLVElement) {.key = {40}};
#define KLVTargetLocationLongitude (KLVElement) {.key = {41}};
#define KLVTargetLocationeElevation (KLVElement) {.key = {42}};


// Other parsing results 
#define KLVParseError(key) (KLVElement) {.key = {(key)}};
#define KLVUnknown(key) (KLVElement) {.key = {(key)}};

typedef struct KLVParser {
    STATE state;
    TYPE type;
    uint8_t buffer[MAX_PARSE_BYTES];
    uint8_t sodb[MAX_PARSE_BYTES];
    // indices of buffers in this parsing session
    size_t bufferSize;
    size_t sodbSize;
    size_t setSize;
    KLVElement checksumElement;
} KLVParser;

static int getLenFlag(uint8_t len)
{
	// retrieve length
	// get the number of bytes
	if ((int)len < 128)
		return 0;
	uint8_t size = len ^ 0x80;
	return size;
}

static int getKLVSetSize(const uint8_t* stream, int sz)
{
    // The use of memcpy here requires attention.
    // We are copying [sz] number of bytes (uint8_t) into the destination.
    // Therefore in the cases where sz < 3, 4, 5 it is valid to copy into an int (4 bytes in a 64 bit system which we assume(!) we have)
    // conversely when sz < 2 (aka sz == 0 or sz == 1) we copy at most 1 byte, which
    // indeed fits into an uint8_t.
    // TODO: Can this be done more safely ? The main worry is when the system running this is 32-bit.
	int ret = 0;
	if (sz < 2)
	{
		uint8_t len = 0;
		memcpy(&len, stream, sz);
		ret = len;
	}
	else if (sz < 3)
	{
		int len = 0;
		memcpy(&len, stream, sz);
		ret = ntohs(len);
	}
	else if (sz < 4)
	{
		int len = 0;
		memcpy(&len, stream, sz);
		ret = ntohl(len);
		ret = ret >> 5;
	}
	else if (sz < 5)
	{
		int len = 0;
		memcpy(&len, stream, sz);
		ret = ntohl(len);
	}

	return ret;
}

static int decodeBERLength(int* numBytesRead, const uint8_t* buffer, int size) {
    int i = 0;
    int len = 0;
    if (buffer[i] < 128) {
        *numBytesRead = 1;
        return buffer[i];
    }
    else {
        switch (buffer[i] ^ 0x80)
        {
        case 1:
            *numBytesRead = 2;
            return buffer[++i];
            break;
        case 2:
            *numBytesRead = 3;
            memcpy(&len, buffer + 1, 2);
            return ntohs(len);
            break;
        case 3:
            *numBytesRead = 4;
            memcpy(&len, buffer + 1, 3);
            len = ntohl(len);
            return len >> 5;
            break;
        case 4:
            *numBytesRead = 5;
            memcpy(&len, buffer + 1, 4);
            return ntohl(len);
            break;
        }
    }
    return 0;
}

static int decodeKey(int* numBytesRead, const uint8_t *buffer, int size) {
    int i = 0;
    int decKey = 0;
    if (buffer[i] < 128) {
        *numBytesRead = 1;
        return buffer[i];
    }
    else 
    {
        *numBytesRead = 2;
        uint8_t b1 = buffer[i++] & 0x7F;
        uint8_t b2 = buffer[i];

        if (b1 & 0x01)
            decKey = 128 + b2;
    }
    return decKey;
}


static int klvParse(KLVElement *klv, uint8_t *buf, size_t size) {
    return 0;
    int p = 0;
	int numOfBytesRead = 0;
	int key = decodeKey(&numOfBytesRead, buf, size);
	p = numOfBytesRead;

    switch (key) {
        case 1:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVChecksum;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 2:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = KLVUnixTimeStamp;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 3:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = KLVMissionID;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 4:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = KLVPlatformTailNumber;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 5:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVPlatformHeadingAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 6:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVPlatformPitchAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 7:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVPlatformRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 8:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVPlatformTrueAirspeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 9:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVPlatformTrueAirspeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 10:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = KLVPlatformDesignation;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 11:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = KLVImageSourceSensor;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 12:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = KLVImageCoordinateSystem;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 13:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorLatitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 14:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorLongitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 15:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVSensorTrueAltitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 16:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVSensorHorizontalFieldOfView;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 17:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVSensorVerticalFieldOfView;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 18:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeAzimuthAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 19:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeElevationAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 20:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 21:// TODO: From here to 42
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 22:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 23:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 24:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 25:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 26:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 27:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 28:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 29:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 30:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 31:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 32:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 33:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 34:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 35:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 36:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 37:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 38:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 39:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 40:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 41:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 42:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        default:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            *klv = KLVUnknown(key);
            klv->length = len;
            for(size_t i = 0; i < len; i++)
                klv->value[i] = buf[p++];
        }
    }
}


static int klvParseUniversalSetElement(KLVElement *klv, uint8_t *data, size_t size) {
    return 0;
}


static void onElement(KLVParser *parser, const KLVElement klv) {
    if(key(klv) == 1) {
        parser->checksumElement = klv;
    }
}

static void onBeginSet(KLVParser *parser, int len, TYPE type) {
    parser->setSize = len;
    parser->state = LEXING;
    for(size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
    parser->bufferSize = 0;
}

static void onEndSet(KLVParser *parser) {
    parser->state = START_SET_KEY;
    parser->setSize = 0;
    for (size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
    parser->bufferSize = 0;

    // TODO: Here is where we validate the checksum for that set if the parser->type is LOCAL_SET

    for(size_t i = 0; i < parser->sodbSize; i++) {
        parser->sodb[i] = 0;
    }
}

static void onBegin(KLVParser *parser, int len) {
    if(parser->type != UNKNOWN) {
        onBeginSet(parser, len, parser->type);
    }
}

static void onEndSetKey(KLVParser *parser) {
    parser->state = START_SET_LEN_FLAG;
    for(size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
}

static void onEndLenFlag(KLVParser *parser) {
    parser->state = START_SET_LEN;
    for(size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
}

static void onEndKey(KLVParser *parser, TYPE type) {
    parser->type = type;
    onEndSetKey(parser);
}

static void onError(KLVParser *parser) {
    parser->state = START_SET_KEY;
    parser->setSize = 0;
    for (size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
    parser->bufferSize = 0;

    for (size_t i = 0; i < parser->sodbSize; i++) {
        parser->sodb[i] = 0;
    }
    parser->sodbSize = 0;
}

static int parse(KLVParser* parser, const uint8_t* chunk, const int length) {
    for(size_t i = 0; i < length; i++) {
        uint8_t byte = chunk[i];

        if(parser->state == START_SET_KEY) {
            parser->buffer[parser->bufferSize++] = byte;
            
            if(parser->bufferSize == 16) {
                if(memcmp(parser->buffer, LocalSetKey, 16) == 0) {
                    memcpy(parser->sodb, parser->buffer, parser->bufferSize);
                    onEndKey(parser, LOCAL_SET);

                } else if (memcmp(parser->buffer, UniversalMetadataSetKey, 16) == 0) {
                    memcpy(parser->sodb, parser->buffer, parser->bufferSize);
                    onEndKey(parser, UNIVERSAL_SET);
                } else if (memcmp(parser->buffer, SecurityMetadataUniversalSetKey, 16) == 0) {
                    memcpy(parser->sodb, parser->buffer, parser->bufferSize);
                    onEndKey(parser, SECURITY_UNIVERSAL_SET);
                } else if (memcmp(parser->buffer, UniversalMetadataElementKey, 4) == 0) {
                    memcpy(parser->sodb, parser->buffer, parser->bufferSize);
                    onEndKey(parser, UNIVERSAL_ELEMENT);
                } else {
                    parser->type = UNKNOWN;
                    onError(parser);
                    return -1;
                }
            }
        }
        else if(parser->state == START_SET_LEN_FLAG) {
            onEndLenFlag(parser);
            parser->buffer[parser->bufferSize++] = byte;
        }
        else if(parser->state == START_SET_LEN) {
            const int lenFlag = getLenFlag(parser->buffer[0]);
            int setSize = 0;
            if(lenFlag == 0) {
                setSize = parser->buffer[0];
                parser->sodb[parser->sodbSize++] = parser->buffer[0];
                onBegin(parser, setSize);
            } else if(parser->bufferSize == lenFlag + 1) {
                uint8_t actualLengthFlag = lenFlag | 0x80;
                parser->sodb[parser->sodbSize++] = actualLengthFlag;
                // skip over the length flag
                memcpy(parser->sodb + parser->sodbSize, parser->buffer + 1, parser->bufferSize - 1);
                setSize = getKLVSetSize(parser->buffer + 1, lenFlag);
                onBegin(parser, setSize);
            } else {
                parser->buffer[parser->bufferSize++] = byte;
            }
        } 
        
        if(parser->state == LEXING) {
            parser->buffer[parser->bufferSize++] = byte;
            parser->sodb[parser->sodbSize++] = byte;
            if(parser->bufferSize == parser->setSize) {
                parser->state = PARSING;
            }
        } 

        if(parser->state == PARSING) {
            int n = 0;
            while(n <= parser->setSize) {
                KLVElement klv;
                if(parser->type == LOCAL_SET) {
                    n += klvParse(&klv, parser->buffer + n, parser->setSize);
                } else {
                    if(parser->type == UNIVERSAL_ELEMENT) {
                        n += klvParseUniversalSetElement(&klv, parser->sodb + n, parser->setSize);
                    } else {
                        n += klvParseUniversalSetElement(&klv, parser->buffer + n, parser->setSize);
                    }
                }

                onElement(parser, klv);
            }
            onEndSet(parser);
        }
        
        return 0;
    }
}


#endif // !KLV_IMPLEMENTATION