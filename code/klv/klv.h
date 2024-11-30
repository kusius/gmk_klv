/**
 * Version History:
 * 
 * 0.0.1: 
 * Initial implementation and port of klvp library in an implementation without other dependencies.
 * For ease of use in other programs or embedded in other languages.
 */

#ifndef KLV_H
#define KLV_H

#ifndef GMKKLV
#define GMKKLV static
#endif

#include <stdint.h>

struct gmk_KLVElement;
enum gmk_KLVValueType;
struct gmk_KLVParser;

GMKKLV struct gmk_KLVParser gmk_newKlvParser();
GMKKLV void gmk_klvParse(struct gmk_KLVParser* parser, const uint8_t* chunk, const int length, void (*onEndSetCallback)(struct gmk_KLVElement *, int));
GMKKLV uint8_t gmk_klvKey(const struct gmk_KLVElement klv);

#endif // !KLV_H


#if defined GMK_KLV_IMPLEMENTATION

// ntohs, ntohl
#if  defined(_WIN32) || defined(WIN32)
 #include <Winsock2.h>
 #pragma comment(lib, "Ws2_32.lib")
#else 
 #include <netinet/in.h>
#endif

#include <stdbool.h>
#include <math.h>
#include <string.h>
// In order to have fixed memory needs, we define the maximum number 
// of total bytes that we are able to be parsed by this library.
#define KILOBYTES(x) (x) * 1024
#define MEGABYTES(x) (KILOBYTES(x)) * 1024
#if !defined MAX_PARSE_BYTES
#define MAX_PARSE_BYTES KILOBYTES(1)
#endif
#define MAX_UAS_TAGS 143

const uint8_t gmk__LocalSetKey[] = { 
    0x06,0x0E,0x2B,0x34,
	0x02,0x0B,0x01,0x01,
	0x0E,0x01,0x03,0x01,
	0x01,0x00,0x00,0x00 
};

const uint8_t gmk__SecurityMetadataUniversalSetKey[] = {
    0x06,0x0E,0x2B,0x34,
    0x02,0x01,0x01,0x01,
    0x02,0x08,0x02,0x00,
    0x00,0x00,0x00,0x00
};

const uint8_t gmk__UniversalMetadataSetKey[] = {
    0x06,0x0E,0x2B,0x34,
    0x02,0x01,0x01,0x01,
    0x0E,0x01,0x01,0x02,
    0x01,0x01,0x00,0x00
};

const uint8_t gmk__UniversalMetadataElementKey[] = { 
    0x06, 0x0E, 0x2B, 0x34, 0x01 
};

typedef enum gmk__SET_TYPE {
    LOCAL_SET, 
    UNIVERSAL_SET,
    SECURITY_UNIVERSAL_SET,  
    UNIVERSAL_ELEMENT, 
    UNKNOWN 
} gmk__SET_TYPE;

typedef enum gmk__PARSER_STATE {
    START_SET_KEY,
    START_SET_LEN_FLAG,
    START_SET_LEN,
    LEXING,
    PARSING
} gmk__PARSER_STATE;

enum gmk_KLVValueType {
    GMK_KLV_VALUE_STRING,
    // in reality these are more strictly defined (uint_x, int_x)
    // but we are choosing simplicity here and encoding all numericals into integers
    GMK_KLV_VALUE_INT,
    GMK_KLV_VALUE_FLOAT,
    GMK_KLV_VALUE_DOUBLE,
    GMK_KLV_VALUE_UINT64,
    GMK_KLV_VALUE_UNKNOWN,
    GMK_KLV_VALUE_PARSE_ERROR,
};

typedef struct gmk_KLVElement {
    // maximum bytes a key can be is 16
    uint8_t key[16];
    int keyLength;
    int length;
    uint8_t value[256];
    enum gmk_KLVValueType valueType;
    union {
        int intValue;
        float floatValue; 
        double doubleValue;
        char *stringValue;
        uint64_t uint64Value;
    };
} gmk_KLVElement;

static uint8_t POSITIVE_INFINITY_HIGH_BYTE = 0xC8;
static uint8_t NEGATIVE_INFINITY_HIGH_BYTE = 0xE8;
static uint8_t POSITIVE_QUIET_NAN_HIGH_BYTE = 0xD0;
static uint8_t NEGATIVE_QUIET_NAN_HIGH_BYTE = 0xF0;
static uint8_t HIGH_BYTE_MASK = 0xF8;

typedef struct gmk__FPParser {
        double a;
		double b;
		double bPow;
		double dPow;
		int length;
		double sF;
		double sR;
		double zOffset;
} gmk__FPParser;

gmk__FPParser gmk__fpParserOf(double min, double max, int length) {
    gmk__FPParser fpParser = {0};
    fpParser.a = min;
    fpParser.b = max;
    fpParser.length = length;
    fpParser.zOffset = 0.0;
    fpParser.bPow = ceil(log2(fpParser.b - fpParser.a));
    fpParser.dPow = (double)(8 * (uint64_t)fpParser.length - 1);
    fpParser.sF = exp2(fpParser.dPow - fpParser.bPow);
    fpParser.sR = exp2(fpParser.bPow - fpParser.dPow);

    if (fpParser.a < 0 && fpParser.b > 0) {
        fpParser.zOffset = fpParser.sF * fpParser.a - floor(fpParser.sF * fpParser.a);
    }

    return fpParser;
}

double gmk__fpParserDecodeAsNormalMappedValue(gmk__FPParser *fpParser, const unsigned char* valueBuffer, int bufsiz) {
    	double val = 0.0;

		switch (fpParser->length)
		{
		case 1:
		{
			int b1 = (int)valueBuffer[0];
			val = fpParser->sR * (b1 - fpParser->zOffset) + fpParser->a;
		} break;
		case 2:
		{
			short nVal;
			memcpy(&nVal, valueBuffer, 2);
			nVal = ntohs(nVal);
			val = fpParser->sR * (nVal - fpParser->zOffset) + fpParser->a;
		} break;
		case 3:
		{
			int nVal = 0;
			memcpy(&nVal, valueBuffer, 3);
			nVal = ntohl(nVal);
			nVal = nVal >> 8;
			val = fpParser->sR * (nVal - fpParser->zOffset) + fpParser->a;
		} break;
		case 4:
		{
			int nVal = 0;
			memcpy(&nVal, valueBuffer, 4);
			nVal = ntohl(nVal);
			val = fpParser->sR * (nVal - fpParser->zOffset) + fpParser->a;
		} break;
		case 5:
		case 6:
		case 7:
		case 8:
		{
			long long nVal = 0;
			memcpy(&nVal, valueBuffer, 8);
			nVal = ntohll(nVal);
			int shift = (8 - fpParser->length) * 8;
			nVal = nVal >> shift;
			val = fpParser->sR * (nVal - fpParser->zOffset) + fpParser->a;
		}
		break;
		}
		return val;
}

double gmk__fpParserDecode(gmk__FPParser *fpParser, const unsigned char *buffer, int bufsiz) {
    	if (bufsiz > fpParser->length)
			return nan("");

		if ((buffer[0] & 0x80) == 0x00)
		{
			return gmk__fpParserDecodeAsNormalMappedValue(fpParser, buffer, bufsiz);
		}
		// Check if it is -1
		else if (buffer[0] == 0x80) {
			bool allZeros = true;
			for (int i = 1; i < bufsiz; i++) {
				if (buffer[i] != 0x00) {
					allZeros = false;
					break;
				}
			}
			if (allZeros) {
				return gmk__fpParserDecodeAsNormalMappedValue(fpParser, buffer, bufsiz);
			}
		}

		uint8_t highByteBits = buffer[0] & HIGH_BYTE_MASK;
		if (highByteBits == POSITIVE_INFINITY_HIGH_BYTE) {
			return INFINITY;
		}
		else if (highByteBits == NEGATIVE_INFINITY_HIGH_BYTE) {
			return INFINITY;
		}
		else {
			return nan("");
		}
}

GMKKLV uint8_t gmk_klvKey(const gmk_KLVElement klv) {
    return klv.keyLength == 0 ? 0 : klv.key[0];
}

// The UAS dataset klv elements we parse
const gmk_KLVElement GMK_KLVChecksum = {. key = {1}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVUnixTimeStamp =  {.key = {2}, .valueType = GMK_KLV_VALUE_UINT64};
const gmk_KLVElement GMK_KLVMissionID =  {.key = {3}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVPlatformTailNumber =  {.key = {4}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVPlatformHeadingAngle =  {.key = {5}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVPlatformPitchAngle =  {.key = {6}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVPlatformRollAngle =  {.key = {7}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVPlatformTrueAirspeed =  {.key = {8}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVPlatformIndicatedAirspeed =  {.key = {9}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVPlatformDesignation =  {.key = {10}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVImageSourceSensor =  {.key = {11}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVImageCoordinateSystem =  {.key = {12}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVSensorLatitude =  {.key = {13}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVSensorLongitude =  {.key = {14}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVSensorTrueAltitude =  {.key = {15}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVSensorHorizontalFieldOfView =  {.key = {16}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVSensorVerticalFieldOfView =  {.key = {17}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVSensorRelativeAzimuthAngle =  {.key = {18}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVSensorRelativeElevationAngle =  {.key = {19}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVSensorRelativeRollAngle =  {.key = {20}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVSlantRange =  {.key = {21}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVTargetWidth =  {.key = {22}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVFrameCenterLatitude =  {.key = {23}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVFrameCenterLongitude =  {.key = {24}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVFrameCenterElevation =  {.key = {25}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOffsetCornerLatitudePoint1 =  {.key = {26}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOffsetCornerLongitudePoint1 =  {.key = {27}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOffsetCornerLatitudePoint2 =  {.key = {28}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOffsetCornerLongitudePoint2 =  {.key = {29}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOffsetCornerLatitudePoint3 =  {.key = {30}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOffsetCornerLongitudePoint3 =  {.key = {31}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOffsetCornerLatitudePoint4 =  {.key = {32}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOffsetCornerLongitudePoint4 =  {.key = {33}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVIcingDetected =  {.key = {34}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVwindDirection =  {.key = {35}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVWindSpeed =  {.key = {36}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVStaticPressure =  {.key = {37}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVDensityAltitude =  {.key = {38}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOutsideAirTemperature =  {.key = {39}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVTargetLocationLatitude =  {.key = {40}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVTargetLocationLongitude =  {.key = {41}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVTargetLocationeElevation =  {.key = {42}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVTargetTrackGateWidth =  {.key = {43}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVTargetTrackGateHeight =  {.key = {44}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVTargetErrorEstimateC90 =  {.key = {45}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVTargetErrorEstimateLE90 =  {.key = {46}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVGenericFlagData =  {.key = {47}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVSecurityLocalSet =  {.key = {48}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVDifferentialPressure =  {.key = {49}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVPlatformAngleOfAttack =  {.key = {50}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVPlatformVerticalSpeed =  {.key = {51}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVPlatformSideslipAngle =  {.key = {52}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVAirfieldBarometricPressure =  {.key = {53}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVAirfieldElevation =  {.key = {54}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVRelavitveHumidity =  {.key = {55}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVPlatformGroundSpeed =  {.key = {56}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVGroundRange =  {.key = {57}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVPlatformFuelRemaining =  {.key = {58}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVPlatformCallsign =  {.key = {59}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVWeaponLoad =  {.key = {60}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVWeaponFired =  {.key = {61}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVLaserPRFCode =  {.key = {62}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVSensorFieldOfViewName =  {.key = {63}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVPlatfofmMagneticHeading =  {.key = {64}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVUASDatalinkLSVersionNumber =  {.key = {65}, .valueType = GMK_KLV_VALUE_INT};
// item 66 is deprecated
const gmk_KLVElement GMK_KLVAlternatePlatformLatitude =  {.key = {67}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVAlternatePlatformLongitude =  {.key = {68}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVAlternatePlatformAltitude =  {.key = {69}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVAlternatePlatformName =  {.key = {70}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVAlternatePlatformHeading =  {.key = {71}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVEventStartTimeUTC =  {.key = {72}, .valueType = GMK_KLV_VALUE_UINT64};
const gmk_KLVElement GMK_KLVRVTLocalDataSet =  {.key = {73}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVVMTILocalDataSet =  {.key = {74}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVSensorEllipsoidHeight =  {.key ={75}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVAlternatePlatformEllipsoidHeight =  {.key ={76}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOperationalMode =  {.key ={77}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVFrameCenterHeightAboveEllipsoid =  {.key ={78}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVSensorNorthVelocity =  {.key ={79}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVSensorEastVelocity =  {.key ={80}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVImageHorizonPixelPack =  {.key ={81}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVCornerLatitudePoint1Full =  {.key ={82}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVCornerLongitudePoint1Full =  {.key ={83}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVCornerLatitudePoint2Full =  {.key ={84}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVCornerLongitudePoint2Full =  {.key ={85}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVCornerLatitudePoint3Full =  {.key ={86}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVCornerLongitudePoint3Full =  {.key ={87}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVCornerLatitudePoint4Full =  {.key ={88}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVCornerLongitudePoint4Full =  {.key ={89}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVPlatformPitchAngleFull =  {.key ={90}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVPlatformRollAngleFull =  {.key ={91}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVPlatformAngleOfAttackFull =  {.key ={92}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVPlatformSideSlipAngleFull =  {.key ={93}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVMIISCoreIdentifier =  {.key ={94}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVSARMotionImageryMetadata =  {.key ={95}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVTargetWidthExtended =  {.key ={96}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVRangeImageLocalSet =  {.key ={97}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVGeoRegistrationLocalSet =  {.key ={98}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVCompositeImagingLocalSet =  {.key ={99}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVSegmentLocalSet =  {.key ={100}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVAmendLocalSet =  {.key ={101}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVKLVSDCCFLP =  {.key ={102}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVDensityAltitudeExtended =  {.key ={103}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVDensityEllipsoidHeightExtended =  {.key ={104}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVAlternatePlatformEllipsoidHeightExtended =  {.key ={105}, .valueType = GMK_KLV_VALUE_DOUBLE};
const gmk_KLVElement GMK_KLVStreamDesignator =  {.key ={106}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVOperationalBase =  {.key ={107}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVBroadcastSource =  {.key ={108}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVRangeToRecoveryLocation =  {.key ={109}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVTimeAirborne =  {.key ={110}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVPropulsionUnitSpeed =  {.key ={111}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVPlatformCourseAngle =  {.key ={112}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVAltitudeAGL =  {.key ={113}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVRadarAltimeter =  {.key ={114}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVControlCommand =  {.key ={115}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVControlCommandVerificationList =  {.key ={116}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVSensorAzimuthRate =  {.key ={117}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVSensorElevationRate =  {.key ={118}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVSensorRollRate =  {.key ={119}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOnboardMISStoragePercentFull =  {.key ={120}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVActiveWaveLength =  {.key ={121}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVKLVCountryCodes =  {.key ={122}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVNumberofNAVSATsInView =  {.key ={123}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVPositioningMethodSource =  {.key ={124}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVPlatformStatus =  {.key ={125}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVSensorControlMode =  {.key ={126}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVSensorFrameRatePack =  {.key ={127}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVWaveLenghtsList =  {.key ={128}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVTargetID =  {.key ={129}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVAirbaseLocations =  {.key ={130}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVTakeoffTime =  {.key ={131}, .valueType = GMK_KLV_VALUE_UINT64};
const gmk_KLVElement GMK_KLVTransmissionFrequency =  {.key ={132}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVOnboardMISStorageCapacity =  {.key ={133}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVZoomPercentage =  {.key ={134}, .valueType = GMK_KLV_VALUE_FLOAT};
const gmk_KLVElement GMK_KLVCommunicationsMethod =  {.key ={135}, .valueType = GMK_KLV_VALUE_STRING};
const gmk_KLVElement GMK_KLVLeapSeconds =  {.key ={136}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVCorrectionOffset =  {.key ={137}, .valueType = GMK_KLV_VALUE_INT};
const gmk_KLVElement GMK_KLVPayloadList =  {.key ={138}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVActivePayloads =  {.key ={139}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVWeaponStores =  {.key ={140}, .valueType = GMK_KLV_VALUE_UNKNOWN};
const gmk_KLVElement GMK_KLVWaypointList =  {.key ={141}, .valueType = GMK_KLV_VALUE_UNKNOWN};


// Other parsing results 
#define GMK_KLVParseError(key) (gmk_KLVElement) {.key = {(key)}, .valueType = GMK_KLV_VALUE_UNKNOWN};
#define GMK_KLVUnknown(key) (gmk_KLVElement) {.key = {(key)}, .valueType = GMK_KLV_VALUE_PARSE_ERROR};

typedef struct gmk_KLVParser {
    gmk__PARSER_STATE state;
    gmk__SET_TYPE type;
    uint8_t buffer[MAX_PARSE_BYTES];
    uint8_t sodb[MAX_PARSE_BYTES];
    // indices of buffers in this parsing session
    size_t bufferSize;
    size_t sodbSize;
    size_t setSize;
    size_t uasDataSetSize;
    gmk_KLVElement checksumElement;
    // The checksum element is saved as 
    gmk_KLVElement uasDataSet[MAX_UAS_TAGS];
} gmk_KLVParser;

// Creates a properly initialized empty KLV parser
GMKKLV gmk_KLVParser gmk_newKlvParser() {
    gmk_KLVParser parser = {0};
    parser.state = START_SET_KEY;
    for(int i = 0; i < MAX_UAS_TAGS; i++) {
        parser.uasDataSet[i] = (gmk_KLVElement) {0} ;
    }

    parser.uasDataSetSize = 0;

    return parser;
}

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

static int klvParse(gmk_KLVElement *klv, uint8_t *buf, size_t size) {
    int p = 0;
	int numOfBytesRead = 0;
	int key = decodeKey(&numOfBytesRead, buf, size);
	p = numOfBytesRead;

    switch (key) {
        case 1:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVChecksum;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->intValue = (int)nVal;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 2:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = GMK_KLVUnixTimeStamp;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int64_t lVal;
                memcpy(&lVal, klv->value, 8);
                klv->uint64Value = ntohll(lVal);
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 3:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = GMK_KLVMissionID;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                    klv->stringValue = (char *)klv->value;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 4:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = GMK_KLVPlatformTailNumber;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->stringValue = (char *)klv->value;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 5:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVPlatformHeadingAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 360.0 / 0xFFFF * LDS;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 6:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVPlatformPitchAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = 40.0 / 0xFFFE * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 7:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVPlatformRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = 100.0 / 0xFFFE * LDS;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 8:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVPlatformTrueAirspeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 9:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVPlatformIndicatedAirspeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 10:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = GMK_KLVPlatformDesignation;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->stringValue = (char *)klv->value;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 11:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = GMK_KLVImageSourceSensor;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->stringValue = (char *)klv->value;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 12:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = GMK_KLVImageCoordinateSystem;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->stringValue = (char *)klv->value;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 13:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSensorLatitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        int LDS = ntohl(nVal);
		        double UDS = 180.0 / 0xFFFFFFFE * LDS;
		        klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 14:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSensorLongitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        int LDS = ntohl(nVal);
		        double UDS = 360.0 / 0xFFFFFFFE * LDS;
		        klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 15:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVSensorTrueAltitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 16:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVSensorHorizontalFieldOfView;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 180.0 / 0xFFFF * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 17:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVSensorVerticalFieldOfView;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 180.0 / 0xFFFF * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 18:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSensorRelativeAzimuthAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint32_t nVal;
                memcpy(&nVal, klv->value, 4);
                uint32_t LDS = (uint32_t)ntohl(nVal);
                klv->doubleValue = 360.0 / 0xFFFFFFFF * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 19:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSensorRelativeElevationAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                uint32_t nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                klv->doubleValue = 360.0 / 0xFFFFFFFF * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        case 20:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSensorRelativeRollAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint32_t nVal; 
                memcpy(&nVal, klv->value, 4);
                uint32_t LDS = (uint32_t)ntohl(nVal);
                klv->doubleValue = 360.0 / 0xFFFFFFFF * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 21:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSlantRange;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint32_t nVal;
                memcpy(&nVal, klv->value, 4);
                uint32_t LDS = ntohl(nVal);
                klv->doubleValue = 5000000.0 / 0xFFFFFFFF * LDS;
                
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 22:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVTargetWidth;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else if (len == 4) { // it should be 2
                *klv = GMK_KLVTargetWidth;
                p++;
                p++;
                for (size_t i = 0; i < 2; i++)
				        klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }

            uint16_t nVal;
            memcpy(&nVal, klv->value, 2);
            uint16_t LDS = ntohs(nVal);
            klv->floatValue = 10000.0 / 0xFFFF * LDS;

        } break; 
		case 23:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVFrameCenterLatitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;
            
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 24:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVFrameCenterLongitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 25:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVFrameCenterElevation;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;


            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 26:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVOffsetCornerLatitudePoint1;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);
                
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 27:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVOffsetCornerLongitudePoint1;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 28:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVOffsetCornerLatitudePoint2;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                
                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 29:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVOffsetCornerLongitudePoint2;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 30:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVOffsetCornerLatitudePoint3;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 31:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv =GMK_KLVOffsetCornerLongitudePoint3;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                    

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 32:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVOffsetCornerLatitudePoint4;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];


                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 33:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVOffsetCornerLongitudePoint4;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 34:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVIcingDetected;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 35:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVwindDirection;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 360.0 / 0xFFFF * LDS; 


            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 36:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVWindSpeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t LDS = (uint16_t)*klv->value;
		         klv->floatValue = (100.0 / 0xFF) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 37:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVStaticPressure;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
		        memcpy(&LDS, klv->value, 2);
		        LDS = ntohs(LDS);
		        klv->floatValue = (5000.0 / 65535.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 38:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVDensityAltitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                unsigned short LDS = 0;
		        memcpy(&LDS, klv->value, 2);
		        LDS = ntohs(LDS);
		        klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 39:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVOutsideAirTemperature;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 40:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVTargetLocationLatitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        int LDS = ntohl(nVal);
		        double UDS = 180.0 / 0xFFFFFFFE * LDS;
		        klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
		case 41:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVTargetLocationLongitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                int nVal;
		        memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
  
		case 42:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVTargetLocationeElevation;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 43:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVTargetTrackGateWidth;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->floatValue = 2.0 * *klv->value;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

		case 44:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVTargetTrackGateHeight;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->floatValue = 2.0 * *klv->value;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 45:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVTargetErrorEstimateC90;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t LDS = 0;
		        memcpy(&LDS, klv->value, 2);
		        klv->floatValue = (4095.0 / 65535.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 46:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = GMK_KLVTargetErrorEstimateLE90;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t LDS = 0;
		        memcpy(&LDS, klv->value, 2);
		        klv->floatValue = (4095.0 / 65535.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 
        

		case 47:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVGenericFlagData;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 48: 
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVSecurityLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

		case 49:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVDifferentialPressure;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (5000.0 / 65535.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 50:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVPlatformAngleOfAttack;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (40.0 / 65534.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

		case 51:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVPlatformVerticalSpeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (360.0 / 65534.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 52:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVPlatformSideslipAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (40.0 / 65534.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 53:
        {
            int len = buf[p++]; 
            if(len < 2) {
                *klv = GMK_KLVAirfieldBarometricPressure;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (5000.0 / 65535.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 54:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVAirfieldBarometricPressure;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 55:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = GMK_KLVRelavitveHumidity;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t LDS = (uint16_t)*klv->value;
                klv->floatValue = (100 / 0xFF) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

		case 56:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = GMK_KLVPlatformGroundSpeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 57:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVGroundRange;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint32_t nVal;
                memcpy(&nVal, klv->value, 4);
                uint32_t LDS = ntohl(nVal);
                klv->doubleValue = 5000000.0 / 0xFFFFFFFF * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 58:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVPlatformFuelRemaining;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (10000.0 / 65535.0) * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 59:
        {
            int len = buf[p++]; 
            if(len <= 127) {
                *klv = GMK_KLVPlatformCallsign;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->stringValue = (char *)klv->value;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


		case 60:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVWeaponLoad;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                klv->intValue = (int) ntohs(nVal);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 61:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = GMK_KLVWeaponFired;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;                              

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 62:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVLaserPRFCode;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                klv->intValue = (int)ntohs(nVal);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 63:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = GMK_KLVSensorFieldOfViewName;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;                              

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 64:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVPlatfofmMagneticHeading;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 360.0 / 0xFFFF * LDS;                          

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 65:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = GMK_KLVUASDatalinkLSVersionNumber;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;                              

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 66:
        {
            int len = buf[p++]; 

            //deprecated
            if(len <= 0) {
                *klv = GMK_KLVWeaponFired;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 67:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVAlternatePlatformLatitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;                           

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 68:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVAlternatePlatformLongitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;                           

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


		case 69:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVAlternatePlatformAltitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;                 

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 70:
        {
            int len = buf[p++]; 
            if(len <= 127) {
                *klv = GMK_KLVAlternatePlatformName;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->stringValue = (char *)klv->value;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


		case 71:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVAlternatePlatformHeading;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                unsigned short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (360.0 / 65535.0) * LDS;                        

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 72:
        {
            int len = buf[p++]; 
            if(len <= 8) {
                *klv = GMK_KLVEventStartTimeUTC;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int64_t lVal;
                memcpy(&lVal, klv->value, 8);
                klv->uint64Value = ntohll(lVal);                       

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

		case 73:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size); 
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVEventStartTimeUTC;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 74:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size); 
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVEventStartTimeUTC;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


		case 75:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVSensorEllipsoidHeight;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;                     

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 76:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVAlternatePlatformEllipsoidHeight;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;    

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 77:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = GMK_KLVOperationalMode;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;   

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 78:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv =GMK_KLVFrameCenterHeightAboveEllipsoid;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;  

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 79:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv =  GMK_KLVSensorNorthVelocity;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = 654.0 / 65534.0 * LDS; 

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 80:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = GMK_KLVSensorEastVelocity;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = 654.0 / 65534.0 * LDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 81:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size); 
            p += numOfBytesRead;
            if(len <= size) {
                *klv = GMK_KLVImageHorizonPixelPack;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 82:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVCornerLatitudePoint1Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 


        case 83:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVCornerLongitudePoint1Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 84:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVCornerLatitudePoint2Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 85:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVCornerLongitudePoint2Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break; 

        case 86:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVCornerLatitudePoint3Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 87:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVCornerLongitudePoint3Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 88:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVCornerLatitudePoint4Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 89:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVCornerLongitudePoint4Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 90:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVPlatformPitchAngleFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 91:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVPlatformRollAngleFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 92:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVPlatformAngleOfAttackFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 93:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = GMK_KLVPlatformSideSlipAngleFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 94:
        {
            int len = buf[p++]; 
            if(len <= 50) {
                *klv = GMK_KLVMIISCoreIdentifier;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 95:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv =  GMK_KLVSARMotionImageryMetadata;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 96:
        {
            int len = buf[p++]; 
            if(len <= 8) {
                *klv = GMK_KLVTargetWidthExtended;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(0.0, 1500000.0, klv->length);
                klv->floatValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 97:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVRangeImageLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 98:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVGeoRegistrationLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 99:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVCompositeImagingLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

         case 100:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVSegmentLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;   

        case 101:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVAmendLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 102:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVKLVSDCCFLP;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 103:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = GMK_KLVDensityAltitudeExtended;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 104:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = GMK_KLVDensityEllipsoidHeightExtended;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 105:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = GMK_KLVAlternatePlatformEllipsoidHeightExtended;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;

        case 106:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = GMK_KLVStreamDesignator;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


        case 107:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = GMK_KLVOperationalBase;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


        case 108:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVBroadcastSource;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


        case 109:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVRangeToRecoveryLocation;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(0.0, 21000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


        case 110:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVBroadcastSource;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                unsigned int val;
                memcpy(&val, klv->value, 4);
                val = ntohl(val);
                klv->intValue = val;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


        case 111:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVPropulsionUnitSpeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                unsigned int val;
                memcpy(&val, klv->value, 4);
                val = ntohl(val);
                klv->intValue = val;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;


        case 112:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = GMK_KLVPlatformCourseAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(0.0, 360.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        
        case 113:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVAltitudeAGL;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];


                gmk__FPParser fpp = gmk__fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        
        case 114:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVRadarAltimeter;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                // FPParser                
                gmk__FPParser fpp = gmk__fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 115:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVControlCommand;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];              

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 116:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVControlCommandVerificationList;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];                

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 117:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSensorAzimuthRate;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(-1000.0, 1000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 118:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSensorElevationRate;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(-900, 40000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 119:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVSensorRollRate;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 120:
        {
            int len = buf[p++];
            if(len <= 3) {
                *klv = GMK_KLVOnboardMISStoragePercentFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(0.0, 100.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 121:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVActiveWaveLength;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];             

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 122:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVKLVCountryCodes;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];             

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
        case 123:
        {
            int len = buf[p++];
            if(len <= 3) {
                *klv = GMK_KLVNumberofNAVSATsInView;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;          

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        } break;
       case 124:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVPositioningMethodSource;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;              

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
       case 125:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVPlatformStatus;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;              

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
       case 126:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = GMK_KLVSensorControlMode;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;              

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 127:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len <= 16) {
                *klv = GMK_KLVSensorFrameRatePack;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 128:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVWaveLenghtsList;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 129:
        {
    	    int len = buf[p++];
            if(len <= 32) {
                *klv = GMK_KLVTargetID;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                // string
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 130:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len <= 24) {
                *klv = GMK_KLVAirbaseLocations;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 131:
        {
    	    int len = buf[p++];
            if(len <= 8) {
                *klv = GMK_KLVTakeoffTime;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int64_t lVal;
                memcpy(&lVal, klv->value, 8);
                int64_t time = ntohll(lVal);
                klv->uint64Value = time / 1000000;
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 132:
        {
    	    int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVTransmissionFrequency;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(1.0, 99999.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 133:
        {
    	    int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVOnboardMISStorageCapacity;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        klv->intValue = ntohl(nVal);
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 134:
        {
    	    int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVZoomPercentage;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                gmk__FPParser fpp = gmk__fpParserOf(0.0, 100.0, klv->length);
                klv->doubleValue = gmk__fpParserDecode(&fpp, klv->value, klv->length);

  
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 135:
        {
    	    int len = buf[p++];
            if(len <= 127) {
                *klv = GMK_KLVCommunicationsMethod;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                //string
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 136:
        {
    	    int len = buf[p++];
            if(len <= 4) {
                *klv = GMK_KLVLeapSeconds;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        klv->intValue = ntohl(nVal);
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 137:
        {
    	    int len = buf[p++];
            if(len <= 8) {
                *klv = GMK_KLVCorrectionOffset;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int64_t lVal;
                memcpy(&lVal, klv->value, 8);
                int64_t time = ntohll(lVal);
                klv->uint64Value = time / 1000000;

            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 138:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVPayloadList;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 139:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVActivePayloads;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 140:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVWeaponStores;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        case 141:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = GMK_KLVWaypointList;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                
            } else {
                *klv = GMK_KLVParseError(key);
                p += len;
            }
        }
        default:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            *klv = GMK_KLVUnknown(key);
            klv->length = len;
            for(size_t i = 0; i < len; i++)
                klv->value[i] = buf[p++];
        }
    }
    klv->keyLength = 1;
    return p;
}


static int klvParseUniversalSetElement(gmk_KLVElement *klv, uint8_t *data, size_t size) {
    return 0;
}


static void onElement(gmk_KLVParser *parser, const gmk_KLVElement klv) {
    uint8_t klvKey = gmk_klvKey(klv);
    if(klvKey== 1) {
        parser->checksumElement = klv;
    } else if(parser->uasDataSetSize < MAX_UAS_TAGS) {
        parser->uasDataSet[parser->uasDataSetSize] = klv;
        parser->uasDataSetSize++;
    }
}

static void onBeginSet(gmk_KLVParser *parser, int len, gmk__SET_TYPE type) {
    parser->setSize = len;
    parser->state = LEXING;
    for(size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
    parser->bufferSize = 0;
}

static void onEndSet(gmk_KLVParser *parser) {
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
    parser->sodbSize = 0;

    for(size_t i = 0; i < parser->uasDataSetSize; i++) {
        parser->uasDataSet[i] = (gmk_KLVElement) {0};
    }
    parser->uasDataSetSize = 0;
}

static void onBegin(gmk_KLVParser *parser, int len) {
    if(parser->type != UNKNOWN) {
        onBeginSet(parser, len, parser->type);
    }
}

static void onEndSetKey(gmk_KLVParser *parser) {
    parser->state = START_SET_LEN_FLAG;
    for(size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
    parser->bufferSize = 0;
}

static void onEndLenFlag(gmk_KLVParser *parser) {
    parser->state = START_SET_LEN;
    for(size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
    parser->bufferSize = 0;
}

static void onEndKey(gmk_KLVParser *parser, gmk__SET_TYPE type) {
    parser->type = type;
    onEndSetKey(parser);
}

static void onError(gmk_KLVParser *parser) {
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

GMKKLV void gmk_klvParse(gmk_KLVParser* parser, const uint8_t* chunk, const int length, void (*onEndSetCallback)(gmk_KLVElement *, int)) {
    
    for(size_t i = 0; i < length; i++) {
        uint8_t byte = chunk[i];

        if(parser->state == START_SET_KEY) {
            parser->buffer[parser->bufferSize++] = byte;
            
            if(parser->bufferSize == 16) {
                if(memcmp(parser->buffer, gmk__LocalSetKey, 16) == 0) {
                    memcpy(parser->sodb, parser->buffer, parser->bufferSize);
                    onEndKey(parser, LOCAL_SET);

                } else if (memcmp(parser->buffer, gmk__UniversalMetadataSetKey, 16) == 0) {
                    memcpy(parser->sodb, parser->buffer, parser->bufferSize);
                    onEndKey(parser, UNIVERSAL_SET);
                } else if (memcmp(parser->buffer, gmk__SecurityMetadataUniversalSetKey, 16) == 0) {
                    memcpy(parser->sodb, parser->buffer, parser->bufferSize);
                    onEndKey(parser, SECURITY_UNIVERSAL_SET);
                } else if (memcmp(parser->buffer, gmk__UniversalMetadataElementKey, 4) == 0) {
                    memcpy(parser->sodb, parser->buffer, parser->bufferSize);
                    onEndKey(parser, UNIVERSAL_ELEMENT);
                } else {
                    parser->type = UNKNOWN;
                    onError(parser);
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
            while(n < parser->setSize) {
                gmk_KLVElement klv;
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
            onEndSetCallback(parser->uasDataSet, parser->uasDataSetSize);
            onEndSet(parser);
        }
    }
}


#endif // !KLV_IMPLEMENTATION