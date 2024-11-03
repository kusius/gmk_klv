/**
 * Version History:
 * 
 * 0.0.1: 
 * Initial implementation and port of klvp library in an implementation without other dependencies.
 * For ease of use in other programs or embedded in other languages.
 */

#if !defined KLV_H
#define KLV_H

// ntohs, ntohl
#if  defined(_WIN32) || defined(WIN32)
 #include <Winsock2.h>
#else 
 #include <netinet/in.h>
#endif

#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <string.h>

#define MAX_UAS_TAGS 143
struct KLVElement;
enum KLVValueType;
struct KLVParser;

void parse(struct KLVParser* parser, const uint8_t* chunk, const int length, void (*onEndSetCallback)(struct KLVElement *, int));
uint8_t key(const struct KLVElement klv);

#endif // !KLV_H


#if defined KLV_IMPLEMENTATION

// In order to have fixed memory needs, we define the maximum number 
// of total bytes that we are able to be parsed by this library.
#define KILOBYTES(x) (x) * 1024
#define MEGABYTES(x) (KILOBYTES(x)) * 1024
#if !defined MAX_PARSE_BYTES
#define MAX_PARSE_BYTES KILOBYTES(1)
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

enum KLVValueType {
    KLV_VALUE_STRING,
    // in reality these are more strictly defined (uint_x, int_x)
    // but we are choosing simplicity here and encoding all numericals into integers
    KLV_VALUE_INT,
    KLV_VALUE_FLOAT,
    KLV_VALUE_DOUBLE,
    KLV_VALUE_UINT64,
    KLV_VALUE_UNKNOWN,
    KLV_VALUE_PARSE_ERROR,
};

typedef struct KLVElement {
    // maximum bytes a key can be is 16
    uint8_t key[16];
    int keyLength;
    int length;
    uint8_t value[256];
    enum KLVValueType valueType;
    union {
        int intValue;
        float floatValue; 
        double doubleValue;
        char *stringValue;
        uint64_t uint64Value;
    };
} KLVElement;

static uint8_t POSITIVE_INFINITY_HIGH_BYTE = 0xC8;
static uint8_t NEGATIVE_INFINITY_HIGH_BYTE = 0xE8;
static uint8_t POSITIVE_QUIET_NAN_HIGH_BYTE = 0xD0;
static uint8_t NEGATIVE_QUIET_NAN_HIGH_BYTE = 0xF0;
static uint8_t HIGH_BYTE_MASK = 0xF8;

typedef struct FPParser {
        double a;
		double b;
		double bPow;
		double dPow;
		int length;
		double sF;
		double sR;
		double zOffset;
} FPParser;

FPParser fpParserOf(double min, double max, int length) {
    FPParser fpParser = {};
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

double fpParserDecodeAsNormalMappedValue(FPParser *fpParser, const unsigned char* valueBuffer, int bufsiz) {
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

double fpParserDecode(FPParser *fpParser, const unsigned char *buffer, int bufsiz) {
    	if (bufsiz > fpParser->length)
			return nan("");

		if ((buffer[0] & 0x80) == 0x00)
		{
			return fpParserDecodeAsNormalMappedValue(fpParser, buffer, bufsiz);
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
				return fpParserDecodeAsNormalMappedValue(fpParser, buffer, bufsiz);
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

uint8_t key(const KLVElement klv) {
    return klv.keyLength == 0 ? 0 : klv.key[0];
}

// The UAS dataset klv elements we parse
#define KLVChecksum (KLVElement) {.key = {1}, .valueType = KLV_VALUE_INT};
#define KLVUnixTimeStamp (KLVElement) {.key = {2}, .valueType = KLV_VALUE_UINT64};
#define KLVMissionID (KLVElement) {.key = {3}, .valueType = KLV_VALUE_STRING};
#define KLVPlatformTailNumber (KLVElement) {.key = {4}, .valueType = KLV_VALUE_STRING};
#define KLVPlatformHeadingAngle (KLVElement) {.key = {5}, .valueType = KLV_VALUE_FLOAT};
#define KLVPlatformPitchAngle (KLVElement) {.key = {6}, .valueType = KLV_VALUE_FLOAT};
#define KLVPlatformRollAngle (KLVElement) {.key = {7}, .valueType = KLV_VALUE_FLOAT};
#define KLVPlatformTrueAirspeed (KLVElement) {.key = {8}, .valueType = KLV_VALUE_INT};
#define KLVPlatformIndicatedAirspeed (KLVElement) {.key = {9}, .valueType = KLV_VALUE_INT};
#define KLVPlatformDesignation (KLVElement) {.key = {10}, .valueType = KLV_VALUE_STRING};
#define KLVImageSourceSensor (KLVElement) {.key = {11}, .valueType = KLV_VALUE_STRING};
#define KLVImageCoordinateSystem (KLVElement) {.key = {12}, .valueType = KLV_VALUE_STRING};
#define KLVSensorLatitude (KLVElement) {.key = {13}, .valueType = KLV_VALUE_DOUBLE};
#define KLVSensorLongitude (KLVElement) {.key = {14}, .valueType = KLV_VALUE_DOUBLE};
#define KLVSensorTrueAltitude (KLVElement) {.key = {15}, .valueType = KLV_VALUE_FLOAT};
#define KLVSensorHorizontalFieldOfView (KLVElement) {.key = {16}, .valueType = KLV_VALUE_FLOAT};
#define KLVSensorVerticalFieldOfView (KLVElement) {.key = {17}, .valueType = KLV_VALUE_FLOAT};
#define KLVSensorRelativeAzimuthAngle (KLVElement) {.key = {18}, .valueType = KLV_VALUE_DOUBLE};
#define KLVSensorRelativeElevationAngle (KLVElement) {.key = {19}, .valueType = KLV_VALUE_DOUBLE};
#define KLVSensorRelativeRollAngle (KLVElement) {.key = {20}, .valueType = KLV_VALUE_DOUBLE};
#define KLVSlantRange (KLVElement) {.key = {21}, .valueType = KLV_VALUE_DOUBLE};
#define KLVTargetWidth (KLVElement) {.key = {22}, .valueType = KLV_VALUE_FLOAT};
#define KLVFrameCenterLatitude (KLVElement) {.key = {23}, .valueType = KLV_VALUE_DOUBLE};
#define KLVFrameCenterLongitude (KLVElement) {.key = {24}, .valueType = KLV_VALUE_DOUBLE};
#define KLVFrameCenterElevation (KLVElement) {.key = {25}, .valueType = KLV_VALUE_FLOAT};
#define KLVOffsetCornerLatitudePoint1 (KLVElement) {.key = {26}, .valueType = KLV_VALUE_FLOAT};
#define KLVOffsetCornerLongitudePoint1 (KLVElement) {.key = {27}, .valueType = KLV_VALUE_FLOAT};
#define KLVOffsetCornerLatitudePoint2 (KLVElement) {.key = {28}, .valueType = KLV_VALUE_FLOAT};
#define KLVOffsetCornerLongitudePoint2 (KLVElement) {.key = {29}, .valueType = KLV_VALUE_FLOAT};
#define KLVOffsetCornerLatitudePoint3 (KLVElement) {.key = {30}, .valueType = KLV_VALUE_FLOAT};
#define KLVOffsetCornerLongitudePoint3 (KLVElement) {.key = {31}, .valueType = KLV_VALUE_FLOAT};
#define KLVOffsetCornerLatitudePoint4 (KLVElement) {.key = {32}, .valueType = KLV_VALUE_FLOAT};
#define KLVOffsetCornerLongitudePoint4 (KLVElement) {.key = {33}, .valueType = KLV_VALUE_FLOAT};
#define KLVIcingDetected (KLVElement) {.key = {34}, .valueType = KLV_VALUE_INT};
#define KLVwindDirection (KLVElement) {.key = {35}, .valueType = KLV_VALUE_FLOAT};
#define KLVWindSpeed (KLVElement) {.key = {36}, .valueType = KLV_VALUE_FLOAT};
#define KLVStaticPressure (KLVElement) {.key = {37}, .valueType = KLV_VALUE_FLOAT};
#define KLVDensityAltitude (KLVElement) {.key = {38}, .valueType = KLV_VALUE_FLOAT};
#define KLVOutsideAirTemperature (KLVElement) {.key = {39}, .valueType = KLV_VALUE_INT};
#define KLVTargetLocationLatitude (KLVElement) {.key = {40}, .valueType = KLV_VALUE_DOUBLE};
#define KLVTargetLocationLongitude (KLVElement) {.key = {41}, .valueType = KLV_VALUE_DOUBLE};
#define KLVTargetLocationeElevation (KLVElement) {.key = {42}, .valueType = KLV_VALUE_FLOAT};
#define KLVTargetTrackGateWidth (KLVElement) {.key = {43}, .valueType = KLV_VALUE_INT};
#define KLVTargetTrackGateHeight (KLVElement) {.key = {44}, .valueType = KLV_VALUE_INT};
#define KLVTargetErrorEstimateC90 (KLVElement) {.key = {45}, .valueType = KLV_VALUE_FLOAT};
#define KLVTargetErrorEstimateLE90 (KLVElement) {.key = {46}, .valueType = KLV_VALUE_FLOAT};
#define KLVGenericFlagData (KLVElement) {.key = {47}, .valueType = KLV_VALUE_INT};
#define KLVSecurityLocalSet (KLVElement) {.key = {48}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVDifferentialPressure (KLVElement) {.key = {49}, .valueType = KLV_VALUE_FLOAT};
#define KLVPlatformAngleOfAttack (KLVElement) {.key = {50}, .valueType = KLV_VALUE_FLOAT};
#define KLVPlatformVerticalSpeed (KLVElement) {.key = {51}, .valueType = KLV_VALUE_FLOAT};
#define KLVPlatformSideslipAngle (KLVElement) {.key = {52}, .valueType = KLV_VALUE_FLOAT};
#define KLVAirfieldBarometricPressure (KLVElement) {.key = {53}, .valueType = KLV_VALUE_FLOAT};
#define KLVAirfieldElevation (KLVElement) {.key = {54}, .valueType = KLV_VALUE_FLOAT};
#define KLVRelavitveHumidity (KLVElement) {.key = {55}, .valueType = KLV_VALUE_FLOAT};
#define KLVPlatformGroundSpeed (KLVElement) {.key = {56}, .valueType = KLV_VALUE_INT};
#define KLVGroundRange (KLVElement) {.key = {57}, .valueType = KLV_VALUE_DOUBLE};
#define KLVPlatformFuelRemaining (KLVElement) {.key = {58}, .valueType = KLV_VALUE_FLOAT};
#define KLVPlatformCallsign (KLVElement) {.key = {59}, .valueType = KLV_VALUE_STRING};
#define KLVWeaponLoad (KLVElement) {.key = {60}, .valueType = KLV_VALUE_INT};
#define KLVWeaponFired (KLVElement) {.key = {61}, .valueType = KLV_VALUE_INT};
#define KLVLaserPRFCode (KLVElement) {.key = {62}, .valueType = KLV_VALUE_INT};
#define KLVSensorFieldOfViewName (KLVElement) {.key = {63}, .valueType = KLV_VALUE_INT};
#define KLVPlatfofmMagneticHeading (KLVElement) {.key = {64}, .valueType = KLV_VALUE_FLOAT};
#define KLVUASDatalinkLSVersionNumber (KLVElement) {.key = {65}, .valueType = KLV_VALUE_INT};
// item 66 is deprecated
#define KLVAlternatePlatformLatitude (KLVElement) {.key = {67}, .valueType = KLV_VALUE_DOUBLE};
#define KLVAlternatePlatformLongitude (KLVElement) {.key = {68}, .valueType = KLV_VALUE_DOUBLE};
#define KLVAlternatePlatformAltitude (KLVElement) {.key = {69}, .valueType = KLV_VALUE_FLOAT};
#define KLVAlternatePlatformName (KLVElement) {.key = {70}, .valueType = KLV_VALUE_STRING};
#define KLVAlternatePlatformHeading (KLVElement) {.key = {71}, .valueType = KLV_VALUE_FLOAT};
#define KLVEventStartTimeUTC (KLVElement) {.key = {72}, .valueType = KLV_VALUE_UINT64};
#define KLVRVTLocalDataSet (KLVElement) {.key = {73}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVVMTILocalDataSet (KLVElement) {.key = {74}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVSensorEllipsoidHeight (KLVElement) {.key ={75}, .valueType = KLV_VALUE_FLOAT};
#define KLVAlternatePlatformEllipsoidHeight (KLVElement) {.key ={76}, .valueType = KLV_VALUE_FLOAT};
#define KLVOperationalMode (KLVElement) {.key ={77}, .valueType = KLV_VALUE_INT};
#define KLVFrameCenterHeightAboveEllipsoid (KLVElement) {.key ={78}, .valueType = KLV_VALUE_FLOAT};
#define KLVSensorNorthVelocity (KLVElement) {.key ={79}, .valueType = KLV_VALUE_FLOAT};
#define KLVSensorEastVelocity (KLVElement) {.key ={80}, .valueType = KLV_VALUE_FLOAT};
#define KLVImageHorizonPixelPack (KLVElement) {.key ={81}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVCornerLatitudePoint1Full (KLVElement) {.key ={82}, .valueType = KLV_VALUE_DOUBLE};
#define KLVCornerLongitudePoint1Full (KLVElement) {.key ={83}, .valueType = KLV_VALUE_DOUBLE};
#define KLVCornerLatitudePoint2Full (KLVElement) {.key ={84}, .valueType = KLV_VALUE_DOUBLE};
#define KLVCornerLongitudePoint2Full (KLVElement) {.key ={85}, .valueType = KLV_VALUE_DOUBLE};
#define KLVCornerLatitudePoint3Full (KLVElement) {.key ={86}, .valueType = KLV_VALUE_DOUBLE};
#define KLVCornerLongitudePoint3Full (KLVElement) {.key ={87}, .valueType = KLV_VALUE_DOUBLE};
#define KLVCornerLatitudePoint4Full (KLVElement) {.key ={88}, .valueType = KLV_VALUE_DOUBLE};
#define KLVCornerLongitudePoint4Full (KLVElement) {.key ={89}, .valueType = KLV_VALUE_DOUBLE};
#define KLVPlatformPitchAngleFull (KLVElement) {.key ={90}, .valueType = KLV_VALUE_DOUBLE};
#define KLVPlatformRollAngleFull (KLVElement) {.key ={91}, .valueType = KLV_VALUE_DOUBLE};
#define KLVPlatformAngleOfAttackFull (KLVElement) {.key ={92}, .valueType = KLV_VALUE_DOUBLE};
#define KLVPlatformSideSlipAngleFull (KLVElement) {.key ={93}, .valueType = KLV_VALUE_DOUBLE};
#define KLVMIISCoreIdentifier (KLVElement) {.key ={94}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVSARMotionImageryMetadata (KLVElement) {.key ={95}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVTargetWidthExtended (KLVElement) {.key ={96}, .valueType = KLV_VALUE_DOUBLE};
#define KLVRangeImageLocalSet (KLVElement) {.key ={97}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVGeoRegistrationLocalSet (KLVElement) {.key ={98}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVCompositeImagingLocalSet (KLVElement) {.key ={99}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVSegmentLocalSet (KLVElement) {.key ={100}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVAmendLocalSet (KLVElement) {.key ={101}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVKLVSDCCFLP (KLVElement) {.key ={102}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVDensityAltitudeExtended (KLVElement) {.key ={103}, .valueType = KLV_VALUE_DOUBLE};
#define KLVDensityEllipsoidHeightExtended (KLVElement) {.key ={104}, .valueType = KLV_VALUE_DOUBLE};
#define KLVAlternatePlatformEllipsoidHeightExtended (KLVElement) {.key ={105}, .valueType = KLV_VALUE_DOUBLE};
#define KLVStreamDesignator (KLVElement) {.key ={106}, .valueType = KLV_VALUE_STRING};
#define KLVOperationalBase (KLVElement) {.key ={107}, .valueType = KLV_VALUE_STRING};
#define KLVBroadcastSource (KLVElement) {.key ={108}, .valueType = KLV_VALUE_STRING};
#define KLVRangeToRecoveryLocation (KLVElement) {.key ={109}, .valueType = KLV_VALUE_FLOAT};
#define KLVTimeAirborne (KLVElement) {.key ={110}, .valueType = KLV_VALUE_INT};
#define KLVPropulsionUnitSpeed (KLVElement) {.key ={111}, .valueType = KLV_VALUE_INT};
#define KLVPlatformCourseAngle (KLVElement) {.key ={112}, .valueType = KLV_VALUE_FLOAT};
#define KLVAltitudeAGL (KLVElement) {.key ={113}, .valueType = KLV_VALUE_FLOAT};
#define KLVRadarAltimeter (KLVElement) {.key ={114}, .valueType = KLV_VALUE_FLOAT};
#define KLVControlCommand (KLVElement) {.key ={115}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVControlCommandVerificationList (KLVElement) {.key ={116}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVSensorAzimuthRate (KLVElement) {.key ={117}, .valueType = KLV_VALUE_FLOAT};
#define KLVSensorElevationRate (KLVElement) {.key ={118}, .valueType = KLV_VALUE_FLOAT};
#define KLVSensorRollRate (KLVElement) {.key ={119}, .valueType = KLV_VALUE_FLOAT};
#define KLVOnboardMISStoragePercentFull (KLVElement) {.key ={120}, .valueType = KLV_VALUE_FLOAT};
#define KLVActiveWaveLength (KLVElement) {.key ={121}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVKLVCountryCodes (KLVElement) {.key ={122}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVNumberofNAVSATsInView (KLVElement) {.key ={123}, .valueType = KLV_VALUE_INT};
#define KLVPositioningMethodSource (KLVElement) {.key ={124}, .valueType = KLV_VALUE_INT};
#define KLVPlatformStatus (KLVElement) {.key ={125}, .valueType = KLV_VALUE_INT};
#define KLVSensorControlMode (KLVElement) {.key ={126}, .valueType = KLV_VALUE_INT};
#define KLVSensorFrameRatePack (KLVElement) {.key ={127}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVWaveLenghtsList (KLVElement) {.key ={128}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVTargetID (KLVElement) {.key ={129}, .valueType = KLV_VALUE_STRING};
#define KLVAirbaseLocations (KLVElement) {.key ={130}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVTakeoffTime (KLVElement) {.key ={131}, .valueType = KLV_VALUE_UINT64};
#define KLVTransmissionFrequency (KLVElement) {.key ={132}, .valueType = KLV_VALUE_FLOAT};
#define KLVOnboardMISStorageCapacity (KLVElement) {.key ={133}, .valueType = KLV_VALUE_INT};
#define KLVZoomPercentage (KLVElement) {.key ={134}, .valueType = KLV_VALUE_FLOAT};
#define KLVCommunicationsMethod (KLVElement) {.key ={135}, .valueType = KLV_VALUE_STRING};
#define KLVLeapSeconds (KLVElement) {.key ={136}, .valueType = KLV_VALUE_INT};
#define KLVCorrectionOffset (KLVElement) {.key ={137}, .valueType = KLV_VALUE_INT};
#define KLVPayloadList (KLVElement) {.key ={138}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVActivePayloads (KLVElement) {.key ={139}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVWeaponStores (KLVElement) {.key ={140}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVWaypointList (KLVElement) {.key ={141}, .valueType = KLV_VALUE_UNKNOWN};


// Other parsing results 
#define KLVParseError(key) (KLVElement) {.key = {(key)}, .valueType = KLV_VALUE_UNKNOWN};
#define KLVUnknown(key) (KLVElement) {.key = {(key)}, .valueType = KLV_VALUE_PARSE_ERROR};

typedef struct KLVParser {
    STATE state;
    TYPE type;
    uint8_t buffer[MAX_PARSE_BYTES];
    uint8_t sodb[MAX_PARSE_BYTES];
    // indices of buffers in this parsing session
    size_t bufferSize;
    size_t sodbSize;
    size_t setSize;
    size_t uasDataSetSize;
    KLVElement checksumElement;
    // The checksum element is saved as 
    KLVElement uasDataSet[MAX_UAS_TAGS];
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
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->intValue = (int)nVal;
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

                int64_t lVal;
                memcpy(&lVal, klv->value, 8);
                klv->uint64Value = ntohll(lVal);
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

                    klv->stringValue = (char *)klv->value;
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

                klv->stringValue = (char *)klv->value;
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
                
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 360.0 / 0xFFFF * LDS;
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
                
                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = 40.0 / 0xFFFE * LDS;

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
                
                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = 100.0 / 0xFFFE * LDS;
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

                klv->intValue = (int)*klv->value;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        case 9:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVPlatformIndicatedAirspeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;
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

                klv->stringValue = (char *)klv->value;
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

                klv->stringValue = (char *)klv->value;
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

                klv->stringValue = (char *)klv->value;
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

                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        int LDS = ntohl(nVal);
		        double UDS = 180.0 / 0xFFFFFFFE * LDS;
		        klv->doubleValue = UDS;

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
                
                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        int LDS = ntohl(nVal);
		        double UDS = 360.0 / 0xFFFFFFFE * LDS;
		        klv->doubleValue = UDS;

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

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;

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
                
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 180.0 / 0xFFFF * LDS;

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
                
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 180.0 / 0xFFFF * LDS;

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

                uint32_t nVal;
                memcpy(&nVal, klv->value, 4);
                uint32_t LDS = (uint32_t)ntohl(nVal);
                klv->doubleValue = 360.0 / 0xFFFFFFFF * LDS;

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
                
                uint32_t nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                klv->doubleValue = 360.0 / 0xFFFFFFFF * LDS;

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

                uint32_t nVal; 
                memcpy(&nVal, klv->value, 4);
                uint32_t LDS = (uint32_t)ntohl(nVal);
                klv->doubleValue = 360.0 / 0xFFFFFFFF * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 21:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSlantRange;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint32_t nVal;
                memcpy(&nVal, klv->value, 4);
                uint32_t LDS = ntohl(nVal);
                klv->doubleValue = 5000000.0 / 0xFFFFFFFF * LDS;
                
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 22:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVTargetWidth;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else if (len == 4) { // it should be 2
                *klv = KLVTargetWidth;
                p++;
                p++;
                for (size_t i = 0; i < 2; i++)
				        klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
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
                *klv = KLVFrameCenterLatitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;
            
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 24:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVFrameCenterLongitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 25:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVFrameCenterElevation;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;


            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 26:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVOffsetCornerLatitudePoint1;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);
                
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 27:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVOffsetCornerLongitudePoint1;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 28:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVOffsetCornerLatitudePoint2;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                
                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 29:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVOffsetCornerLongitudePoint2;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 30:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVOffsetCornerLatitudePoint3;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 31:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVOffsetCornerLongitudePoint3;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                    

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 32:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVOffsetCornerLatitudePoint4;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];


                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 33:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVOffsetCornerLongitudePoint4;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short nVal;
                memcpy(&nVal, klv->value, 2);
                short LDS = ntohs(nVal);
                klv->floatValue = (0.15 / 0xFFFE * LDS);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 34:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVIcingDetected;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 35:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVwindDirection;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 360.0 / 0xFFFF * LDS; 


            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 36:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVWindSpeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t LDS = (uint16_t)*klv->value;
		         klv->floatValue = (100.0 / 0xFF) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 37:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVStaticPressure;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
		        memcpy(&LDS, klv->value, 2);
		        LDS = ntohs(LDS);
		        klv->floatValue = (5000.0 / 65535.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 38:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVDensityAltitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                unsigned short LDS = 0;
		        memcpy(&LDS, klv->value, 2);
		        LDS = ntohs(LDS);
		        klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 39:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVOutsideAirTemperature;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 40:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVTargetLocationLatitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        int LDS = ntohl(nVal);
		        double UDS = 180.0 / 0xFFFFFFFE * LDS;
		        klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
		case 41:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVTargetLocationLongitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                int nVal;
		        memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
  
		case 42:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVTargetLocationeElevation;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 43:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVTargetTrackGateWidth;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->floatValue = 2.0 * *klv->value;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

		case 44:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVTargetTrackGateHeight;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->floatValue = 2.0 * *klv->value;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 45:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVTargetErrorEstimateC90;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t LDS = 0;
		        memcpy(&LDS, klv->value, 2);
		        klv->floatValue = (4095.0 / 65535.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 46:
        {
            int len = buf[p++];
            if(len <= 2) {
                *klv = KLVTargetErrorEstimateLE90;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t LDS = 0;
		        memcpy(&LDS, klv->value, 2);
		        klv->floatValue = (4095.0 / 65535.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 
        

		case 47:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVGenericFlagData;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 48: 
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVSecurityLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

		case 49:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVDifferentialPressure;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (5000.0 / 65535.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 50:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVPlatformAngleOfAttack;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (40.0 / 65534.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

		case 51:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVPlatformVerticalSpeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (360.0 / 65534.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 52:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVPlatformSideslipAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (40.0 / 65534.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 53:
        {
            int len = buf[p++]; 
            if(len < 2) {
                *klv = KLVAirfieldBarometricPressure;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (5000.0 / 65535.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 54:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVAirfieldBarometricPressure;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 55:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = KLVRelavitveHumidity;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t LDS = (uint16_t)*klv->value;
                klv->floatValue = (100 / 0xFF) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

		case 56:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = KLVPlatformGroundSpeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 57:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVGroundRange;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint32_t nVal;
                memcpy(&nVal, klv->value, 4);
                uint32_t LDS = ntohl(nVal);
                klv->doubleValue = 5000000.0 / 0xFFFFFFFF * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 58:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVPlatformFuelRemaining;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (10000.0 / 65535.0) * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 59:
        {
            int len = buf[p++]; 
            if(len <= 127) {
                *klv = KLVPlatformCallsign;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->stringValue = (char *)klv->value;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


		case 60:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVWeaponLoad;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                klv->intValue = (int) ntohs(nVal);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 61:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = KLVWeaponFired;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;                              

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 62:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVLaserPRFCode;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                klv->intValue = (int)ntohs(nVal);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 63:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = KLVSensorFieldOfViewName;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;                              

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 64:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVPlatfofmMagneticHeading;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = 360.0 / 0xFFFF * LDS;                          

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 65:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = KLVUASDatalinkLSVersionNumber;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;                              

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 66:
        {
            int len = buf[p++]; 

            //deprecated
            if(len <= 0) {
                *klv = KLVWeaponFired;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 67:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVAlternatePlatformLatitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;                           

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 68:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVAlternatePlatformLongitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;                           

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


		case 69:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVAlternatePlatformAltitude;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;                 

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 70:
        {
            int len = buf[p++]; 
            if(len <= 127) {
                *klv = KLVAlternatePlatformName;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->stringValue = (char *)klv->value;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


		case 71:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVAlternatePlatformHeading;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                unsigned short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = (360.0 / 65535.0) * LDS;                        

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 72:
        {
            int len = buf[p++]; 
            if(len <= 8) {
                *klv = KLVEventStartTimeUTC;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int64_t lVal;
                memcpy(&lVal, klv->value, 8);
                klv->uint64Value = ntohll(lVal);                       

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

		case 73:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size); 
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVEventStartTimeUTC;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 74:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size); 
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVEventStartTimeUTC;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


		case 75:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVSensorEllipsoidHeight;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;                     

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 76:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVAlternatePlatformEllipsoidHeight;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;    

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 77:
        {
            int len = buf[p++]; 
            if(len <= 1) {
                *klv = KLVOperationalMode;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;   

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 78:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVFrameCenterHeightAboveEllipsoid;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                uint16_t nVal;
                memcpy(&nVal, klv->value, 2);
                uint16_t LDS = ntohs(nVal);
                klv->floatValue = (19900.0 / 0xFFFF * LDS) - 900;  

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 79:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVSensorNorthVelocity;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = 654.0 / 65534.0 * LDS; 

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 80:
        {
            int len = buf[p++]; 
            if(len <= 2) {
                *klv = KLVSensorEastVelocity;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                short LDS = 0;
                memcpy(&LDS, klv->value, 2);
                LDS = ntohs(LDS);
                klv->floatValue = 654.0 / 65534.0 * LDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 81:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size); 
            p += numOfBytesRead;
            if(len <= size) {
                *klv = KLVImageHorizonPixelPack;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 82:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVCornerLatitudePoint1Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 


        case 83:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVCornerLongitudePoint1Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 84:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVCornerLatitudePoint2Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 85:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVCornerLongitudePoint2Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break; 

        case 86:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVCornerLatitudePoint3Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 87:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVCornerLongitudePoint3Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 88:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVCornerLatitudePoint4Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 89:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVCornerLongitudePoint4Full;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 90:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVPlatformPitchAngleFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 91:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVPlatformRollAngleFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 92:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVPlatformAngleOfAttackFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 180.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 93:
        {
            int len = buf[p++]; 
            if(len <= 4) {
                *klv = KLVPlatformSideSlipAngleFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
                memcpy(&nVal, klv->value, 4);
                int LDS = ntohl(nVal);
                double UDS = 360.0 / 0xFFFFFFFE * LDS;
                klv->doubleValue = UDS;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 94:
        {
            int len = buf[p++]; 
            if(len <= 50) {
                *klv =  KLVMIISCoreIdentifier;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 95:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv =  KLVSARMotionImageryMetadata;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 96:
        {
            int len = buf[p++]; 
            if(len <= 8) {
                *klv = KLVTargetWidthExtended;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(0.0, 1500000.0, klv->length);
                klv->floatValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 97:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVRangeImageLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 98:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVGeoRegistrationLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 99:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVCompositeImagingLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

         case 100:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVSegmentLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;   

        case 101:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVAmendLocalSet;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 102:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVKLVSDCCFLP;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 103:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = KLVDensityAltitudeExtended;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 104:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = KLVDensityEllipsoidHeightExtended;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 105:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = KLVAlternatePlatformEllipsoidHeightExtended;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;

        case 106:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = KLVStreamDesignator;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


        case 107:
        {
            int len = buf[p++];
            if(len <= 127) {
                *klv = KLVOperationalBase;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


        case 108:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVBroadcastSource;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


        case 109:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVRangeToRecoveryLocation;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(0.0, 21000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


        case 110:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVBroadcastSource;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                unsigned int val;
                memcpy(&val, klv->value, 4);
                val = ntohl(val);
                klv->intValue = val;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


        case 111:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVPropulsionUnitSpeed;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                
                unsigned int val;
                memcpy(&val, klv->value, 4);
                val = ntohl(val);
                klv->intValue = val;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;


        case 112:
        {
            int len = buf[p++];
            if(len <= 8) {
                *klv = KLVPlatformCourseAngle;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(0.0, 360.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        
        case 113:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVAltitudeAGL;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];


                FPParser fpp = fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        
        case 114:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVRadarAltimeter;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                // FPParser                
                FPParser fpp = fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 115:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
            p += numOfBytesRead;
            if(len < size) {
                *klv = KLVControlCommand;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];              

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 116:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = KLVControlCommandVerificationList;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];                

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 117:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorAzimuthRate;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(-1000.0, 1000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 118:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorElevationRate;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(-900, 40000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 119:
        {
            int len = buf[p++];
            if(len <= 4) {
                *klv = KLVSensorRollRate;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(-900.0, 40000.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 120:
        {
            int len = buf[p++];
            if(len <= 3) {
                *klv = KLVOnboardMISStoragePercentFull;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(0.0, 100.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 121:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = KLVActiveWaveLength;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];             

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 122:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = KLVKLVCountryCodes;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];             

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
        case 123:
        {
            int len = buf[p++];
            if(len <= 3) {
                *klv = KLVNumberofNAVSATsInView;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;          

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        } break;
       case 124:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVPositioningMethodSource;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;              

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
       case 125:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVPlatformStatus;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;              

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
       case 126:
        {
            int len = buf[p++];
            if(len <= 1) {
                *klv = KLVSensorControlMode;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                klv->intValue = (int)*klv->value;              

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 127:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len <= 16) {
                *klv = KLVSensorFrameRatePack;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 128:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = KLVWaveLenghtsList;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 129:
        {
    	    int len = buf[p++];
            if(len <= 32) {
                *klv = KLVTargetID;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                // string
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 130:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len <= 24) {
                *klv = KLVAirbaseLocations;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 131:
        {
    	    int len = buf[p++];
            if(len <= 8) {
                *klv = KLVTakeoffTime;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int64_t lVal;
                memcpy(&lVal, klv->value, 8);
                int64_t time = ntohll(lVal);
                klv->uint64Value = time / 1000000;
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 132:
        {
    	    int len = buf[p++];
            if(len <= 4) {
                *klv = KLVTransmissionFrequency;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(1.0, 99999.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 133:
        {
    	    int len = buf[p++];
            if(len <= 4) {
                *klv = KLVOnboardMISStorageCapacity;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        klv->intValue = ntohl(nVal);
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 134:
        {
    	    int len = buf[p++];
            if(len <= 4) {
                *klv = KLVZoomPercentage;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                FPParser fpp = fpParserOf(0.0, 100.0, klv->length);
                klv->doubleValue = fpParserDecode(&fpp, klv->value, klv->length);

  
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 135:
        {
    	    int len = buf[p++];
            if(len <= 127) {
                *klv = KLVCommunicationsMethod;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
                //string
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 136:
        {
    	    int len = buf[p++];
            if(len <= 4) {
                *klv = KLVLeapSeconds;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int nVal;
		        memcpy(&nVal, klv->value, 4);
		        klv->intValue = ntohl(nVal);
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 137:
        {
    	    int len = buf[p++];
            if(len <= 8) {
                *klv = KLVCorrectionOffset;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                int64_t lVal;
                memcpy(&lVal, klv->value, 8);
                int64_t time = ntohll(lVal);
                klv->uint64Value = time / 1000000;

            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 138:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = KLVPayloadList;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 139:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = KLVActivePayloads;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 140:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = KLVWeaponStores;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
        case 141:
        {
            int len = decodeBERLength(&numOfBytesRead, buf + p, size);
		    p += numOfBytesRead;
            if(len < size) {
                *klv = KLVWaypointList;
                klv->length = len;
                for(size_t i = 0; i < len; i++)
                    klv->value[i] = buf[p++];

                
            } else {
                *klv = KLVParseError(key);
                p += len;
            }
        }
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
    klv->keyLength = 1;
    return p;
}


static int klvParseUniversalSetElement(KLVElement *klv, uint8_t *data, size_t size) {
    return 0;
}


static void onElement(KLVParser *parser, const KLVElement klv) {
    if(key(klv) == 1) {
        parser->checksumElement = klv;
    }
    parser->uasDataSet[key(klv)] = klv;
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
    parser->sodbSize = 0;
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
    parser->bufferSize = 0;
}

static void onEndLenFlag(KLVParser *parser) {
    parser->state = START_SET_LEN;
    for(size_t i = 0; i < parser->bufferSize; i++) {
        parser->buffer[i] = 0;
    }
    parser->bufferSize = 0;
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

void parse(KLVParser* parser, const uint8_t* chunk, const int length, void (*onEndSetCallback)(KLVElement *, int)) {
    
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
            onEndSetCallback(parser->uasDataSet, MAX_UAS_TAGS);
            onEndSet(parser);
        }
    }
}


#endif // !KLV_IMPLEMENTATION