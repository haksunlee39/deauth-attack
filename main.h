#include "mac.h"

#pragma pack(push, 1)
typedef struct RadiotapHeader {
	uint8_t it_version;
	uint8_t it_pad;
	uint16_t it_len;
	uint32_t it_present;
} RadiotapHeader;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct BeaconMacHeader {
	uint16_t frameControl;
	uint16_t durationID;
	Mac dst;
	Mac source;
	Mac BSSID;
	uint16_t sequenceControl;
} BeaconMacHeader;
#pragma pack(pop)

typedef struct codes {
	uint16_t code;
} codes;

#pragma pack(push, 1)
typedef struct DeauthPacket {
	RadiotapHeader rth;
	BeaconMacHeader bmh;
	codes code;
} DeauthPacket;
#pragma pack(pop)
