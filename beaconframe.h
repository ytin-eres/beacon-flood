#include "radiotaphdr.h"
#include "beaconhdr.h"

#define MAX_SSID_LEN 256

struct BeaconFrame {
	RadiotapHdr radioHdr_;
	BeaconHdr beaconHdr_;
	char dummy[256];
	size_t size_;
};

