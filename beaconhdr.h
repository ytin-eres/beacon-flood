#pragma once
#include <stdint.h>
#include "dot11hdr.h"
#include "mac.h"

#pragma pack(push, 1)
struct BeaconHdr : Dot11Hdr {
	Mac addr1_;
	Mac addr2_;
	Mac addr3_;
	uint8_t frag_:4;
	uint16_t seq_:12;

	Mac ra() { return addr1_;}
	Mac da() { return addr1_; }
	Mac ta() { return addr2_; }
	Mac sa() { return addr2_; }
	Mac bssid() { return addr3_; }

	struct __attribute__((packed)) Fix {
		uint64_t timestamp_; // microsecond
		uint16_t beaconInterval_; // millisecond
		uint16_t capabilities_;
	} fix_;

	struct Tag {
		uint8_t num_;
		uint8_t len_;

		void* value() {
			return (char*)this + sizeof(Tag);
		}

		Tag* next() {
			char* res = (char*)this;
			res += sizeof(Tag) + this->len_;
			return PTag(res);
		}
	};
	typedef Tag *PTag;
	Tag* tag() {
		char* p = (char*)(this);
		p += sizeof(BeaconHdr);
		return PTag(p);
	}

	enum: uint8_t {
		TagSsidParameterSet = 0,
		TagSupportedRated = 1,
		TagDsParameterSet = 3,
		TagTrafficIndicationMap = 5,
		TagCountryInformation = 7,
		TagQbssLoadElement = 11,
		TagHtCapabilities = 45,
		TagRsnInformation = 48,
		TagHtInformation = 61,
		TagVendorSpecific = 221
	};


	// struct TrafficIndicationMap : Tag {
	// 	uint8_t count_;
	// 	uint8_t period_;
	// 	uint8_t control_;
	// 	uint8_t bitmap_;
	// };
	// typedef TrafficIndicationMap *PTrafficIndicationMap;

	// struct HtCapabilities : Tag {
	// 	uint16_t capabilitiesInfo_;
	// 	uint8_t mpduParameters_;
	// 	uint8_t mcsSet_[16];
	// 	uint16_t extCapabilities_;
	// 	uint32_t txbfCapabilities_;
	// 	uint8_t aselCapabilities_;
	// };
	// typedef HtCapabilities *PHtCapabilities;

	// struct HtInformation : Tag {
	// 	uint8_t primaryChannel_;
	// 	uint8_t htInformationSubset1_;
	// 	uint16_t htInformationSubset2_;
	// 	uint16_t htInformationSubset3_;
	// 	uint8_t basicMcsSet_[16];
	// };
	// typedef HtInformation *PHtInformation;
};
typedef BeaconHdr *PBeaconHdr;
#pragma pack(pop)
