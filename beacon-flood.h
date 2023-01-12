#pragma once
#include <iostream>
using namespace std;

void usage() {
	cerr << "syntax : beacon-flood <interface> <ssid-list-file>" << endl;
	exit(-1);
}

void beacon_flood(char* if_name, char* ssid_list);