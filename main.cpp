#include <iostream>
#include <csignal>
#include "beacon-flood.h"
using namespace std;


int main(int argc, char** argv) {
	if (argc != 3) {
		usage();
	}

	beacon_flood(argv[1], argv[2]);
}