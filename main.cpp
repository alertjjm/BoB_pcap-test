#include <stdio.h>
#include <pcap.h>
#include <stdint.h>
#include "header.h"
#define ETH_SIZE 14
void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}
void show_pckt_info(pcap_t* handle){
    struct pcap_pkthdr* header;
    const u_char* packet;
    u_int size_ip,size_tcp,size_payload; //size of the headers and payload
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) return;
    if (res == -1 || res == -2) {
        printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
        exit(1);
    }
    printf("%u bytes captured\n", header->caplen);

    //initiailize components of packet
    struct sniff_ethernet* eth_header=(struct sniff_ethernet*)packet;
    struct sniff_ip* ip_header=(struct sniff_ip*)(packet+ETH_SIZE);
    size_ip = IP_HL(ip_header)*4;
    const struct sniff_tcp* tcp_header=(struct sniff_tcp*)(packet+ETH_SIZE+size_ip);
    size_tcp = TH_OFF(tcp_header)*4;
    const u_char* payload=packet+ETH_SIZE+size_ip+size_tcp;
    size_payload=ntohs(ip_header->ip_len)-size_ip-size_tcp;

    if(ip_header->ip_p!=6) //if pckt is not tcp
        return;
    //print mac address
    printf("1. src mac: ");
    for(int i=0; i<ETHER_ADDR_LEN; i++)
        printf("%02X ",eth_header->ether_shost[i]);
    printf("\tdst mac: ");
    for(int i=0; i<ETHER_ADDR_LEN; i++)
        printf("%02X ",eth_header->ether_dhost[i]);
    printf("\n");
    //print ip address
    printf("2. src ip: %s\t",inet_ntoa(ip_header->ip_src));
    printf("dst ip: %s\n",inet_ntoa(ip_header->ip_dst));
    //print port
    printf("3. src port: %d\tdst port:%d\n",ntohs(tcp_header->th_sport),ntohs(tcp_header->th_dport));
    //print payload len & 16 bytes of payload in hexadecimal(if exists)
    printf("4. Payload(len: %d): ",size_payload);
    for(int i=0; i<16&&i<size_payload; i++)
        printf("%02X ",payload[i]);
    printf("\n\n");
}
int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf);
        return -1;
    }

    while (true) {
        show_pckt_info(handle);
    }

    pcap_close(handle);
}
