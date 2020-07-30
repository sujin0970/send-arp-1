#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static uint8_t my_mac[Mac::SIZE];

char* get_myaddr(char *dev)
{
    struct ifreq ifr;
    // 0, use an unspecified default protocol appropriate for the requested socket type.
    int fd_ip = socket(PF_INET, SOCK_DGRAM, 0);
    if(fd_ip == -1) {
        printf("socketopen error\n");
        exit(0);
    }

    ifr.ifr_addr.sa_family = AF_INET;

    // IFNAMESIZ = ifr_name length
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);

    // Get MAC Address
    /* SIOCGIFHWADDR
    *       Get or set the hardware address of a device using  ifr_hwaddr.
    *       The  hardware  address  is  specified  in  a  struct sockaddr.
    *       a_family contains the ARPHRD_* device type,  sa_data  the  L2
    *       hardware  address  starting from byte 0.  Setting the hardware
    *       address is a privileged operation.
    */
    if (0 == ioctl(fd_ip, SIOCGIFHWADDR, &ifr)) {
        memcpy(&my_mac, ifr.ifr_hwaddr.sa_data, Mac::SIZE);
    }
    else {
        printf("interface error");
        exit(0);
    }

    // GET IP Address
    /* SIOCGIFADDR
    *       Get  or set the address of the device using ifr_addr.  Setting
    *       the interface address is a privileged operation.  For compati‐
    *       bility, only AF_INET addresses are accepted or returned.
    */
    if(ioctl(fd_ip, SIOCGIFADDR, &ifr)<0) {
        perror("ioctl error\n");
        exit(0);
    }
    else
    {
        return inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
    }
    close(fd_ip);
}

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp <interface> sender_ip target_ip\n");
    printf("sample: send-arp ens33 192.168.159.102 192.168.159.103\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }


    char *sender_ip = argv[2];
    char *target_ip = argv[3];
    EthArpPacket packet;

    get_myaddr(dev);
    packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
    packet.eth_.smac_ = my_mac;
    packet.eth_.type_ = htons(EthHdr::Arp);

    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = my_mac;
    packet.arp_.sip_ = htonl(Ip(get_myaddr(dev)));
    packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packet.arp_.tip_=htonl(Ip(sender_ip));


    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }

    struct pcap_pkthdr* header;
    const u_char* reply_packet;

    while(int res = pcap_next_ex(handle, &header, &reply_packet) >= 0) {
        sleep(0);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        struct EthArpPacket *etharp = (struct EthArpPacket *)reply_packet;
        if(etharp->eth_.type_!=htons(EthHdr::Arp) && etharp->arp_.op_!=htons(ArpHdr::Reply) && etharp->arp_.sip_!=htonl(Ip(sender_ip))) continue;

        printf("resolving OK\n");
        packet.eth_.dmac_ = etharp->eth_.smac_;
        packet.arp_.tmac_ = etharp->arp_.smac_;
        packet.arp_.op_=htons(ArpHdr::Reply);
        packet.arp_.sip_=htonl(Ip(target_ip));
    }
    pcap_close(handle);
}