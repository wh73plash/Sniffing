//
//  main.cpp
//  sniffing
//
//  Created by 김제인 on 2022/05/25.
//

//include standard header files
#include "standard_include.h"

//include libtins
#include <tins/tins.h>
using namespace Tins;
#define tins Tins

//include tracemanager headerfile
#include "TraceManager/tracemanager.h"

//helper
#include <unistd.h>

//include libpcap header
#include <pcap.h>
//reporting error number
#include <errno.h>
//networking headers
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>

#define NONPROMISCUOUS 0
#define PROMISCUOUS 1
#define DEV_MAX 32

inline bool callback_libtins(tins::PDU &packet){
    try{
        const tins::TCP &tcp = packet.rfind_pdu<tins::TCP>();
//        const TCP* tcp1 = packet.find_pdu<TCP>(); reference find
//        if(tcp.dport()!=80&&tcp.sport()!=80) return true; //parsing HTTP Packet

        std::cout << "TCP Source Port : " << tcp.sport() << std::endl;
        std::cout << "TCP Destination Port : " << tcp.dport() << std::endl;

//        const tins::RawPDU &rawPDU = packet.rfind_pdu<tins::RawPDU>();
//        std::cout << "Payload Size : " << rawPDU.size() << std::endl;

        return true;
    }catch(exception ex){
//        TraceManager::AddLog(ex.what());
        std::cout << ex.what() << std::endl;
        return false;
    }
}

inline void capture_pcap_functions(){
    char* dev; //name of pressent working network device
    char* net; //network address
    char* mask; //network mask address

    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    bpf_u_int32 netp; //ip
    bpf_u_int32 maskp; //submet mask
    struct in_addr addr;

    //get network device name
    dev = pcap_lookupdev(errbuf);

    //error
    if(dev == NULL){
        std::cout << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    //print network device name
    std::cout << "DEV : " << dev << std::endl;

    //get mask and ip with respect to network device dev
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);

    if(ret == -1){
        std::cout << errbuf << std::endl;
        exit(EXIT_FAILURE);
    }

    //convert network address
    addr.s_addr = netp;
    net = inet_ntoa(addr);

    if(net == NULL){
        std::perror("inet_ntoa");
        exit(EXIT_FAILURE);
    }

    //convert mask address
    addr.s_addr = maskp;
    mask = inet_ntoa(addr);

    if(mask == NULL){
        std::perror("inet_ntoa");
        exit(EXIT_FAILURE);
    }

    std::cout << "MASK : " << mask << std::endl;

    return;
}

inline bool recvPacket(pcap_t* pcd, uint8_t** packetData, int& dataLen){
    const u_char *pkt_data;
    struct pcap_pkthdr *pktHeader;
    int valueOfNextEx;

    while(true){
        valueOfNextEx = pcap_next_ex(pcd, &pktHeader, &pkt_data);

        switch (valueOfNextEx){
            case 1:
                *packetData = (uint8_t*)pkt_data;
                dataLen = pktHeader->caplen;
                return true;
            case 0:
                std::cout <<"need a sec.. to packet capture" << std::endl;
                continue;
            case -1:
                perror("pcap_next_ex function has an error");
                exit(EXIT_FAILURE);

            case -2:
                std::cout << "the packet have reached EOF" << std::endl;
                exit(EXIT_SUCCESS);
            default:
                return false;
        }
    }
}

inline void pcap_sec_t(){
    char errBuffer[PCAP_ERRBUF_SIZE];
    uint8_t* packetData;
    int dataLen;
    pcap_t* pcd;

    if((pcd = pcap_open_live(pcap_lookupdev(errBuffer), BUFSIZ, NONPROMISCUOUS, 1, errBuffer)) == NULL){
        perror("pcap_open_live error");
    }

    if(recvPacket(pcd, &packetData, dataLen)){
            std::cout << "Packet Come in" << std::endl;
            //packet saved in packetData
            //packet capture length saved in dataLen

            /***************example Code*****************/
            /*
             struct ether_header *ep= (struct ether_header*)packetData;
             */
            /***************example Code*****************/
    }
}

typedef struct _pcd_info_t{
    int     num;
    char    name[DEV_MAX][16];
    pcap_t  *pcd;
    u_long  out_size[DEV_MAX];
    u_long  out_pkts[DEV_MAX];
    u_long  in_size[DEV_MAX];
    u_long  in_pkts[DEV_MAX];
} pcd_info_t;

class devices{
public:
    int flags;
    std::string name;
    std::string sin_addr;
};

class network_devices{
public:
    std::string name;
    std::string IP;
    std::string BROD;
    std::string MASK;
    long long int MTU;
};

class packet{
public:
    std::vector<devices> dev_list;
    std::vector<network_devices> netdev_list;
};

packet pack;

int32_t main(const int32_t argc, const char** argv, const char** env) {
    std::ios::sync_with_stdio(false);
    std::cin.tie(nullptr);
    std::cout.tie(nullptr);

    char errbuf[PCAP_ERRBUF_SIZE];
    pcd_info_t lpcd_info;
    pcap_if_t *alldevps;
    struct sockaddr_in *si;

    std::memset((void *)&lpcd_info, 0x00, sizeof(lpcd_info));
    pcap_findalldevs(&alldevps, errbuf);

    while(true){
        if((alldevps->flags != PCAP_IF_LOOPBACK)){
            si = (struct sockaddr_in *)alldevps->addresses->addr;
            devices buffer;
            buffer.flags = alldevps->flags;
            buffer.name  = alldevps->name;
            buffer.sin_addr = inet_ntoa(si->sin_addr);
//            std::printf("%d %s %s\n", alldevps->flags, alldevps->name, inet_ntoa(si->sin_addr));
            pack.dev_list.push_back(buffer);
        }
        if (alldevps->next == NULL){
            break;
        }
        alldevps = alldevps->next;
    }

//    이더넷 데이터 구조체
    struct ifreq *ifr;
    struct sockaddr_in *sin;

//    이더넷 설정 구조체
    struct ifconf ifcfg;
    int fd;
    int n;
    int numreqs = 30;
    fd = socket(AF_INET, SOCK_DGRAM, 0);

//    이더넷 설정정보를 가지고오기 위해서
//    설정 구조체를 초기화하고
//    ifreq데이터는 ifc_buf에 저장되며,
//    네트워크 장치가 여러개 있을 수 있으므로 크기를 충분히 잡아주어야 한다.
//    보통은 루프백주소와 하나의 이더넷카드, 2개의 장치를 가진다.

    std::memset(&ifcfg, 0, sizeof(ifcfg));
    ifcfg.ifc_buf = NULL;
    ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
    ifcfg.ifc_buf = (char*)std::malloc(sizeof(char) * ifcfg.ifc_len);

    while(true){
        ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
        ifcfg.ifc_buf = (char*)realloc(ifcfg.ifc_buf, ifcfg.ifc_len);
        if (ioctl(fd, SIOCGIFCONF, (char *)&ifcfg) < 0){
            perror("SIOCGIFCONF ");
            exit(EXIT_FAILURE);
        }
//        디버깅 메시지 ifcfg.ifc_len/sizeof(struct ifreq)로 네트워크
//        장치의 수를 계산할 수 있다.
//        물론 ioctl을 통해서도 구할 수 있는데 그건 각자 해보기 바란다.
//        std::printf("%d : %d \n", ifcfg.ifc_len, (int)sizeof(struct ifreq));
        break;
    }
//    주소를 비교해 보자.. ifcfg.ifc_req는 ifcfg.ifc_buf를 가리키고 있음을
//    알 수 있다.
//    std::printf("address %d\n", &ifcfg.ifc_req);
//    std::printf("address %d\n", &ifcfg.ifc_buf);

//    네트워크 장치의 정보를 얻어온다.
//    보통 루프백과 하나의 이더넷 카드를 가지고 있을 것이므로
//    2개의 정보를 출력할 것이다.
    ifr = ifcfg.ifc_req;
    for (n = 0; n < ifcfg.ifc_len; n+= sizeof(struct ifreq)){
//        주소값을 출력하고 루프백 주소인지 확인한다.
//        std::printf("[%s]\n", ifr->ifr_name);
        network_devices buffer_class;
        buffer_class.name  = ifr->ifr_name;
        sin = (struct sockaddr_in *)&ifr->ifr_addr;
//        std::printf("IP    %s\n", inet_ntoa(sin->sin_addr));
        buffer_class.IP  = inet_ntoa(sin->sin_addr);
        if((sin->sin_addr.s_addr) == INADDR_LOOPBACK){
            std::printf("Loop Back\n");
        }else{
//            루프백장치가 아니라면 MAC을 출력한다.
//            ioctl(fd, SIOCGIFHWADDR, (char *)ifr);
//            sa = &ifr->ifr_hwaddr;
//            printf("%s\n", ether_ntoa((struct ether_addr *)sa->sa_data));
        }
//        브로드 캐스팅 주소
        ioctl(fd,  SIOCGIFBRDADDR, (char *)ifr);
        sin = (struct sockaddr_in *)&ifr->ifr_broadaddr;
//        std::printf("BROD  %s\n", inet_ntoa(sin->sin_addr));
        buffer_class.BROD = inet_ntoa(sin->sin_addr);
//        네트워크 마스팅 주소
        ioctl(fd, SIOCGIFNETMASK, (char *)ifr);
        sin = (struct sockaddr_in *)&ifr->ifr_addr;
//        std::printf("MASK  %s\n", inet_ntoa(sin->sin_addr));
        buffer_class.MASK = inet_ntoa(sin->sin_addr);
//        MTU값
        ioctl(fd, SIOCGIFMTU, (char *)ifr);
//        std::printf("MTU   %d\n", ifr->ifr_mtu);
        buffer_class.MTU = ifr->ifr_mtu;
        ifr++;

        pack.netdev_list.push_back(buffer_class);
    }


//    for(const auto& i : pack.dev_list){
//        std::cout << i.flags << " : " << i.name << " : " << i.sin_addr << std::endl;
//    }

    for(const auto& i : pack.netdev_list){
        if(std::strcmp(i.name.c_str(), "") == 0){
            continue;
        }
        std::cout << "name : [" << i.name << "]\nIP : [" << i.IP << "] \nBROD : [" << i.BROD << "] \nMASK : [" << i.MASK << "] \nMTU : [" << i.MTU << "]\n\n";
    }

    return EXIT_SUCCESS;
}
