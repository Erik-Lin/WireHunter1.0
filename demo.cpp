#include <iostream>
#include <string>
#include <boost/shared_ptr.hpp>
#include <boost/thread.hpp>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <iomanip>
#include<stdio.h>

//定义网络数据包处理函数
// Version 1.0

// void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData)
// {
//     //解析数据包
//     struct ether_header* ethHeader = (struct ether_header*) packetData;
//     if(ntohs(ethHeader->ether_type) != ETHERTYPE_IP)
//     {
//         return;
//     }
//     struct ip* ipHeader = (struct ip*)(packetData + sizeof(struct ether_header));
//     if(ipHeader->ip_p != IPPROTO_TCP)
//     {
//         return;
//     }
//     struct tcphdr* tcpHeader = (struct tcphdr*)(packetData + sizeof(struct ether_header) + sizeof(struct ip));

//     //打印数据包信息
//     std::cout << "\n------------------" <<std::endl;
//     std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
//     std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
//     std::cout << "Source port: " << ntohs(tcpHeader->source) << std::endl;
//     std::cout << "Destination port: " << ntohs(tcpHeader->dest) << std::endl;
//     std::cout << "Packet length: " << pkthdr->len << std::endl;
//     std::cout << "------------------\n" <<std::endl;

//     //数据处理
//     const u_char* payload = packetData + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
//     int payloadLen = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
//     std::cout << "Payload: ";
//     for(int i = 0; i < payloadLen; i++)
//     {
//         std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)payload[i];
//     }
//     std::cout << std::dec << std::endl;
// }


// Function : This function parses the Ethernet header and IP header, 
// and judges the protocol type contained in the data packet according to the protocol type, 
// and supports IPv4, IPv6, ARP, TCP, UDP, ICMP, and IGMP protocol types. 
// If the protocol type is not one of these types, set the protocol type to Unknown and print it. 
// The function also prints the source IP address, destination IP address, protocol type and packet length, and prints the payload of the packet.
// Writer: Lin Shanli
// Time: February 17, 2023
// Version 2.0
// All Rights Reserved.
void packetHandler(u_char* userData, const struct pcap_pkthdr* pkthdr, const u_char* packetData)
{
    // 解析以太网帧头部
    struct ether_header* ethHeader = (struct ether_header*) packetData;

    // 判断以太网协议类型
    u_int16_t etherType = ntohs(ethHeader->ether_type);
    std::string protocol1,protocol2;
    switch (etherType) {
        case ETHERTYPE_IP:
            protocol1 = "IPv4";
            break;
        case ETHERTYPE_IPV6:
            protocol1 = "IPv6";
            break;
        case ETHERTYPE_ARP:
            protocol1 = "ARP";
            break;
        default:
            protocol1 = "Unknown";
            break;
    }

    // 如果不是IPv4或IPv6，返回
    if (etherType != ETHERTYPE_IP && etherType != ETHERTYPE_IPV6) {
        return;
    }

    // 解析IP头部
    struct ip* ipHeader = (struct ip*)(packetData + sizeof(struct ether_header));

    // 判断IP协议类型
    u_int8_t protocolNumber = ipHeader->ip_p;
    switch (protocolNumber) {
        case IPPROTO_TCP:
            protocol2 = "TCP";
            break;
        case IPPROTO_UDP:
            protocol2 = "UDP";
            break;
        case IPPROTO_ICMP:
            protocol2 = "ICMP";
            break;
        case IPPROTO_IGMP:
            protocol2 = "IGMP";
            break;
        default:
            protocol2 = "Unknown";
            break;
    }

    // 打印数据包信息
    std::cout << "\n------------------" <<std::endl;
    std::cout << "Source IP: " << inet_ntoa(ipHeader->ip_src) << std::endl;
    std::cout << "Destination IP: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
    std::cout << "Protocol: " << protocol1<<"\t"<<protocol2<< std::endl;
    std::cout << "Packet length: " << pkthdr->len << std::endl;
    

    // 数据处理
    const u_char* payload = packetData + sizeof(struct ether_header) + sizeof(struct ip) + (ipHeader->ip_hl * 4);
    int payloadLen = pkthdr->len - (sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
    std::cout << "Payload: ";
    for(int i = 0; i < payloadLen; i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)payload[i];
    }
    std::cout << std::dec << std::endl;
    std::cout << "------------------\n" <<std::endl;
}
int main(int argc, char* argv[])
{
    //打开网络接口并设置捕获过滤器
    pcap_t* descr = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    descr = pcap_open_live("ens33", BUFSIZ, 0, -1, errbuf);
    if(descr == NULL)
    {
        std::cerr << "Unable to open network interface." << std::endl;
        return 1;
    }
    struct bpf_program fp;
    if(pcap_compile(descr, &fp, "tcp", 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        std::cerr << "Unable to compile filter." << std::endl;
        return 1;
    }
    if(pcap_setfilter(descr, &fp) == -1)
    {
        std::cerr << "Unable to set filter." << std::endl;
        return 1;
    }

    //启动数据包捕获线程
    boost::thread packetThread(boost::bind(pcap_loop, descr, 0, packetHandler, reinterpret_cast<u_char*>(NULL)));

    //等待用户输入退出命令
    std::string input;
    std::cin >> input;
    std::cout << "Exiting..." << std::endl;

    //停止数据包捕获线程并关闭网络接口
    pcap_breakloop(descr);
    packetThread.join();
    pcap_close(descr);

    return 0;
}