#include "adaptor.hpp"
#include <unordered_set>
#include <fstream>
#include <iostream>
#include <pcap.h>

Adaptor::Adaptor(std::string filename) {
    unsigned long long buf_size = 5000000000;
    data = (adaptor_t*)calloc(1, sizeof(adaptor_t));
    data->databuffer = (unsigned char*)calloc(buf_size, sizeof(unsigned char));
    data->ptr = data->databuffer;
    data->cnt = 0;
    data->cur = 0;
    unsigned char* p = data->databuffer;
    //Read pcap file
    std::ifstream infile;       
    uint32_t srcip, dstip;
    uint16_t srcport, dstport;
    int pro;
    infile.open(filename);
    if(!infile) std::cout << "Open file error!" << std::endl;
    while(infile >> srcip >> dstip >> srcport >> dstport >> pro) {
        if (p+13 < data->databuffer + buf_size) {
            memcpy(p, &srcip, sizeof(uint32_t));
            memcpy(p+sizeof(uint8_t)*4, &dstip, sizeof(uint32_t));
            memcpy(p+sizeof(uint8_t)*8, &srcport, sizeof(uint16_t));
            memcpy(p+sizeof(uint8_t)*10, &dstport, sizeof(uint16_t)); 
            memcpy(p+sizeof(uint8_t)*12, &pro, sizeof(uint8_t));          
            p += sizeof(uint8_t)*13;
            data->cnt++;
        } else {
            std::cout << "[Error] Buffersize too small" << std::endl;
            break;
        }
    }
    //std::cout << "[Message] Read " << data->cnt << " items" << std::endl;
    //std::cout << "[Message] Test = " << test << std::endl;
    infile.close();
}

Adaptor::Adaptor(std::string filename, uint64_t buffersize) {
    unsigned long test = 0;
    data = (adaptor_t*)calloc(1, sizeof(adaptor_t));
    data->databuffer = (unsigned char*)calloc(buffersize, sizeof(unsigned char));
    data->ptr = data->databuffer;
    data->cnt = 0;
    data->cur = 0;
    
    //Read pcap file
    std::string path = filename;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pfile = pcap_open_offline(path.c_str(), errbuf);
    if (pfile == NULL) {
        std::cout << "[Error] Fail to open pcap file" << std::endl;
        exit(-1);
    }
    unsigned char* p = data->databuffer;
    int linktype = pcap_datalink(pfile);
    int ETH_LEN = 14;
    if (linktype == 1) ETH_LEN = 14;
    else if (linktype == 12) ETH_LEN = 0;
    //pcpp::RawPacket rawPacket;
    const u_char* rawpkt; // raw packet
    struct pcap_pkthdr hdr;

    struct ip* ip_hdr;
    while ((rawpkt = pcap_next(pfile, &hdr)) != NULL) {
        int status = 1;
        int eth_len = ETH_LEN;
        // error checking (Ethernet level)
        if (eth_len == 14) {
            struct ether_header* eth_hdr = (struct ether_header*)rawpkt;
            if (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN) {
                eth_len = 18;
            }
            else if (ntohs(eth_hdr->ether_type) != ETH_P_IP) {
                status = -1;
            }
        }
        else if (eth_len == 4) {
            if (ntohs(*(uint16_t*)(rawpkt + 2)) != ETH_P_IP) {
                status = -1;
            }
        }
        else if (eth_len != 0) {
            // unkown ethernet header length
            status = -1;
        }
        int pkt_len = (hdr.caplen < MAX_CAPLEN) ? hdr.caplen : MAX_CAPLEN;
        uint32_t len = pkt_len - eth_len;
        // error checking (IP level)
        ip_hdr = (struct ip*)(rawpkt + eth_len);
        // i) IP header length check
        if ((int)len < (ip_hdr->ip_hl << 2)) {
            status = -1;
        }
        // ii) IP version check
        if (ip_hdr->ip_v != 4) {
            status = -1;
        }
        // iii) IP checksum check
        if (IP_CHECK && in_chksum_ip((unsigned short*)ip_hdr, ip_hdr->ip_hl << 2)) {
            status = -1;
        }

        // error checking (TCP/UDP/ICMP layer test)
        struct tcphdr* tcp_hdr;
        if (ip_hdr->ip_p == IPPROTO_TCP) {
            // see if the TCP header is fully captured
            tcp_hdr = (struct tcphdr*)((uint8_t*)ip_hdr + (ip_hdr->ip_hl << 2));
            if ((int)len < (ip_hdr->ip_hl << 2) + (tcp_hdr->doff << 2)) {
                status = -1;
            }
        } else if (ip_hdr->ip_p == IPPROTO_UDP) {
            // see if the UDP header is fully captured
            if ((int)len < (ip_hdr->ip_hl << 2) + 8) {
                status = -1;
            }
        } else if (ip_hdr->ip_p == IPPROTO_ICMP) {
            // see if the ICMP header is fully captured
            if ((int)len < (ip_hdr->ip_hl << 2) + 8) {
                status = -1;
            }
        }

        if (status == 1) {
            // assign the fields
            uint16_t src_port, dst_port, iplen;
            iplen = ntohs(ip_hdr->ip_len);
            if (ip_hdr->ip_p == IPPROTO_TCP) {
                // TCP
                tcp_hdr = (struct tcphdr*)((uint8_t*)ip_hdr + (ip_hdr->ip_hl << 2));
                src_port = ntohs(tcp_hdr->source);
                dst_port = ntohs(tcp_hdr->dest);
            }
            else if (ip_hdr->ip_p == IPPROTO_UDP) {
                // UDP
                struct udphdr* udp_hdr = (struct udphdr*)((uint8_t*)ip_hdr + (ip_hdr->ip_hl << 2));
                src_port = ntohs(udp_hdr->source);
                dst_port = ntohs(udp_hdr->dest);
            } else {
                // Other L4
               	src_port = 0;
                dst_port = 0;
            }
            int srcip = ntohl(ip_hdr->ip_src.s_addr);
            int dstip = ntohl(ip_hdr->ip_dst.s_addr);
            //uint8_t protocol = (uint8_t)ntohs(ip_hdr->ip_p);
			uint8_t protocol = (uint8_t)ip_hdr->ip_p;

			//debug
			/*if(data->cnt < 50) {
				if(protocol == 6) std::cout<<"tcp"<<std::endl;
				else if(protocol == 17) std::cout<<"udp"<<std::endl;
				else std::cout<<"none"<<std::endl;
			}*/
            if (p+13 < data->databuffer + buffersize) {
                memcpy(p, &srcip, sizeof(uint32_t));
                memcpy(p+sizeof(uint8_t)*4, &dstip, sizeof(uint32_t));
                memcpy(p+sizeof(uint8_t)*8, &src_port, sizeof(uint16_t));
                memcpy(p+sizeof(uint8_t)*10, &dst_port, sizeof(uint16_t)); 
                memcpy(p+sizeof(uint8_t)*12, &protocol, sizeof(uint8_t));          
                p += sizeof(uint8_t)*13;
                data->cnt++;
                test += iplen;
            }
            

        }
    }
    //std::cout << "[Message] Read " << data->cnt << " items" << std::endl;
    //std::cout << "[Message] Test = " << test << std::endl;

    pcap_close(pfile);
}


Adaptor::~Adaptor() {
    free(data->databuffer);
    free(data);
}

int Adaptor::GetNext(tuple_t* t) {
    if (data->cur > data->cnt) {
        return -1;
    }
    t->src_ip = *((uint32_t*)data->ptr);
    t->dst_ip = *((uint32_t*)(data->ptr+4));
    t->src_port = *((uint16_t*)(data->ptr+8));
    t->dst_port = *((uint16_t*)(data->ptr+10));
    t->protocol = *((uint8_t*)(data->ptr+12));

    data->cur++;
    data->ptr += 13;
    return 1;
}

void Adaptor::Reset() {
    data->cur = 0;
    data->ptr = data->databuffer;
}

uint64_t Adaptor::GetDataSize() {
    return data->cnt;
}
