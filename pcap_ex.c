#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <pcap.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

char* filter = NULL;
int filter_port = 0;

void printHelp() {
    printf("Usage:\n");
    printf("-i <network_name> Select the network interface name (e.g.,eth0)\n");
    printf("-r <packet_capture_name>: Packet capture filename (e.g., test.pcap\n");
    printf("-f <port>: Filter expression in string format (e.g., port 8080\n");
    printf("-h: Display help\n");
}


void tcp_process(const struct ip *ip_header, const struct ip6_hdr *ip6_header, int ip_type, const unsigned char *packet){
    // if ipv4
    if (ip_type == 0) {
        // Cast to TCP header
        struct tcphdr *tcp_header = (struct tcphdr *)((char *)ip_header + (ip_header->ip_hl * 4));
        // Check if the destination port matches the filter_port
        if (filter_port == 0 || ntohs(tcp_header->th_dport) == filter_port) {
            // Process the packet
            printf("\n\nNew packet\n");
            printf("Protocol: TCP\n");
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));
            printf("TCP Header Length: %d bytes\n", (tcp_header->doff * 4)); 
            printf("TCP Payload Length: %d bytes\n", ntohs(ip_header->ip_len) - (tcp_header->doff * 4) - (ip_header->ip_hl * 4));
            unsigned char *payload = (unsigned char *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + (tcp_header->th_off * 4));
            printf("TCP Payload location: %s\n", payload);

        }
    } else {
        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];
        struct tcphdr *tcp_header = (struct tcphdr *)(ip6_header + 1);  // Assuming there are no extension headers
        if (filter_port == 0 || ntohs(tcp_header->th_dport) == filter_port) {
            // Process the packet
            printf("\n\nNew packet\n");
            printf("Protocol: TCP \n");
            inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);    
            inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);
            printf("Source IP: %s\n", src_ip_str);
            printf("Destination IP: %s\n", dst_ip_str);
            printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
            printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));
            printf("TCP Header Length: %d bytes\n", (tcp_header->doff * 4)); 
            printf("TCP Payload Length: %d bytes\n", ntohs(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen) - (tcp_header->doff * 4));
            unsigned char *payload = (unsigned char *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + (tcp_header->th_off * 4));
            printf("TCP Payload location: %s\n", payload);

        }
    }
}

void udp_process(const struct ip * ip_header, const struct ip6_hdr *ip6_header, int ip_type, const unsigned char *packet){
    // If ipv4
    if (ip_type == 0) {
        // Cast to UDP header
        struct udphdr *udp_header = (struct udphdr *)((char *)ip_header + (ip_header->ip_hl * 2));
        // Check if the destination port matches the filter_port
        if (filter_port == 0 || ntohs(udp_header->uh_dport) == filter_port) {
            // Process the packet
            printf("\n\nNew packet\n");
            printf("Protocol: UDP\n");
            printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
            printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
            printf("Source Port: %u\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %u\n", ntohs(udp_header->uh_dport));
            printf("UDP Header Length: %ld bytes\n", sizeof(struct udphdr));
            printf("UDP Payload Length: %ld bytes\n", ntohs(udp_header->uh_ulen) - sizeof(struct udphdr));  
            unsigned char *payload = (unsigned char *)(packet + sizeof(struct ether_header) + (ip_header->ip_hl * 4) + sizeof(struct udphdr));  
            printf("UDP Payload location: %s\n", payload);
    
        } 
    } else {
        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];
        struct udphdr *udp_header = (struct udphdr *)(ip6_header + 1);  // Assuming there are no extension headers
        if (filter_port == 0 || ntohs(udp_header->uh_dport) == filter_port) {
            // Process the packet
            printf("\n\nNew packet\n");
            printf("Protocol: UDP\n");
            inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);    
            inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);
            printf("Source IP: %s\n", src_ip_str);
            printf("Destination IP: %s\n", dst_ip_str);
            printf("Source Port: %u\n", ntohs(udp_header->uh_sport));
            printf("Destination Port: %u\n", ntohs(udp_header->uh_dport));
            printf("UDP Header Length: %lu bytes\n", sizeof(struct udphdr));
            printf("UDP Payload Length: %lu bytes\n", ntohs(udp_header->uh_ulen) - sizeof(struct udphdr));
            unsigned char *payload = (unsigned char *)(packet + sizeof(struct ether_header) + sizeof(struct ip6_hdr) + sizeof(struct udphdr));
            printf("UDP Payload location: %s\n", payload);
        }
    }

}






void packet_handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    //printf("filter_port: %d", filter_port);
    struct ether_header *eth_header;
    struct ip *ip_header;
    struct ip6_hdr *ip6_header;

    eth_header = (struct ether_header *) packet;

    // Check if the EtherType is IP
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        // Cast to IP header
        ip_header = (struct ip *)(packet + sizeof(struct ether_header));

        // Check if udp or tcp
        if (ip_header->ip_p == IPPROTO_TCP){
            tcp_process(ip_header, ip6_header, 0, packet);
        } else if (ip_header->ip_p == IPPROTO_UDP){
            udp_process(ip_header, ip6_header, 0, packet);
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6){
        // Cast to IP6 header
        ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        // Check if udp or tcp
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            tcp_process(ip_header, ip6_header, 1, packet); 
        } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            udp_process(ip_header, ip6_header, 1, packet);  
        }
    }

}


int online_monitor(char *interface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Check if filter is given 
    if (filter) {
        char *port_str = strstr(filter, "port ");
        if (port_str != NULL) {
            // Skip "port " and convert the remaining string to an integer
            filter_port = atoi(port_str + 5);
        }
        //printf("filter port: %d", filter_port);
    }  

    pcap_t *handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface_name, errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;

}


int main(int argc, char *argv[]) {
    int opt;
    int flag = -1;
    char *interface_name = NULL;
    char *file_name = NULL;


    if (argc < 2) {
        printf("No options provided. Use -h for help.\n");
        return 1;
    }
    while ((opt = getopt(argc, argv, ":i:r:f:h")) != -1){
        switch(opt){
        case 'i':
            flag = 1;
            interface_name = optarg;
            break;
        case 'r':
            flag = 0;
            file_name = optarg;
            break;
        case 'f':
            filter = optarg;
            break;
        case 'h':
            printHelp();
            break;
        case '?':
            printf("Unknown option or missing argument: -%c\n", optopt);
            printHelp();
            return 1;
        default:
            abort();
        }
    }
    if (flag == 1){
        online_monitor(interface_name);
        
        printf("interface: %s, filter: %s", interface_name, filter);
        return 0;
    } else if (flag == 0){
        //offline_monitor(file_name);
        
        printf("filename: %s", file_name);
        return 0;
    } else {
        printf("Unknown option or missing argument: %c\n", optopt);
        printHelp();
        return 1;
    }

}