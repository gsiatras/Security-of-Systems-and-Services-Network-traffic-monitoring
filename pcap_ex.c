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
#include <sys/socket.h>
#include <net/ethernet.h>

char* filter = NULL;
int filter_port = 0;
int flag = -1;

int netflows = 0;
int packets = 0;
int tcppackets = 0;
int udppackets = 0;
long tcpbytes = 0;
long udpbytes = 0;

struct network_flow {
    char *source_ip;
    char *destination_ip;
    unsigned int source_port;
    unsigned int destination_port;
    unsigned int protocol;
};

struct network_flow network_flows[10000];

int getTCPflows() {
    int tcpCount = 0;

    for (int i = 0; i < netflows; i++) {
        if (network_flows[i].protocol == 0) {
            // Protocol 0 represents TCP
            tcpCount++;
        }
    }

    return tcpCount;
}


int getUDPflows() {
    int tcpCount = 0;

    for (int i = 0; i < netflows; i++) {
        if (network_flows[i].protocol == 1) {
            // Protocol 1 represents UDP
            tcpCount++;
        }
    }

    return tcpCount;
}


void print_stats() {
    printf("\n\n\n|======================Statistics=========================|\n");
    printf("|-Total number of network flows captured: %d\n", netflows);
    printf("|-Total number of TCP flows captured: %d\n", getTCPflows());
    printf("|-Total number of UDP flows captured: %d\n", getUDPflows());
    printf("|-Total number of packets received: %d\n", packets);
    printf("|-Total number of TCP packets received: %d\n", tcppackets);
    printf("|-Total number of UDP packets received: %d\n", udppackets);
    printf("|-Total bytes of TCP packets received: %ld\n", tcpbytes);
    printf("|-Total bytes of UDP packets received: %ld\n", udpbytes);
}


void printHelp() {
    printf("Usage:\n");
    printf("-i <network_name> Select the network interface name (e.g.,eth0)\n");
    printf("-r <packet_capture_name>: Packet capture filename (e.g., test.pcap\n");
    printf("-f <port>: Filter expression in string format (e.g., port 8080\n");
    printf("-h: Display help\n");
}


void add_network_flow(char *source_ip, char *destination_ip, unsigned int source_port, unsigned int destination_port, unsigned int protocol) {
    // Check if the flow already exists
    for (int i = 0; i < netflows; i++) {
        if (strcmp(source_ip, network_flows[i].source_ip) == 0 &&
            strcmp(destination_ip, network_flows[i].destination_ip) == 0 &&
            source_port == network_flows[i].source_port &&
            destination_port == network_flows[i].destination_port &&
            protocol == network_flows[i].protocol) {
            // The flow already exists, so don't add it again
            //printf("Flow already exists.\n");
            return;
        }
    }

    // If the flow doesn't exist, add it to the array
    if (netflows < sizeof(network_flows) / sizeof(network_flows[0])) {
        network_flows[netflows].source_ip = strdup(source_ip);
        network_flows[netflows].destination_ip = strdup(destination_ip);
        network_flows[netflows].source_port = source_port;
        network_flows[netflows].destination_port = destination_port;
        network_flows[netflows].protocol = protocol;

        // Increment the counter
        netflows++;
    } else {
        printf("Array is full. Cannot add more flows.\n");
    }
}


int find_retransmissions(const u_char * Buffer, int Size)
{
    static struct iphdr  previous_packets[20000];
    static struct tcphdr  previous_tcp[20000];
    static int index = 0;
    static int retransmissions = 0;
    int retransmission = 0;
    
    struct sockaddr_in source,dest;
    unsigned short iphdrlen;
    
    // IP header
    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    previous_packets[index] = *iph;
    
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;
    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    // TCP header
    struct tcphdr *tcph=(struct tcphdr*)(Buffer 
                                  + iphdrlen 
                                  + sizeof(struct ethhdr));
    previous_tcp[index]=*tcph;
    index++;
    
    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
    unsigned int segmentlength;
    segmentlength = Size - header_size;
    
    /* First check if a same TCP packet has been received */
    for(int i=0;i<index-1;i++)
    {
        // Check if packet has been resent
        unsigned short temphdrlen;
        temphdrlen = previous_packets[i].ihl*4;
        
        // First check IP header
        if ((previous_packets[i].saddr == iph->saddr) // Same source IP address
            && (previous_packets[i].daddr == iph->daddr) // Same destination Ip address
            && (previous_packets[i].protocol == iph->protocol) //Same protocol
            && (temphdrlen == iphdrlen)) // Same header length
        {
            // Then check TCP header
            if((previous_tcp[i].source == tcph->source) // Same source port
                && (previous_tcp[i].dest == tcph->dest) // Same destination port
                && (previous_tcp[i].th_seq == tcph->th_seq) // Same sequence number
                && (previous_tcp[i].th_ack==tcph->th_ack) // Same acknowledge number
                && (previous_tcp[i].th_win == tcph->th_win) // Same window
                && (previous_tcp[i].th_flags == tcph->th_flags) // Same flags
                && (tcph->syn==1 || tcph->fin==1 ||segmentlength>0)) // Check if SYN or FIN are
            {                                                        // set or if tcp.segment 0
                // At this point the packets are almost identical
                //  Now Check previous communication to check for retransmission
                for(int z=index-1;z>=0;z--)
                {   
                    // Find packets going to the reverse direction
                    if ((previous_packets[z].daddr == iph->saddr) // Swapped IP source addresses
                        && (previous_packets[z].saddr ==iph->daddr) // Same for IP dest addreses
                        && (previous_packets[z].protocol == iph->protocol)) // Same protocol
                    {
                        if((previous_tcp[z].dest==tcph->source) // Swapped ports
                            && (previous_tcp[z].source==tcph->dest)
                            && (previous_tcp[z].th_seq-1 != tcph->th_ack) // Not Keepalive
                            && (tcph->syn==1          // Either SYN is set
                                || tcph->fin==1       // Either FIN is set
                                || (segmentlength>0)) // Either segmentlength >0 
                            && (previous_tcp[z].th_seq>tcph->th_seq) // Next sequence number is 
                                                                     // bigger than the expected 
                            && (previous_tcp[z].ack  != 1))  // Last seen ACK is set
                        {
                            retransmission = 1;
                            retransmissions++;
                            break;
                        }
                    }
                }
            }
        }
    }
    
    if (retransmission == 1) {return 1;} else {return 0;}
}


void tcp_process(const struct ip *ip_header, const struct ip6_hdr *ip6_header, int ip_type, const unsigned char *packet, const struct pcap_pkthdr *pkthdr){
    // if ipv4
    if (ip_type == 0) {
        // Cast to TCP header
        struct tcphdr *tcp_header = (struct tcphdr *)((char *)ip_header + (ip_header->ip_hl * 4));
        // Check if the destination port matches the filter_port
        if (filter_port == 0 || ntohs(tcp_header->th_dport) == filter_port) {
            if (flag == 0) {
                // Offline mode
                printf("\n\nNew packet\n");
                printf("Protocol: TCP\n");
                printf("IP Version: IPV4\n");
                printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
                printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
                printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));
                printf("TCP Header Length: %d bytes\n", (tcp_header->doff * 4)); 
                printf("TCP Payload Length: %d bytes\n", ntohs(ip_header->ip_len) - (tcp_header->doff * 4) - (ip_header->ip_hl * 4));
                if (find_retransmissions(packet, pkthdr->len) == 1) {
                    printf("Retransmission: True");
                } else {
                    printf("Retransmission: False");
                }
                add_network_flow(inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport), 0);
                tcpbytes += (ip_header->ip_hl * 4);  
            } else if (flag ==1){
                //Online mode
                FILE *log_file = fopen("log.txt", "a");
                fprintf(log_file, "\n\nNew packet\n");
                fprintf(log_file, "Protocol: TCP\n");
                fprintf(log_file, "IP Version: IPV4\n");
                fprintf(log_file, "Source IP: %s\n", inet_ntoa(ip_header->ip_src));
                fprintf(log_file, "Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
                fprintf(log_file, "Source Port: %u\n", ntohs(tcp_header->th_sport));
                fprintf(log_file, "Destination Port: %u\n", ntohs(tcp_header->th_dport));
                fprintf(log_file, "TCP Header Length: %d bytes\n", (tcp_header->doff * 4)); 
                fprintf(log_file, "TCP Payload Length: %d bytes\n", ntohs(ip_header->ip_len) - (tcp_header->doff * 4) - (ip_header->ip_hl * 4));
                if (find_retransmissions(packet, pkthdr->len) == 1) {
                    fprintf(log_file, "Retransmission: True");
                } else {
                    fprintf(log_file, "Retransmission: False");
                }
                fclose(log_file);
                add_network_flow(inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport), 0);
                tcpbytes += (ip_header->ip_hl * 4);            
            }
        }
    } else {
        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];
        struct tcphdr *tcp_header = (struct tcphdr *)(ip6_header + 1);  // Assuming there are no extension headers
        if (filter_port == 0 || ntohs(tcp_header->th_dport) == filter_port) {
            if (flag == 0)  {
                // Process the packet
                printf("\n\nNew packet\n");
                printf("Protocol: TCP \n");
                printf("IP Version: IPv6\n");
                inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);    
                inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);
                printf("Source IP: %s\n", src_ip_str);
                printf("Destination IP: %s\n", dst_ip_str);
                printf("Source Port: %u\n", ntohs(tcp_header->th_sport));
                printf("Destination Port: %u\n", ntohs(tcp_header->th_dport));
                printf("TCP Header Length: %d bytes\n", (tcp_header->doff * 4)); 
                printf("TCP Payload Length: %d bytes\n", ntohs(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen) - (tcp_header->doff * 4));
                if (find_retransmissions(packet, pkthdr->len) == 1) {
                    printf("Retransmission: True");
                } else {
                    printf("Retransmission: False");
                }
                add_network_flow(src_ip_str, dst_ip_str, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport), 0);
                tcpbytes += sizeof(struct ip6_hdr); 
            } else if (flag == 1) {
                // Online mode
                FILE *log_file = fopen("log.txt", "a");
                fprintf(log_file, "\n\nNew packet\n");
                fprintf(log_file, "Protocol: TCP \n");
                fprintf(log_file, "IP Version: IPv6\n");
                inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);    
                inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);
                fprintf(log_file, "Source IP: %s\n", src_ip_str);
                fprintf(log_file, "Destination IP: %s\n", dst_ip_str);
                fprintf(log_file, "Source Port: %u\n", ntohs(tcp_header->th_sport));
                fprintf(log_file, "Destination Port: %u\n", ntohs(tcp_header->th_dport));
                fprintf(log_file, "TCP Header Length: %d bytes\n", (tcp_header->doff * 4)); 
                fprintf(log_file, "TCP Payload Length: %d bytes\n", ntohs(ip6_header->ip6_ctlun.ip6_un1.ip6_un1_plen) - (tcp_header->doff * 4));
                if (find_retransmissions(packet, pkthdr->len) == 1) {
                    fprintf(log_file, "Retransmission: True");
                } else {
                    fprintf(log_file, "Retransmission: False");
                }
                fclose(log_file);
                add_network_flow(src_ip_str, dst_ip_str, ntohs(tcp_header->th_sport), ntohs(tcp_header->th_dport), 0);
                tcpbytes += sizeof(struct ip6_hdr);

            }
        }
    }
}

void udp_process(const struct ip * ip_header, const struct ip6_hdr *ip6_header, int ip_type, const unsigned char *packet, const struct pcap_pkthdr *pkthdr){
    // If ipv4
    if (ip_type == 0) {
        // Cast to UDP header
        struct udphdr *udp_header = (struct udphdr *)((char *)ip_header + (ip_header->ip_hl * 2));
        // Check if the destination port matches the filter_port
        if (filter_port == 0 || ntohs(udp_header->uh_dport) == filter_port) {
            if (flag == 0) {
                // Offline mode
                printf("\n\nNew packet\n");
                printf("Protocol: UDP\n");
                printf("IP Version: IPV4\n");
                printf("Source IP: %s\n", inet_ntoa(ip_header->ip_src));
                printf("Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
                printf("Source Port: %u\n", ntohs(udp_header->uh_sport));
                printf("Destination Port: %u\n", ntohs(udp_header->uh_dport));
                printf("UDP Header Length: %ld bytes\n", sizeof(struct udphdr));
                printf("UDP Payload Length: %ld bytes\n", ntohs(udp_header->uh_ulen) - sizeof(struct udphdr));  
                add_network_flow(inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport), 1);
                udpbytes += (ip_header->ip_hl * 4);  
            } else if (flag == 1) {
                // Online mode
                FILE *log_file = fopen("log.txt", "a");
                fprintf(log_file, "\n\nNew packet\n");
                fprintf(log_file, "Protocol: UDP\n");
                fprintf(log_file, "IP Version: IPV4\n");
                fprintf(log_file, "Source IP: %s\n", inet_ntoa(ip_header->ip_src));
                fprintf(log_file, "Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
                fprintf(log_file, "Source Port: %u\n", ntohs(udp_header->uh_sport));
                fprintf(log_file, "Destination Port: %u\n", ntohs(udp_header->uh_dport));
                fprintf(log_file, "UDP Header Length: %ld bytes\n", sizeof(struct udphdr));
                fprintf(log_file, "UDP Payload Length: %ld bytes\n", ntohs(udp_header->uh_ulen) - sizeof(struct udphdr)); 
                fclose(log_file); 
                add_network_flow(inet_ntoa(ip_header->ip_src), inet_ntoa(ip_header->ip_dst), ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport), 1);
                udpbytes += (ip_header->ip_hl * 4);  
            }
    
        } 
    } else {
        char src_ip_str[INET6_ADDRSTRLEN];
        char dst_ip_str[INET6_ADDRSTRLEN];
        struct udphdr *udp_header = (struct udphdr *)(ip6_header + 1);  // Assuming there are no extension headers
        if (filter_port == 0 || ntohs(udp_header->uh_dport) == filter_port) {
            if (flag == 0) {
                // Offline mode
                printf("\n\nNew packet\n");
                printf("Protocol: UDP\n");
                printf("IP Version: IPV6\n");
                inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);    
                inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);
                printf("Source IP: %s\n", src_ip_str);
                printf("Destination IP: %s\n", dst_ip_str);
                printf("Source Port: %u\n", ntohs(udp_header->uh_sport));
                printf("Destination Port: %u\n", ntohs(udp_header->uh_dport));
                printf("UDP Header Length: %lu bytes\n", sizeof(struct udphdr));
                printf("UDP Payload Length: %lu bytes\n", ntohs(udp_header->uh_ulen) - sizeof(struct udphdr));
                add_network_flow(src_ip_str, dst_ip_str, ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport), 1);
                udpbytes += sizeof(struct ip6_hdr);
            } else if (flag == 1) {
                // Online mode
                FILE *log_file = fopen("log.txt", "a");
                fprintf(log_file, "\n\nNew packet\n");
                fprintf(log_file, "Protocol: UDP\n");
                fprintf(log_file, "IP Version: IPV6\n");
                inet_ntop(AF_INET6, &(ip6_header->ip6_src), src_ip_str, INET6_ADDRSTRLEN);    
                inet_ntop(AF_INET6, &(ip6_header->ip6_dst), dst_ip_str, INET6_ADDRSTRLEN);
                fprintf(log_file, "Source IP: %s\n", src_ip_str);
                fprintf(log_file, "Destination IP: %s\n", dst_ip_str);
                fprintf(log_file, "Source Port: %u\n", ntohs(udp_header->uh_sport));
                fprintf(log_file, "Destination Port: %u\n", ntohs(udp_header->uh_dport));
                fprintf(log_file, "UDP Header Length: %lu bytes\n", sizeof(struct udphdr));
                fprintf(log_file, "UDP Payload Length: %lu bytes\n", ntohs(udp_header->uh_ulen) - sizeof(struct udphdr));
                fclose(log_file);
                add_network_flow(src_ip_str, dst_ip_str, ntohs(udp_header->uh_sport), ntohs(udp_header->uh_dport), 1);
                udpbytes += sizeof(struct ip6_hdr);
            }  
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
        packets++;
        // Check if udp or tcp
        if (ip_header->ip_p == IPPROTO_TCP){
            tcp_process(ip_header, ip6_header, 0, packet, pkthdr);
            tcppackets++;
        } else if (ip_header->ip_p == IPPROTO_UDP){
            udp_process(ip_header, ip6_header, 0, packet, pkthdr);
            udppackets++;
        }
    } else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6){
        // Cast to IP6 header
        ip6_header = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
        packets++;
        // Check if udp or tcp
        if (ip6_header->ip6_nxt == IPPROTO_TCP) {
            tcp_process(ip_header, ip6_header, 1, packet, pkthdr); 
            tcppackets++;
        } else if (ip6_header->ip6_nxt == IPPROTO_UDP) {
            udp_process(ip_header, ip6_header, 1, packet, pkthdr);  
            udppackets++;
        }
    }

}


int online_monitor(char *interface_name) {
    char errbuf[PCAP_ERRBUF_SIZE];
    // Handle for the pcap session
    pcap_t *handle; 

    // Check if filter is given 
    if (filter) {
        char *port_str = strstr(filter, "port ");
        if (port_str != NULL) {
            // Skip "port " and convert the remaining string to an integer
            filter_port = atoi(port_str + 5);
        }
        //printf("filter port: %d", filter_port);
    }  

    handle = pcap_open_live(interface_name, BUFSIZ, 1, 1000, errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open device %s: %s\n", interface_name, errbuf);
        return 1;
    }

    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}

int offline_monitor(const char *filename){
    char errbuf[PCAP_ERRBUF_SIZE];
    // Handle for the pcap session
    pcap_t *handle; 

    handle = pcap_open_offline(filename,errbuf);

    if (handle == NULL) {
        fprintf(stderr, "Could not open file %s: %s\n", filename, errbuf);
        return 1;
    }
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);

    return 0;
}


int main(int argc, char *argv[]) {
    int opt;
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
        
        //printf("interface: %s, filter: %s", interface_name, filter);
        print_stats();
        return 0;
    } else if (flag == 0){
        offline_monitor(file_name);
        
        //printf("filename: %s", file_name);
        print_stats();
        return 0;
    } else {
        printf("Unknown option or missing argument: %c\n", optopt);
        printHelp();
        return 1;
    }


}