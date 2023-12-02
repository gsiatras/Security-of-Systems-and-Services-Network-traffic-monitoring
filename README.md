# Network traffic monitoring using the Packet Capture library
Developed by Georgios Michail Siatras and Andreas Karogiannis		

TUC: Security of Systems and Services				

Proffessor: Sotirios Ioannidis					

***Network traffic monitoring tool***					
The tool was created following the given instructions.					

**Use:**				
sudo ./pcap_ex -i interface_name -f "port port_id" (optional)				
sudo ./pcap_ex -r file_name			
		
**online_monitor**
Inputs: 				
interface_name (char)				
1. extract the port_id from the string if port given.			
2. Start capturing packets from the interface given.			
		
**packet_handler**		

Inputs:				

user: (char)	

pcap_pkthdr: information about the captured packet		

packet: packet itself				

1. casts the raw packet data (packet) to a structure (struct ether_header) representing the Ethernet header.		
2. Check if IPV4//IPV6				
3. Raise packets counter			
4. Check if TCP//UDP			
5. Call the appropriate function with the appropriate arguments to handle each packet.			

**tcp_process**
Inputs:		
ip_header: IPV4 header
ip6_header: IPV6 header
ip_type: (int) 0 => use the IPV4 header as packet is IPV4 packet, 1 => use IPV6 header as packet is IPV6 packet.
packet: packet itself
pkthdr: header containing information for the packet (used to find retransmisions)
1. Extract all the information of the packet, either print in console or in file depending on the flag(**flag==0 => online_mode** and **flag==1 => offline_mode**).
2. Find out if retransmition
3. Raise counters, store network flow

**udp_process**		

Inputs:			

ip_header: IPV4 header		

ip6_header: IPV6 header		

ip_type: (int) 0 => use the IPV4 header as packet is IPV4 packet, 1 => use IPV6 header as packet is IPV6 packet.		
packet: packet itself		

pkthdr: header containing information for the packet (used to find retransmisions)			

1. Extract all the information of the packet, either print in console or in file depending on the flag(**flag==0 => online_mode** and **flag==1 => offline_mode**).			
2. Finding retransmitions not implemented		
3. Raise counters, store network flow		

**add_network_flow**	

Input: 			

tuple <source_ip, destination_ip, source_port, destination_port, protocol>		

1. Check if another identical tupple already exists in the array (network_flows)			
2. If it doesnt add it to the array.			

**find_retransmitions**			

Inputs: 			

Buffer: packet itself			

Size: packet_header length			
			
Implenentation borrowed from: https://stackoverflow.com/questions/65238453/how-to-find-tcp-retransmissions-while-sniffing-packets-in-c			
Basically, it keeps track over the tcp packet traffic behaviour, checks if the same packet is being resent, sequence numbers not being in the right order, SYN, or FIN flags are raised. Seems to work well.





