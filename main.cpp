#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>

void usage() {
	printf("syntax: arp_send <interface> <send ip> <target ip>\n");
	printf("sample: arp_send wlan0 <192.168.43.117> <192.168.43.1>\n");
}

void print_ip(u_char *ip_addr) {
	int i;
	for(i=0;i<4;i++) {
		printf("%d%c",ip_addr[i],i==3?'\n':'.');
	}
}

void print_mac(u_char *mac_addr) {
	int i;
	for(i=0;i<6;i++) {
		printf("%02x%c",mac_addr[i],i==5?'\n':':');
	}
}

void print_packet(u_char *packet,int size) {
	int i;
	for(i=0;i<size;i++) {
		printf("%02x%s",packet[i],i%16==15?"\n":i%8==7?"  ":" ");
	}
	printf("\n");
}

void input_arp(u_char *packet, const void *text,int t_size, int *p_pos) {
	memcpy(packet+*p_pos,text,t_size);
	*p_pos+=t_size;
}

int getIPnMACaddr(char *interface, u_char *ip_addr, u_char *mac_addr) {
	int sock;
	struct ifreq ifr={0};
	struct sockaddr_in *sin;
	u_char *mac = NULL;
	
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("no socket\n");
		return 0;
	}

	strcpy(ifr.ifr_name, interface);
	if (ioctl(sock, SIOCGIFADDR, &ifr)< 0) { //get IP address
		printf("getIP failed\n");
		//close(sock);
		return 0;
	}
	sin = (struct sockaddr_in*)&ifr.ifr_addr;
	/*
	uint32_t temp;
	memcpy(&temp, (const void *)(&(sin->sin_addr)),4);
	memcpy(ip_addr,(const void *)&temp,4);	*/
	memcpy(ip_addr, (const void *)(&(sin->sin_addr)),4);
	
	if (ioctl(sock, SIOCGIFHWADDR, &ifr)< 0) { //get MAC address
		printf("getMAC failed\n");
		//close(sock);
		return 0;
	}
	mac = (u_char *)ifr.ifr_hwaddr.sa_data;
	memcpy(mac_addr,mac,6);
	
	//close(sock);
	return 1;
}

int makeARPpacket(u_char *packet, u_char *dest_mac,u_char *src_mac, u_char *dest_ip, u_char *src_ip, int opcode) {
	//ethernet structures : 
	//dest mac(6B) src mac(6B) ethtype(2B) ->tot. 14B Ethernet header
	//hardware type(2B) protocol type(2B) HW size, PT size(2B) OPcode(2B) ->8B
	//sender MAC,IP(10B) target MAC,IP(10B) ->20B
	int st=0;
	//ethernet header
	//sprintf(packet,"%s%s%s",dest_mac,src_mac,"\x08\x06");
	input_arp(packet,dest_mac,6,&st);
	input_arp(packet,src_mac,6,&st);
	input_arp(packet,"\x08\x06",2,&st);
	
	//ARP header
	//sprintf(packet+14,"%s%s","\x00\x01\x08\x00\x06\x04",opcode==1?"\x00\x01":"\x00\x02");
	input_arp(packet,"\x00\x01\x08\x00\x06\x04",6,&st);
	input_arp(packet,opcode==1?"\x00\x01":"\x00\x02",2,&st);
	input_arp(packet,src_mac,6,&st);
	input_arp(packet,src_ip,4,&st);
	if(memcmp(dest_mac,"\xff\xff\xff\xff\xff\xff",6)==0) {
		input_arp(packet,"\x00\x00\x00\x00\x00\x00",6,&st);
	}
	else input_arp(packet,dest_mac,6,&st);
	input_arp(packet,dest_ip,4,&st);
	return st;
}

int main(int argc, char* argv[]) {
  if (argc != 4) {
    char c=0;
    printf("default interface name : enp0s3, okay? y/n\n");
    scanf("%c",&c);
    if(c=='y') {
      argv[1]="enp0s3";
    }
    else {
      usage();
      return -1;
    }
  }

	char* dev = argv[1];
	u_char srcIP[4], srcMAC[6];
	u_char sendIP[4], sendMAC[6];
	struct in_addr temp;
	
	inet_aton(argv[2],&temp);
	getIPnMACaddr(dev,srcIP,srcMAC);
	memcpy(sendIP,&temp,4);
	print_ip(sendIP);
	print_ip(srcIP);
	memcpy(sendMAC,"\xff\xff\xff\xff\xff\xff",6);
	
	u_char packet[50];
	int packet_size = makeARPpacket(packet,sendMAC,srcMAC,sendIP,srcIP,1);
	printf("%d\n",packet_size);
	print_packet(packet,packet_size);	
	return 0;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
    printf("src MAC : ");
    for(int i=6;i<12;i++) { printf("%02x ",packet[i]);}
    printf("\n");
    printf("dest MAC : ");
    for(int i=0;i<6;i++) { printf("%02x ",packet[i]);}
    printf("\n");
    uint16_t eth_type = (packet[12]<<8) + packet[13];
    printf("type : %04x\n",eth_type);

  }



  pcap_close(handle);
  return 0;
}
