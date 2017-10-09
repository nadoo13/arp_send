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

void print_mac(u_char *mac_addr) {
	int i;
	for(i=0;i<6;i++) {
		printf("%02x%c",mac_addr[i],i==5?'\n':':');
	}
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
	strcpy((char *)ip_addr, inet_ntoa(sin->sin_addr));
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

int makeARPpacket(u_char dest_mac,u_char src_mac, u_char 

int main(int argc, char* argv[]) {
  if (argc != 2) {
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
	u_char IP[20]={0};
	u_char MAC[10]={0};
	getIPnMACaddr(dev,IP,MAC);
	printf("%s\n",IP);
	print_mac(MAC);
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
