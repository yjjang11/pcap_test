#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "libnet-headers.h"

int main(int argc, char *argv[])
{
	int i=0, Data_len=0; 
	
	pcap_t *handle;
	
	char *dev; 
	char errbuf[PCAP_ERRBUF_SIZE];
	
	struct pcap_pkthdr header;
	const u_char *packet;

	dev=pcap_lookupdev(errbuf);//device name
	
	if(dev==NULL)
	{
		printf("Couldn't find device:%s \n", errbuf);
		return(2);
	}
	printf("Device: %s\n", dev);
	
	
		
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);//make packet capture descriptor(PCD) for dev

	if (handle == NULL) 
	{
		printf("Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	while(1)
	{
		i=0, Data_len=0;
		
		packet = pcap_next(handle, &header);//grab a packet
		printf("jacked a packet wuth length of (%d)\n", header.len);

		struct libnet_ethernet_hdr * eth_hdr; 
		struct libnet_ipv4_hdr * ip_hdr; 
  		struct libnet_tcp_hdr * tcp_hdr; 

 		eth_hdr = (struct libnet_ethernet_hdr*)packet; 
		printf("src MAC:%s\n", ether_ntoa(eth_hdr->ether_shost)); 
		printf("dst MAC:%s\n", ether_ntoa(eth_hdr->ether_dhost)); 

		if(ntohs(eth_hdr->ether_type)!=0x0800) 
		{ 
			printf("Not IP\n"); 
 			continue; 
 		} 
 	 
 		ip_hdr =(struct libnet_ipv4_hdr *)(packet+14); 
 		printf("src IP:%s\n", inet_ntoa(ip_hdr->ip_src)); 
		printf("dst IP:%s\n", inet_ntoa(ip_hdr->ip_dst)); 
  
		if(ip_hdr->ip_p != 0x06) 
 		{ 
 			printf("Not TCP\n"); 
			continue; 
 		}	 
 
  		tcp_hdr =(struct libnet_tcp_hdr *)(packet+14+4*(ip_hdr->ip_hl)); 
		printf("Src port: %d\n", ntohs(tcp_hdr->th_sport)); 
     		printf("Dst port: %d\n", ntohs(tcp_hdr->th_dport)); 
	 
 		Data_len = header.len-14-4*(ip_hdr->ip_hl)-4*(tcp_hdr->th_off); 
 	 
 		printf("Data:\n"); 
 		for(i=0;i< Data_len;i++) 
 		{ 
			printf("%02x ", packet[14+4*(ip_hdr->ip_hl)+4*(tcp_hdr->th_off)+i]); 
 		} 
		printf("\n\n"); 
 
 	}

	pcap_close(handle);
	return(0);
}

