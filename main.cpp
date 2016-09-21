#include <netinet/in.h> 

#include <pcap.h>       g

#include <stdio.h>

#include <stdlib.h>

#include <netinet/ether.h>

#include <netinet/ip.h>

#include <netinet/tcp.h>

#include <arpa/inet.h>

#include "libnet-headers.h"

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet);



int main(int argc, char **argv)

{
    char *dev;
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t *pcd;

    dev = pcap_lookupdev(errbuf);


    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }

    
    pcd = pcap_open_live(dev, BUFSIZ,  1/*PROMISCUOUS*/, -1, errbuf);

    if (pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    pcap_loop(pcd, 0, callback, NULL);
}

void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet )
{
	struct libnet_ethernet_hdr * eth_hdr;
	struct libnet_ipv4_hdr * ip_hdr;
 	struct libnet_tcp_hdr * tcp_hdr;

	int i, Data_len;


	

	eth_hdr = (struct libnet_ethernet_hdr*)packet;
	printf("src MAC:%s\n", ether_ntoa(eth_hdr->ether_shost));
	printf("dst MAC:%s\n", ether_ntoa(eth_hdr->ether_dhost));

	if(ntohs(eth_hdr->ether_type)!=0x0800)
	{
		printf("IP use X"\n");
		return;
	}
	
	ip_hdr =(struct libnet_ipv4_hdr *)(packet+14);
	printf("src IP:%s\n", inet_ntoa(ip_hdr->ip_src));
	printf("dst IP:%s\n", inet_ntoa(ip_hdr->ip_dst));

	if(ip_hdr->ip_p != 0x06)
	{
		printf("TCP use X"\n");
		return;
	}	

 	tcp_hdr =(struct libnet_tcp_hdr *)(packet+14+4*(ip_hdr->ip_hl));
	printf("Src port: %d\n", ntohs(tcp_hdr->th_sport));
    	printf("Dst port: %d\n", ntohs(tcp_hdr->th_dport));
	

	Data_len = pkthdr->caplen-14-4*(ip_hdr->ip_hl)-4*(tcp_hdr->th_off);
	
	printf("Data:\n");
	for(i=0;i< Data_len;i++)
	{
		printf("%02x ", packet[14+4*(ip_hdr->ip_hl)+4*(tcp_hdr->th_off)+i];
	}
	printf("\n\n");

}

