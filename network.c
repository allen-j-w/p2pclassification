/*
 ============================================================================
 Name        : network.c
 Author      : 
 Version     :
 Copyright   : Your copyright notice
 Description : Hello World in C, Ansi-style
 ============================================================================
 */

#include <stdio.h>
#include <stdlib.h>
#include "hashtab.h"
#include <pcap.h>
#define maxHash 10007

hashtab* hashtable;

void process(pcap_t* pcap, unsigned int numberpkt, unsigned int timewindow)
{
	const u_char *pkt;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;
	struct ip *ip_hdr;
	struct udphdr *udp_hdr;

	int num = 0;
	unsigned long long starttime;
	unsigned long long endtime;
	unsigned long long pkttimestamp;

	while (pkt = pcap_next(pcap,  &hdr))
	{

		eptr = (struct ether_header *) pkt;
		pkttimestamp =(unsigned long long) hdr.ts.tv_sec * 1000000 + (unsigned long long) hdr.ts.tv_usec;

		struct iphdr* ip_hdr = (struct iphdr*)(pkt+14);

		if(ip_hdr->protocol == IPPROTO_UDP)
		{
			num++;
			insert(hashtable, ip_hdr, &hdr.ts, numberpkt, timewindow);
		}
	}
}



int main(int argc, char** argv)
{
	int opt;
	char* pcapFile;
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned int numberpkt = 0;
	unsigned int timewindow = 0;

	//initialize hash table

    hashtable = initializeHash(hashtable, maxHash);

    while ((opt = getopt(argc, argv, "f:n:w:")) != EOF)
    {
    	switch (opt)
		{
			case 'f':
				pcapFile = optarg;
				break;
			case 'n':
				if(atoi(optarg) > 0)
				{
					numberpkt = atoi(optarg);
					break;
				}
				else
				{
					printf("n must be positive.\n");
					exit(0);
				}
			case 'w':
				if(atoi(optarg) > 0)
				{
					timewindow = atoi(optarg);
					break;
				}
				else
				{
					printf("w must be positive.\n");
					exit(0);
				}
			case '?':
				printf("only two parameters, n and w are avilable.");
				exit(0);
		}
    }

    if(numberpkt == 0 || timewindow == 0)
    {
    	printf("two paramters n and w which are all positive are needed.\n");
       	exit(0);
    }

	if (pcapFile == NULL || strcmp(pcapFile, "") == 0)
	{
		printf("ERROR: no pcap file path provided; use option -f with the path to a valid pcap file\n");
		exit(-1);
	}

	if((pcap = pcap_open_offline(pcapFile, errbuf)) == NULL)
	{
		printf("%s\n", errbuf);
		printf("ERROR in opening pcap file.\n");
		exit(-1);
	}

	process(pcap, numberpkt, timewindow);
    return 0;
}
