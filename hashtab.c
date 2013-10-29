/*
 * hashtab.c
 *
 *  Created on: May 4, 2011
 *      Author: lucus
 */

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include "hashtab.h"

#ifndef MALLOC
#define MALLOC(r, t, c)		((r) = (t *) malloc(sizeof(t)*(c)))
#define FREE(r)			do { free(r); (r) = 0; } while (0)
#endif


unsigned long long computeHash(struct iphdr* ip_hdr)
{
	struct udphdr* udp;
	udp = (struct udphdr*) (((uint8_t*)ip_hdr) + ip_hdr->ihl*4);
	return ((unsigned long long)ntohl(ip_hdr->daddr) * 100000 + ntohs(udp->dest));
}

udpType** findslot(hashtab* table, unsigned long long key)
{
	return table->list + (key%table->size);
}

void fillUdp(udpType* udp, struct iphdr* ip_hdr, struct timeval* time)
{
	struct udphdr* udp_hdr;
	udpSource* udpsource;
	packet* pkt;
	udp_hdr = (struct udphdr*) (((uint8_t*)ip_hdr) + ip_hdr->ihl*4);

	udp->packetNum = 1;
	udp->dAddr = ntohl(ip_hdr->daddr);
	udp->dport = ntohs(udp_hdr->dest);
	udp->nextUdp = 0;
	udp->starttime = (unsigned long long)time->tv_sec * 1000000 + time->tv_usec;

	MALLOC(udpsource, udpSource, 1);
	udpsource->saddr = ntohl(ip_hdr->saddr);
	udpsource->sport = ntohs(udp_hdr->source);
	udpsource->next = 0;

	MALLOC(pkt, packet, 1);
	fillPacket(pkt, udp_hdr, time);
	udpsource->firstpacket = pkt;
	udpsource->lastpacket = pkt;

	udp->udpsource = udpsource;
}

void fillPacket(packet* pkt, struct udphdr* udp_hdr, struct timeval* time)
{
	pkt->timeStamp =(unsigned long long)time->tv_sec * 1000000 + time->tv_usec;
	pkt->packetSize = ntohs(udp_hdr->len);
	pkt->nextPacket = 0;
	pkt->prePacket = 0;
}


boolean compareUdp(udpType* udp, unsigned long long hashcode)
{
	if(udp == NULL)
		return FALSE;
	unsigned long long temp =(unsigned long long) udp->dAddr * 100000 + udp->dport;

	if(temp == hashcode)
		return TRUE;
	else
		return FALSE;
}

boolean compareUdpSource(udpSource* udpsource, u_long saddr, u_int16_t source)
{
	if(udpsource == NULL)
		return FALSE;
	if(udpsource->saddr == saddr && udpsource->sport == source)
		return TRUE;
	else
		return FALSE;
}

void emptyUDP(udpType* udp)
{
	udpSource* udpsource = udp->udpsource;
	udpSource* postudpsource;
	packet* pkt;
	packet* tmppkt;
	while(udpsource != NULL)
	{
		postudpsource = udpsource->next;
		pkt = udpsource->lastpacket;
		while(pkt != NULL)
		{
			tmppkt = pkt->prePacket;
			free(pkt);
			pkt = tmppkt;
		}
		free(udpsource);
		udpsource = postudpsource;
	}
	udp->starttime = 0;
	udp->packetNum = 0;
}

void printUDP(udpType* udp)
{
	udpSource* udpsource = udp->udpsource;
	packet* pkt;
	packet* tmppkt;
	int a,b,c,d;
	int e,f,g,h;

	e = udp->dAddr>>24;
	f = (udp->dAddr & 0x00FFFFFF)>>16;
	g = (udp->dAddr & 0x0000FFFF)>>8;
	h = (udp->dAddr & 0x000000FF);
	while(udpsource != NULL)
	{
		printf("%d.%d.%d.%d %d ", e, f, g, h, udp->dport);
		a = udpsource->saddr>>24;
		b = (udpsource->saddr & 0x00FFFFFF)>>16;
		c = (udpsource->saddr & 0x0000FFFF)>>8;
		d = (udpsource->saddr & 0x000000FF);
		printf("%d.%d.%d.%d %d ", a, b, c, d, udpsource->sport);
		pkt = udpsource->lastpacket;
		while(pkt != NULL)
		{
			tmppkt = pkt->prePacket;
			if(tmppkt == NULL)
				printf("%d ", pkt->packetSize);
			else
				printf("%d %lld ", pkt->packetSize, tmppkt->timeStamp - pkt->timeStamp);
			pkt = tmppkt;
		}
		printf("\n");
		udpsource = udpsource->next;
	}
	printf("%d packets in this timewindow.\n", udp->packetNum);
}

void flushUDP(udpType* udp, unsigned int numberpkt)
{
	if(udp->packetNum > numberpkt)
	{
		printUDP(udp);
		emptyUDP(udp);
	}
	else
	{
		emptyUDP(udp);
	}
}

void insert(hashtab* table, struct iphdr* ip_hdr, struct timeval* time, unsigned int numberpkt, unsigned int timewindow)
{
	unsigned long long hashcode = computeHash(ip_hdr);
	udpType** slot = findslot(table, hashcode);
	if(*slot == NULL)
	{
		MALLOC(*slot, udpType, 1);
		fillUdp(*slot, ip_hdr, time);
	}
	else
	{
		udpType* tmp = *slot;
		while(!compareUdp(tmp, hashcode) && tmp != NULL)
		{
			tmp = tmp->nextUdp;
		}
		if(tmp == NULL)
		{
			MALLOC(tmp, udpType, 1);
			fillUdp(tmp, ip_hdr, time);
			tmp->nextUdp = (*slot)->nextUdp;
			(*slot)->nextUdp = tmp;
		}
		else
		{
			if((unsigned long long)time->tv_sec * 1000000 + time->tv_usec < tmp->starttime + timewindow)
			{
				struct udphdr* udp_hdr;
				udp_hdr = (struct udphdr*) (((uint8_t*)ip_hdr) + ip_hdr->ihl*4);
				udpSource* udpsource = (tmp->udpsource);
				while(!compareUdpSource(udpsource, ntohl(ip_hdr->saddr), ntohs(udp_hdr->source)) && udpsource != NULL)
				{
					udpsource = udpsource->next;
				}
				if(udpsource == NULL)
				{
					MALLOC(udpsource, udpSource, 1);
					udpsource->saddr = ntohl(ip_hdr->saddr);
					udpsource->sport = ntohs(udp_hdr->source);
					udpsource->next = 0;

					packet* pkt;
					MALLOC(pkt, packet, 1);
					fillPacket(pkt, udp_hdr, time);
					udpsource->firstpacket = pkt;
					udpsource->lastpacket = pkt;

					udpsource->next = tmp->udpsource;
					tmp->udpsource = udpsource;
				}
				else
				{
					packet* tmppkt;
					MALLOC(tmppkt, packet, 1);
					fillPacket(tmppkt, udp_hdr, time);
					tmppkt->nextPacket = udpsource->firstpacket;
					udpsource->firstpacket->prePacket = tmppkt;
					udpsource->firstpacket = tmppkt;
				}
				tmp->packetNum++;
			}
			else
			{
				flushUDP(tmp, numberpkt);
				struct udphdr* udp_hdr;
				udp_hdr = (struct udphdr*) (((uint8_t*)ip_hdr) + ip_hdr->ihl*4);
				udpSource* udpsource;
				packet* tmppkt;
				MALLOC(udpsource, udpSource, 1);
				udpsource->saddr = ntohl(ip_hdr->saddr);
				udpsource->sport = ntohs(udp_hdr->source);
				udpsource->next = 0;

				MALLOC(tmppkt, packet, 1);
				fillPacket(tmppkt, udp_hdr, time);

				tmp->udpsource = udpsource;
				udpsource->firstpacket = tmppkt;
				udpsource->lastpacket = tmppkt;
				tmp->starttime = (unsigned long long)time->tv_sec * 1000000 + time->tv_usec;
				tmp->packetNum++;
			}
		}
	}
}

hashtab* initializeHash(hashtab* hash, long size)
{
	unsigned long i;
	udpType** tmp;
	MALLOC(hash, hashtab, 1);
	if(!hash)
	{
		printf("initialize hash failed.\n");
		exit(0);
	}
	MALLOC(hash->list, udpType*, size);
	if(!hash->list)
	{
		printf("initialize hash failed.\n");
		exit(0);
	}
	tmp = hash->list;
	for(i = 0; i < size; i++, tmp++)
	{
		hash->list[i] = NULL;
	}
	hash->size = size;
}
