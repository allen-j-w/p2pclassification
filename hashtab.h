/*
 * hashtab.h
 *
 *  Created on: May 4, 2011
 *      Author: lucus
 */

#ifndef HASHTAB_H_
#define HASHTAB_H_

#include <unistd.h>
#include <sys/time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
typedef struct _packet
{
	unsigned long long timeStamp;
	int packetSize;
	struct packet* nextPacket;
	struct packet* prePacket;
}packet;

typedef struct _udpSource
{
	u_long saddr;
	u_int16_t sport;
	packet* firstpacket;
	packet* lastpacket;

	struct udpSource* next;
}udpSource;

typedef struct _udpType
{
	unsigned int packetNum;
	unsigned long long starttime;

	u_long dAddr;
	u_int16_t dport;
	struct udpType* nextUdp;
	struct udpSource* udpsource;
}udpType;


typedef enum _bool
{
	FALSE = 0,
	TRUE = 1
}boolean;

typedef struct _hashtab
{
	int size;
	udpType** list;
}hashtab;

extern unsigned long long computeHash(struct iphdr* ip_hdr);
extern void insert(hashtab* table, struct iphdr* ip_hdr, struct timeval* time, unsigned int numberpkt, unsigned int timewindow);
extern udpType* findSlot(hashtab* table, unsigned long long key);
extern void fillPacket(packet* pkt, struct udphdr* udp_hdr, struct timeval* time);
extern void fillUdp(udpType* udp, struct iphdr* ip_hdr, struct timeval* time);
extern hashtab* initializeHash(hashtab* hash, long size);
extern boolean compareUdp(udpType* udp, unsigned long long hashcode);


#endif /* HASHTAB_H_ */
