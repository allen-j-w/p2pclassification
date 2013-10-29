#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <unistd.h>
#include <time.h>

#include "hashtab.h"
#include "model.h"
#include "classif.h"


#define ACTION_LABEL	0
#define ACTION_PARSE	1
#define FLOW_HASH_TABLE_SIZE	100000

#define STATS_TABLE_SIZE	100

#define NOOPTMEM	0
#define OPT_NOSTORE	1	//Remove connections when classified
#define OPT_GARBAGE	2	//Garbage collection

#define EXP_TIME	60	//Expiration time (seconds)
#define CLEAN_TIME	360	//Periodicity of garbage collection (seconds)

#define PRINTPKT 100000


typedef struct _flow {
/* flow key data */
	struct in_addr src;
	struct in_addr dst;
	uint16_t sport;
	uint16_t dport;

	int8_t label;		//Application Label
	int8_t labelSSL;	//Application Label inside SSL connection

	uint8_t isSSL;		//Is connection an SSL connection?
	uint8_t SSLdata;	//Have we seen the first SSL packet with payload?

	uint8_t data1;		//data seen on client side of the connection
	uint8_t data2;		//data seen on server side

	uint32_t nextseq;	//Next sequence number for TCP client
	uint32_t nextseqpeer;	//Next sequence number for TCP server

	uint8_t datapkts;	//Number of packets with payload
	int16_t *pkt_sizes;	//Array of first payload sizes

	uint32_t ts_latest;	//Timestamp of latest packet seen in this connection

	// operational data
	struct _flow *next, *prev;
} flow;

typedef struct _stats {
	uint16_t nbstats;
	uint32_t entries;
	uint32_t inserts;
	uint32_t timeidx[STATS_TABLE_SIZE];
	uint32_t creations[STATS_TABLE_SIZE];
	uint32_t deletions[STATS_TABLE_SIZE];
} stats_t;

typedef struct ssl {
	unsigned char	type;
	unsigned char	version;
	unsigned char	minor;
	#pragma pack(1)
	unsigned short  size;
} ssl_t;


static int (*labeling) (int cluster,int dport);
static int (*SSL_labeling) (int cluster,int dport);
int16_t threshold;
int pktlimit;

int sslparsing;
int action;
int memory;

hash_tab *flow_hash;

flow * active_flows;
flow * first_flow;
uint32_t nbflows;
stats_t stats; 

/* return 0 if the same - for use by the hashtable */
static int compare_flow (const void *entry1, const void *entry2) {
	const flow *foo1 = entry1;
	const flow *foo2 = entry2;

	return ( foo1->src.s_addr != foo2->src.s_addr || foo1->dst.s_addr != foo2->dst.s_addr || foo1->sport != foo2->sport || foo1->dport != foo2->dport) ;
}

/* make a hash of an entry - for use by the hashtable */
static unsigned long make_key_flow (const void *entry) {
	const flow *what = entry;
	return (unsigned) what->src.s_addr * 59 + what->dst.s_addr + ((unsigned) what->dport << 16) + what->sport;
}

/* free mem of an entry - for use by the hashtable */
static void delete_flow (void *entry) {
	flow *what = entry;
	if (!what) return;
	what->prev->next=what->next;
	if (what->next) {
		what->next->prev=what->prev;
	} else {
	//Removing last entry
		active_flows=what->prev;
	}

	free (what->pkt_sizes);
	free (what);
}

static void init_hashes (void) {
    flow_hash = init_hash_table ("# hashes entries for each flow", compare_flow, make_key_flow, delete_flow, FLOW_HASH_TABLE_SIZE);
}


static void print_flow(flow * flowrec) {
	int i;

	printf("%s\t",inet_ntoa(flowrec->src));
	printf("%s\t%d\t%d",inet_ntoa(flowrec->dst),flowrec->sport,flowrec->dport);

	switch (action) {
		case ACTION_LABEL:
			printf("\t%s",label(flowrec->label));
			if (flowrec->isSSL) printf(" (%s)",label(flowrec->labelSSL));
			break;
		default:
			break;
	}
	printf("\n");
}


static void clean_flows(flow * list, uint32_t ts) {
	flow * flowrec;
	flow * savflow;
	int i=0;
	
	flowrec=list;
	while (flowrec && ts-flowrec->ts_latest>EXP_TIME) {
		i++;
		savflow=flowrec;
		print_flow(flowrec);
		clear_hash_entry(flow_hash,flowrec);
		flowrec=savflow->next;
	}
}


static void dump_flows(flow * list) {
	flow * flowrec;
	for (flowrec = list; flowrec; flowrec = flowrec->next) {
		print_flow(flowrec);
		clear_hash_entry(flow_hash,flowrec);
	}
}


static uint16_t clearsize(uint16_t sslsize) {
	// Simple heuristic to find original size of packet
	return sslsize-16;
}


void analyze(flow * flowrec) {

	if (flowrec->datapkts==pktlimit) {
		if (action==ACTION_LABEL) {
			if (!flowrec->isSSL) {
				flowrec->label=labeling(assign(flowrec->pkt_sizes,threshold),flowrec->dport);
			} else {
				flowrec->label=SSL_labeling(assign(flowrec->pkt_sizes,threshold),flowrec->dport);
			}
		} else {
			flowrec->label=LABEL_PARSED;
		}
		
		if (sslparsing && flowrec->label>0 && flowrec->label<=model.nbapplis && model.SSLapplis[flowrec->label-1]) {
		//If connection is SSL we continue the parsing
			flowrec->isSSL=1;
			flowrec->SSLdata=0;
			flowrec->datapkts=0;
			bzero(flowrec->pkt_sizes,pktlimit*sizeof(int16_t));
			flowrec->labelSSL=flowrec->label;
			flowrec->label=LABEL_NONE;
			return;
		}

		if (memory>=OPT_NOSTORE) {
			//If we want to minimize memory usage, we print information about the connection and remove it from the hashtable
			print_flow(flowrec);
			clear_hash_entry(flow_hash,flowrec);
		}
	}
}

int16_t sslpayload(uint8_t * l4buf,uint16_t psize,uint16_t pcaptured) {
	ssl_t *sslhd;
	uint16_t tmpsize;
	
	if (pcaptured>=5) {
		sslhd= (ssl_t *) l4buf;
		if (sslhd->version==3 && (sslhd->minor==1 || sslhd->minor==0) && (sslhd->type==23 || sslhd->type==21 || sslhd->type==20 || sslhd->type==22) ) {
		// Content check for SSL
			if (sslhd->type==23) return psize-5;		// 23: payload, 5: header size
			
			tmpsize=ntohs(sslhd->size)+5;	//Size of ssl data
			while (psize>tmpsize) {		//While we have SSL packets in this paylaod
				if (pcaptured>=tmpsize+5) {
					sslhd= (ssl_t *) (l4buf+tmpsize);
					if (sslhd->type==23) return psize-tmpsize-5;		// 23: payload
					tmpsize+=ntohs(sslhd->size)+5;
				} else break;
			}
		} else return -1;	// Not SSL
	}
	return 0;
}


void count_flow (const struct ip * ip,uint16_t iplen,uint32_t tspkt) {
	flow tmp, tmp_peer;
	flow * flowrec=NULL;

	uint16_t hsize,psize,sslsize;
	uint32_t seq;
	struct tcphdr *t;
	int direction=0;

	t=(struct tcphdr *)(((uint8_t*)ip) + ip->ip_hl*4);


	hsize=ip->ip_hl*4+t->doff*4;
	psize=ntohs(ip->ip_len)-hsize;

	seq=ntohl(t->seq);


	if (psize>0) {
	//	If this packet is a data packet, we look for its connection in the hashtable
		/* Set the key to the source/destination address pair. */
		tmp.src.s_addr = ip->ip_src.s_addr;
		tmp.dst.s_addr = ip->ip_dst.s_addr;
		tmp.sport = ntohs (t->source);
		tmp.dport = ntohs (t->dest);

		// Peer
		tmp_peer.src.s_addr = tmp.dst.s_addr;
		tmp_peer.dst.s_addr = tmp.src.s_addr;
		tmp_peer.sport = tmp.dport;
		tmp_peer.dport = tmp.sport;

		direction=0;
		if (flowrec = (flow *) find_hash_entry (flow_hash, &tmp)) {
			direction=1;
		} else if (flowrec = (flow *) find_hash_entry (flow_hash, &tmp_peer)) {
			direction=2;
		}
		

		if (direction>0 && flowrec->label==LABEL_NONE) {
		//	Connection exists, is classifiable (SYN seen) and in sequence
			
			//First we reorder the list of connection (connections with most recent packets at the end of the list)
			if (flowrec->next) {
				//Else connection is already the last in the last so no modification
				//Connection cannot be the first we have a special empty pointer for the head of the list (first_flow)
				flowrec->prev->next=flowrec->next;
				flowrec->next->prev=flowrec->prev;
				active_flows->next=flowrec;
				flowrec->prev=active_flows;
				flowrec->next=NULL;
				active_flows=flowrec;
			}
			flowrec->ts_latest=tspkt;

			if (direction==1) {
				if (flowrec->data1==0) {
					//First packet with data
					flowrec->data1=1;
					flowrec->nextseq=seq+psize;
				} else if (flowrec->nextseq!=seq) {
					//Out of sequence packet, we remove the entry for this connection
					flowrec->label=LABEL_OUTOFSEQ;
					if (memory>=OPT_NOSTORE) {
						print_flow(flowrec);
						clear_hash_entry(flow_hash,flowrec);
						return ;
					}
				} else {
					flowrec->nextseq+=psize;
				}
			}
			if (direction==2) {
				if (flowrec->data2==0) {
					//First packet in reverse direction, initialize sequence number
					flowrec->data2=1;
					flowrec->nextseqpeer=seq+psize;
				} else if (flowrec->nextseqpeer!=seq) {
					flowrec->label=LABEL_OUTOFSEQ;
					if (memory>=OPT_NOSTORE) {
						print_flow(flowrec);
						clear_hash_entry(flow_hash,flowrec);
						return ;
					}
				} else {
					flowrec->nextseqpeer+=psize;
				}
			}
	
			if (!flowrec->isSSL) {
				assert(flowrec->datapkts<pktlimit);
				flowrec->pkt_sizes[flowrec->datapkts]=(direction==1) ? psize : -psize;
				flowrec->datapkts+=1;
				analyze(flowrec);
			}
			
			//If packet is SSL we parse it
			if (flowrec->isSSL) {
				sslsize=0;
				if (!flowrec->SSLdata) {
					sslsize=sslpayload(((uint8_t*)t)+t->doff*4,psize,iplen-hsize);
					if (sslsize>0) flowrec->SSLdata=1;
				} else sslsize=psize-5; 	//5: length of SSL header

				if (flowrec->SSLdata) {
					assert(flowrec->datapkts<pktlimit);
					flowrec->pkt_sizes[flowrec->datapkts]=(direction==1) ? clearsize(sslsize) : -clearsize(sslsize);
					flowrec->datapkts+=1;
					analyze(flowrec);
				}
			}
		}
		// Else: Connection is not classifiable: ignored
	} else if (t->syn==1 && t->ack==0) {
		// We are only intersted in SYN packets when there is no data

		flowrec = (flow *) malloc (sizeof (flow));
		if (flowrec == NULL) {
			fprintf (stderr, "Can't malloc new connection\n");
			abort ();
		}

		flowrec->pkt_sizes=(int16_t *)malloc(pktlimit*sizeof(int16_t));
		if (flowrec->pkt_sizes == NULL) {
			fprintf (stderr, "Can't malloc new connection\n");
			abort ();
		}
		flowrec->label=LABEL_NONE;

		bzero(flowrec->pkt_sizes,pktlimit*sizeof(int16_t));
		
		flowrec->src.s_addr=ip->ip_src.s_addr;
		flowrec->dst.s_addr=ip->ip_dst.s_addr;
		flowrec->sport=ntohs (t->source);
		flowrec->dport=ntohs (t->dest);

		flowrec->nextseq=0;
		flowrec->nextseqpeer=0;
		flowrec->data1=0;
		flowrec->data2=0;

		flowrec->isSSL=0;
		flowrec->SSLdata=0;

		flowrec->datapkts=0; 
		flowrec->ts_latest=tspkt;

		flowrec->prev = active_flows;
		flowrec->next = NULL;

		active_flows->next = flowrec;
      		active_flows = flowrec;

      		nbflows++;

      		add_hash_entry (flow_hash, flowrec);
	} else if (memory>=OPT_GARBAGE && (t->rst || t->fin)) {
	// We remove connections in which we see RST or FIN

		/* Set the key to the source/destination address pair. */
		tmp.src.s_addr = ip->ip_src.s_addr;
		tmp.dst.s_addr = ip->ip_dst.s_addr;
		tmp.sport = ntohs (t->source);
		tmp.dport = ntohs (t->dest);

		// Peer
		tmp_peer.src.s_addr = tmp.dst.s_addr;
		tmp_peer.dst.s_addr = tmp.src.s_addr;
		tmp_peer.sport = tmp.dport;
		tmp_peer.dport = tmp.sport;
		
		flowrec = (flow *) find_hash_entry (flow_hash, &tmp);
		if (!flowrec) flowrec = (flow *) find_hash_entry (flow_hash, &tmp_peer);
		if (flowrec) {
			print_flow(flowrec);
			clear_hash_entry(flow_hash,flowrec);
			return ;
		}
	}
	flowrec;
}


void usage(char ** argv) {
	printf("Usage: %s [OPTION] [FILE]\n"
 		"-h	Help (this message)\n"
 		"-P	Do not label connections, simply output sizes of the first packet\n"
 		"-L	Label connections (default)\n"
 		"-D	Use DOMINANT labeling heuristic\n"
 		"-C	Use CLUSTER+PORT labeling heuristic (default)\n"
 		"-S	Analyze encapsulated SSL traffic (default: no SSL parsing)\n"
		"-m <M>	Memory optimization (O: none (default), 1:removed classed connections, 2: 1+Garbage Collection)\n"
 		"-t <f>	Apply threshold -<f> for assignment heuristic (default: 255, no threshold)\n"
 		"-p <n>	Print sizes of first <n> application packets (only valid with -P option)\n",argv[0]);
	exit(1);
}


static void statistics(uint32_t timediff) {
	// Regular parsing of connections to remove expired ones
	stats.nbstats++;
	stats.timeidx[stats.nbstats]=timediff+stats.timeidx[stats.nbstats-1];

	stats.creations[stats.nbstats]=flow_hash->total_insert-stats.inserts;
	stats.inserts=flow_hash->total_insert;
	
	stats.deletions[stats.nbstats]=stats.entries+stats.creations[stats.nbstats]-flow_hash->entries;
	stats.entries=flow_hash->entries;
}


void print_statistics() {
	int i;
	fprintf(stderr,"\n\nInserts: %lu Max entries: %lu Entries at the end: %lu\n",flow_hash->total_insert,flow_hash->max_entries,stats.entries);
	for (i=0;i<=stats.nbstats;i++) {
		printf("%d\t%d\t%d\t%d\n",stats.timeidx[i],stats.creations[i],stats.deletions[i],stats.creations[i]-stats.deletions[i]);
	}
}

int main(int argc, char **argv) {
	pcap_t *pcap;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *pkt;
	struct pcap_pkthdr hdr;
	struct ether_header *eptr;
	struct ip *ip_hdr;   
	struct tcphdr *tcp_hdr;   
	unsigned long nbp,nbip,nbtcp;
	unsigned long long totalSize;
	flow * flowrec;
	int c,optpkt;
	struct timeval t0,t1;
	uint32_t last_expiration,current_ts;

	// Default Paramaters for the classification
	labeling=clusterport;
	SSL_labeling=SSL_clusterport;
	sslparsing=0;
	threshold=-255;
	action=ACTION_LABEL;
	memory=NOOPTMEM;
	pktlimit=model.nbpackets;
	optpkt=pktlimit;

	stats.nbstats=0;
	bzero(stats.timeidx,sizeof(stats.timeidx));
	bzero(stats.creations,sizeof(stats.creations));
	bzero(stats.deletions,sizeof(stats.deletions));

	nbflows=0;
	last_expiration=0;

	// Parsing options
	while ((c = getopt (argc, argv, "m:hCDPLSt:p:")) != -1)
		switch (c) {
			case 'h':
				usage(argv);
				break;
			case 'P':
				action=ACTION_PARSE;
				break;
			case 'L':
				action=ACTION_LABEL;
				break;
			case 'D':
				labeling=dominant;
				SSL_labeling=dominant;
				break;
			case 'C':
				labeling=clusterport;
				SSL_labeling=SSL_clusterport;
				break;
			case 'm':
				if (atoi(optarg)>=0) {
					memory=atoi(optarg);
					break;
				} else {
					fprintf(stderr,"Invalid Memory option\n");
					usage(argv);
				}
				break;
			case 'S':
				sslparsing=1;
				break;
			case 't':
				if (atoi(optarg)>0) {
					threshold=-atoi(optarg);
					break;
				} else {
					fprintf(stderr,"Invalid threshold value\n");
					usage(argv);
				}
			case 'p':
				if (atoi(optarg)>0) {
					optpkt=atoi(optarg);
					break;
				} else {
					fprintf(stderr,"Invalid packet value\n");
					usage(argv);
				}

			case '?':
				if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
				usage(argv);
			default:
				usage(argv);
		}


	if (action==ACTION_PARSE) pktlimit=optpkt;

	if (optind>=argc) {
		fprintf(stderr,"No file specified\n");
		usage(argv);
	}
	
	// Opening pcap file
	fprintf(stderr,"Opening file : %s\n",argv[optind]);
	if ((pcap = pcap_open_offline(argv[optind], errbuf)) == NULL) {
		fprintf(stderr,"Error opening pcap file : %s\n",errbuf);
		usage(argv);
	}

	init_hashes ();

	// Empty connection to start list
	first_flow=(flow*)malloc(sizeof(flow));
	first_flow->src.s_addr=0;
	first_flow->dst.s_addr=0;
	first_flow->sport=0;
	first_flow->dport=0;

	active_flows=first_flow;


	// Parse packets one by one
	nbp=0;nbip=0;nbtcp=0;
	totalSize=0;
	gettimeofday (&t0,NULL);
	while (pkt  = pcap_next( pcap,  &hdr )) {
		nbp++;
		totalSize+=hdr.len;

		current_ts=hdr.ts.tv_sec;
		if (last_expiration==0) last_expiration=current_ts;
		if (current_ts-last_expiration>CLEAN_TIME) {
			if (memory>=OPT_GARBAGE) clean_flows(first_flow->next,current_ts);
			statistics(current_ts-last_expiration);
			last_expiration=current_ts;
		}

		if (nbp % PRINTPKT== 0) {
			fprintf(stderr, "Pkt : %lu",nbp);
	    		fprintf(stderr, "\r");
			fflush(stderr);
		}

		eptr = (struct ether_header *) pkt;
		if (ntohs (eptr->ether_type) != ETHERTYPE_IP) {
			continue;
		} else {
			nbip++;
			ip_hdr=(struct ip *)(pkt+14);

			if (ip_hdr->ip_p==IPPROTO_TCP && ((ntohs (ip_hdr->ip_off) & IP_OFFMASK)==0)) {
				nbtcp++;
				count_flow(ip_hdr,hdr.caplen-14,hdr.ts.tv_sec);
			}
		}
	}

	if (memory>=OPT_GARBAGE) clean_flows(first_flow->next,current_ts);
	statistics(current_ts-last_expiration);
	last_expiration=current_ts;
	dump_flows(first_flow->next);
	statistics(1);

	gettimeofday (&t1,NULL);
	pcap_close(pcap);

	fprintf(stderr,"\n%lu Packets parsed in %.2fms\n(%lu non-ip / %lu non-tcp)\n"
			"TCP Connections with Syn: %lu\n"
			"Total Volume: %llu\n"
			"Duration: %lu\n",
			nbp,
			(float)((t1.tv_sec-t0.tv_sec)*1000000 + (t1.tv_usec-t0.tv_usec))/1000,
			nbp-nbip,nbp-nbtcp,flow_hash->total_insert,totalSize,stats.timeidx[stats.nbstats]);
	
	//dump_hashtab_stats(flow_hash);
	//print_statistics();
}

