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

#include "hashtab.h"
#include "model.h"
#include "classif.h"


#define ACTION_LABEL	0
#define ACTION_PARSE	1
#define ACTION_STATS	2
#define FLOW_HASH_TABLE_SIZE	100000

#define PRINTPKT 100000

static int (*labeling) (int cluster,int dport);
int16_t threshold;
int action;
int pktlimit;


typedef struct _flow {
/* flow key data */
	struct in_addr src;
	struct in_addr dst;
	u_short sport;
	u_short dport;

	int8_t label;
	uint8_t data1;
	uint8_t data2;

	uint32_t nextseq;
	uint32_t nextseqpeer;

	uint32_t datapkts;
	int16_t *pkt_sizes;

	struct timeval first;
	long flow_id;

	// operational data
	struct _flow *next, *prev;
} flow;

hash_tab *flow_hash;

flow * active_flows;
int nbflows;


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
	free (what);
}

static void init_hashes (void) {
    flow_hash = init_hash_table ("# hashes entries for each flow", compare_flow, make_key_flow, delete_flow, FLOW_HASH_TABLE_SIZE);
}


static void dump_flows(flow * list) {
	flow * flowrec;
	int i;

	for (flowrec = list; flowrec!=NULL; flowrec = flowrec->next) {
		//SRC DST SPORT DPORT
		printf("%s\t",inet_ntoa(flowrec->src));
		printf("%s\t%d\t%d",inet_ntoa(flowrec->dst),flowrec->sport,flowrec->dport);
		for (i=0;i<pktlimit;i++) printf("\t%d",flowrec->pkt_sizes[i]);
		printf("\t%s\n",label(flowrec->label));
	}
}


static void dump_nolabel(flow * list) {
	flow * flowrec;
	int i;

	for (flowrec = list; flowrec!=NULL; flowrec = flowrec->next) {
		// We do not dump connections that do not have enough packets in sequence
		if (flowrec->label==LABEL_PARSED) {
			printf("%s\t",inet_ntoa(flowrec->src));
			printf("%s\t%d\t%d",inet_ntoa(flowrec->dst),flowrec->sport,flowrec->dport);
			for (i=0;i<pktlimit;i++) printf("\t%d",flowrec->pkt_sizes[i]);
			printf("\n");
		}
	}
}


flow* count_flow (const struct ip * ip) {
	flow tmp, tmp_peer;
	flow * flowrec;

	uint32_t hsize,psize,seq;
	struct tcphdr *t;
	int direction=0;

	t=(struct tcphdr *)(((uint8_t*)ip) + ip->ip_hl*4);

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

	hsize=ip->ip_hl*4+t->doff*4;
	psize=ntohs(ip->ip_len)-hsize;

	seq=ntohl(t->seq);
	      
	direction==0;
	if ((flowrec = (flow *) find_hash_entry (flow_hash, &tmp))) {
		direction=1;
	} else if ((flowrec = (flow *) find_hash_entry (flow_hash, &tmp_peer))) {
		direction=2;
	}
	

	if (direction>0 && flowrec->label==LABEL_NONE) {
		//	Connection exists, is classifiable (SYN seen) and in sequence
          	if (psize>0) {
		//	Is this packet a datapacket?
			if (direction==1) {
				if (flowrec->data1==0) {
					//First packet with data
					flowrec->data1=1;
					flowrec->nextseq=seq+psize;
				} else if (flowrec->nextseq!=seq) {
					//Out of sequence packet, we end the parsing for this packet
					flowrec->label=LABEL_OUTOFSEQ;
					return flowrec;
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
					return flowrec;
				} else {
					flowrec->nextseqpeer+=psize;
				}
			}
	
			assert(flowrec->datapkts<pktlimit);
			flowrec->pkt_sizes[flowrec->datapkts]=(direction==1) ? psize : -psize;
			flowrec->datapkts+=1;
		}	
	}

	if (!direction) {
	//Unknown connection
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

		bzero(flowrec->pkt_sizes,pktlimit*sizeof(int16_t));
		
		flowrec->src.s_addr=tmp.src.s_addr;
		flowrec->dst.s_addr=tmp.dst.s_addr;
		flowrec->sport=tmp.sport;
		flowrec->dport=tmp.dport;

		flowrec->nextseq=0;
		flowrec->nextseqpeer=0;
		flowrec->data1=0;
		flowrec->data2=0;

		flowrec->datapkts=0; 

     		if (t->syn==1 && t->ack==0) {
			flowrec->label=LABEL_NONE;
		} else {
			flowrec->label=LABEL_NOSYN;
		}
      
		flowrec->prev = NULL;
		flowrec->next = active_flows;
		if (flowrec->next) flowrec->next->prev = flowrec;

      		active_flows = flowrec;
      		nbflows++;
      		add_hash_entry (flow_hash, flowrec);
	}
	return flowrec;
}


void analyze(flow * flowrec) {

	if (flowrec->datapkts==pktlimit) {
		if (action==ACTION_LABEL) {
			flowrec->label=labeling(assign(flowrec->pkt_sizes,threshold),flowrec->dport);
		} else {
			flowrec->label=LABEL_PARSED;
		}
	}
}


void usage(char ** argv) {
	printf("Usage: %s [OPTION] [FILE]\n"
 		"-h	Help (this message)\n"
 		"-P	Do not label connections, simply output sizes of the first packet\n"
 		"-L	Label connections (default)\n"
 		"-D	Use DOMINANT labeling heuristic\n"
 		"-C	Use CLUSTER+PORT labeling heuristic (default)\n"
 		"-t <f>	Apply threshold -<f> for assignment heuristic (default: 255, no threshold)\n"
 		"-p <n>	Print sizes of first <n> application packets (only valid with -P option)\n",argv[0]);
	exit(1);
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
	flow * flowrec;
	int c,optpkt;

	// Default Paramaters for the classification
	labeling=clusterport;
	threshold=-255;
	action=ACTION_LABEL;
	pktlimit=model.nbpackets;
	optpkt=pktlimit;

	// Parsing options
	while ((c = getopt (argc, argv, "hCDPLSt:p:")) != -1)
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
			case 'S':
				action=ACTION_STATS;
				break;
			case 'D':
				labeling=dominant;
				break;
			case 'C':
				labeling=clusterport;
				break;
			case 't':
				if (atoi(optarg)>0) {
					threshold=-atoi(optarg);
					break;
				} else {
					fprintf(stderr,"Invalid threhsold value\n");
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
	active_flows=NULL;
	nbflows=0;

	// Parse packets one by one
	nbp=0;nbip=0;nbtcp=0;
	while (pkt  = pcap_next( pcap,  &hdr )) {
		nbp++;

		if (nbp % PRINTPKT== 0) {
			fprintf(stderr, "Pkt : %d",nbp);
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
				flowrec=count_flow(ip_hdr);
				assert(flowrec != NULL);
				if (flowrec->label==LABEL_NONE) analyze(flowrec);
			}
		}
	}

	fprintf(stderr,"%d Packets Read (%d non-ip / %d non-tcp)\nTCP Connections Identified: %d\n",nbp,nbp-nbip,nbp-nbtcp,nbflows);
	pcap_close( pcap );
	

	switch(action) {
		case ACTION_LABEL:
			dump_flows(active_flows);
			break;
		case ACTION_PARSE:
			dump_nolabel(active_flows);
			break;
		case ACTION_STATS:
			dump_hashtab_stats(flow_hash);
			break;
	}
}

