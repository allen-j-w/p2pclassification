#include <stdint.h>
#include <stdio.h>

#include "model.h"
#include "classif.h"

int assign(const int16_t * sizes,int16_t th) {
	int bestcl;
	float bestproba;
	float tmp;
	int j,k;
	
	tmp=0;
	for (j=0;j<model.nbpackets;j++) {
		tmp+=(sizes[j]-model.clusters[0].center[j])*(sizes[j]-model.clusters[0].center[j])/model.clusters[0].covar[j];
	}
	bestcl=0;
	bestproba=model.clusters[0].cst-0.5*tmp;

	for (k=1;k<model.nbclusters;k++) {
		tmp=0;
		for (j=0;j<model.nbpackets;j++) {
			tmp+=(sizes[j]-model.clusters[k].center[j])*(sizes[j]-model.clusters[k].center[j])/model.clusters[k].covar[j];
		}
		tmp=model.clusters[k].cst-0.5*tmp;
		if (tmp>bestproba) {
			bestproba=tmp;
			bestcl=k;
		}
	}
	if (bestproba<(float)th) {
		return -1; // -1 : unknown
	} else {
		return bestcl;
	}
}

int dominant(int cluster,int dport) {
	if (cluster<0) {
		return 0;
	} else {
		return model.clusters[cluster].labelDom;
	}
}

int clusterport(int cluster,int dport) {
	int i;

	if (cluster<0) {
		return 0;
	} else {
		i=0;
		while (model.knownports[i]<dport && i<model.nbports) i++;
		if (model.knownports[i]==dport) {
			//Known port
			return model.clusters[cluster].appFromPort[i];
		} else {
			return model.clusters[cluster].DominantUnStd;
		}
	}
}


int SSL_clusterport(int cluster,int dport) {
	int i;

	if (cluster<0) {
		return 0;
	} else {
		i=0;
		while (model.SSL_knownports[i]<dport && i<model.SSL_nbports) i++;
		if (model.SSL_knownports[i]==dport) {
			//Known port
			return model.clusters[cluster].SSL_appFromPort[i];
		} else {
			return model.clusters[cluster].DominantUnStd;
		}
	}
}


char *label(int numlabel) {
	switch (numlabel) {
		case LABEL_NONE:
			return "too few packets";
		case LABEL_NOSYN:
			return "unclassifiable";
		case LABEL_OUTOFSEQ:
			return "out of sequence";
		case -2:
		case -1:
			return "masquerade";
		case 0:
			return "unknown";
		default:
			return(model.applis[numlabel-1]);
	}
}

