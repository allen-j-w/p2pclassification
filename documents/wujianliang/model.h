#define LABEL_NONE 100
#define LABEL_NOSYN 101
#define LABEL_OUTOFSEQ 102
#define LABEL_PARSED 127

typedef struct _model_t{
	int nbpackets;
	int nbclusters;
	int nbapplis;
	char applis[10][20];
	int SSLapplis[10];
	int nbports;
	int knownports[12];
	int SSL_nbports;
	int SSL_knownports[2];
	struct clust {
		int labelDom;
		int DominantUnStd;
		float cst;
		int appFromPort[12];
		int SSL_appFromPort[2];
		float center[3];
		float covar[3];
	} clusters[30];
} model_t;

extern const model_t model;
