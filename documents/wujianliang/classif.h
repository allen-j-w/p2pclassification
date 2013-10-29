#define MAXLABELSIZE 50

int assign(const int16_t * sizes,int16_t th);
int dominant(int cluster,int dport);
int clusterport(int cluster,int dport);
int SSL_clusterport(int cluster,int dport);
char *label(int numlabel);
