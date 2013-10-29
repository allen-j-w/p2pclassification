#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <unistd.h>
#include <time.h>

#include "classif.h"

int main() {
	int16_t seq[3]={-25,27,-544};
	printf("Assign : %d %d %s\n",assign(seq,-255),dominant(assign(seq,-255),22),label(dominant(assign(seq,-255),22)));
}
