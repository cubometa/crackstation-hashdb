#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "hash_md5.h"

int nextm4(uint64_t i) {
	if ((i&3)==0) return i;
	else return i+(4-i%4);
}

int main(int argc, char** argv) {
if (argc < 2) exit(1);

uint64_t len;
for (len = 0; argv[1][len] != '\0'; ++len);

uint64_t nlen = nextm4(len)/4;
uint32_t thedata[nlen];

int rpos = 0;
for (int pos = 0; pos < len; ++pos) {
	if (pos % 4 == 0) {
		thedata[rpos] = argv[1][pos] << 24;
	} else if (pos % 4 == 1) {
		thedata[rpos] |= argv[1][pos] << 16;
	} else if (pos % 4 == 2) {
		thedata[rpos] |= argv[1][pos] << 8;
	} else {
		thedata[rpos] |= argv[1][pos];
		++rpos;
	}
}

uint32_t thehash[4];
hash_md5(len,thedata,thehash);
char buf[256];
sprintf(buf, "%llu, %llu: %x %x %x %x\n", len, nlen, thehash[0], thehash[1], thehash[2], thehash[3]);
write(1,buf,strlen(buf));
exit (0);
}
