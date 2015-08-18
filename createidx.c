#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define WARN(x) write(2,(x),strlen(x))
#define TYPE_NONE 0
#define TYPE_HASH 1
#define TYPE_CIPHER 2

/*
Tue, Aug 18, 2015
(c) 2015 Ale Navarro (cubometa.com)
*/

int main(int argc, char** argv) {
if (argc < 2) {
	WARN("Not enough arguments supplied.\nusage: createidx hashalgo infile outfile\n");
	exit(1);
}

/* Check if files exist */

char algotype = TYPE_NONE;
int optpos = 0;
char *hashalgos[9] = {"-md2","-md4","-md5","-sha1","-sha224","-sha256","-sha384","-sha512","-rmd160"};
for (int i=0; i<10; ++i) { if (strcmp(&hashalgos[i][1],argv[1])==0) { algotype = TYPE_HASH; optpos = i; break; } }
if (strcmp("ripemd160",argv[1])==0) { algotype = TYPE_HASH; optpos = 8; }

char *cipheralgos[3] = {"-rc4","-base64","-bf"};
for (int i=0; i<1; ++i) { if(strcmp(&cipheralgos[i][1],argv[1])==0) { algotype = TYPE_CIPHER; optpos = i; break; } }
if (strcmp("blowfish",argv[1])==0) { algotype = TYPE_CIPHER; optpos = 2; }

if (algotype == TYPE_NONE) {
	WARN("The specified algorithm does not exist.\n");
	WARN("Supported algorithms: md2, md4, md5, sha1, sha224, sha256, sha384, sha512, rmd160 (ripemd160), rc4, base64, bf (blowfish).\n");
	exit(1);
}

int thepipe[2];
pipe(thepipe);

int k = fork();
if (k == 0) {
	int secondpipe[2];
	pipe(secondpipe);
	write(secondpipe[1],argv[2],strlen(argv[2]));
	close(secondpipe[1]);
	close(thepipe[0]);
	close(1);
	dup(thepipe[1]);
	close(0);
	dup(secondpipe[0]);
	
	if (algotype == TYPE_HASH) {
		execlp("openssl","openssl","dgst",hashalgos[optpos],"-binary",(char*)NULL);
	} else if (algotype == TYPE_CIPHER) {
		execlp("openssl","openssl","enc",cipheralgos[optpos],"-nosalt",(char*)NULL);
	}
	
	exit(0);
}

close(thepipe[1]);
while (waitpid(-1,NULL,0)>0);

char result[1024];
int canread = read(thepipe[0],result,1024);
if (canread < 0) exit(1);

char buf[256];
sprintf(buf, "%s", result);
write(1,buf,strlen(buf));
exit(0);
}
