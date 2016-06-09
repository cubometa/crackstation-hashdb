#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#define WARN(x) write(2,(x),strlen(x))
char warnbuff[1024];
#define WARNS(x,y) sprintf(warnbuff,(x),(y))|write(2,warnbuff,strlen(warnbuff))
#define TYPE_NONE 0
#define TYPE_HASH 1
#define TYPE_CIPHER 2

/*
Tue, Aug 18, 2015 through Thu, Aug 20, 2015
(c) 2015 Ale Navarro (cubometa.com)
*/

int readline(int id, int od) {
	//WARN("readline() CALL\n");
	int rl;
	char data[1];
	int chars = 0;
	while ((rl = read(id, data, 1)) > 0) {
		if (data[0] == '\n') {return 1;}
		else {write(od,data,1);}
		++chars;
		//WARNS("Chars: %d\n",chars);
	}
	return rl;
}

int main(int argc, char** argv) {
if (argc < 4) {
	WARN("Not enough arguments supplied.\nusage: createidx hashalgo infile outfile\n");
	exit(1);
}

int infile, outfile;
if ((infile=open(argv[2],O_RDONLY))==-1) {
	WARNS("Can't open '%s': check that the file exists and that you have read permissions to it.\n",argv[2]); exit(1);
}
if ((outfile=open(argv[3],O_WRONLY|O_TRUNC|O_CREAT,0644))==-1) {
	WARNS("Can't open '%s': check that you have write permissions to it if it exists or permissions to create it if not.\n",argv[3]); exit(1);
}

char algotype = TYPE_NONE;
int optpos = 0;
char *hashalgos[9] = {"-md2","-md4","-md5","-sha1","-sha224","-sha256","-sha384","-sha512","-ripemd160"};
for (int i=0; i<10; ++i) { if (strcmp(&hashalgos[i][1],argv[1])==0) { algotype = TYPE_HASH; optpos = i; break; } }
if (strcmp("rmd160",argv[1])==0) { algotype = TYPE_HASH; optpos = 8; }

char *cipheralgos[3] = {"-rc4","-base64","-bf"};
for (int i=0; i<1; ++i) { if(strcmp(&cipheralgos[i][1],argv[1])==0) { algotype = TYPE_CIPHER; optpos = i; break; } }
if (strcmp("blowfish",argv[1])==0) { algotype = TYPE_CIPHER; optpos = 2; }

if (algotype == TYPE_NONE) {
	WARNS("The specified algorithm '%s' does not exist.\n",argv[1]);
	WARN("Supported algorithms: md2, md4, md5, sha1, sha224, sha256, sha384, sha512, rmd160 (ripemd160), rc4, base64, bf (blowfish).\n");
	exit(1);
}

int inpipe[2], outpipe[2];
int cro, canread;
char result[1024];
pipe(inpipe);
pipe(outpipe);
int rl = readline(infile, inpipe[1]);
close(inpipe[1]);
while (rl > 0) {
	int k = fork();
	if (k == 0) {
		//WARN("LO");
		close(inpipe[1]);
		close(outpipe[0]);
		//WARN("LE");
		dup2(outpipe[1],1);
		close(outpipe[1]);
		dup2(inpipe[0],0);
		close(inpipe[0]);
		//WARN("LA");
		
		if (algotype == TYPE_HASH) {
			execlp("openssl","openssl","dgst",hashalgos[optpos],"-binary",(char*)NULL);
		} else if (algotype == TYPE_CIPHER) {
			execlp("openssl","openssl","enc",cipheralgos[optpos],"-nosalt",(char*)NULL);
		}
		exit(0);
	} else {
		//WARNS("PID %d",k);
		close(inpipe[0]);
		close(outpipe[1]);
		//WARN("MA\n");
		while((cro=waitpid(-1,NULL,0))>0) {WARNS("++%d\n",cro);}
		WARNS("--%d\n",cro);
		WARNS("..%d\n",errno==ECHILD);
		//WARN("MO\n");
		canread = read(outpipe[0],result,1024);
		WARNS(",,%d\n",(~kill(k,SIGTERM))|(errno==ESRCH));
		WARNS("read: %i",canread);
		WARN("MI");
		if (canread < 0) {
			WARN("There was an error hashing the data.");
			exit(1);
		}
		WARN("ME");
		WARNS("%s",result);
		write(outfile,result,strlen(result));
		close(outpipe[0]);
	}
	pipe(inpipe);
	pipe(outpipe);
	rl = readline(infile, inpipe[1]);
}

exit(0);
}
