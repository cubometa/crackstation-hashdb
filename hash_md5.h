/*
MD5 algorithm taken by Ale Navarro from https://en.wikipedia.org/wiki/MD5 on Mon, Aug 17, 2015
*/

uint32_t hash_md5_leftrotate (uint32_t x, uint32_t c) {
    return (x << c) | (x >> (32-c));
}

void hash_md5(uint64_t mlen, uint32_t *message, uint32_t thehash[4]) {
#define TOP_BIT_SET 0x80000000

// s specifies the per-round shift amounts
uint32_t s[64] = { 7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
                   5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
                   4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
                   6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21 };

uint32_t k[64] = { 0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
                   0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
                   0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
                   0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
                   0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
                   0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
                   0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
                   0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
                   0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
                   0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
                   0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
                   0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
                   0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
                   0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
                   0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
                   0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };

//Initialize variables:
uint32_t a0 = 0x67452301;   //A
uint32_t b0 = 0xefcdab89;   //B
uint32_t c0 = 0x98badcfe;   //C
uint32_t d0 = 0x10325476;   //D

uint64_t nlen = mlen + 512 - (mlen % 512);
if (mlen % 512 >= 448) {
	nlen += 512;
}

uint32_t msg[nlen/32];

uint64_t pos;
for (pos = 0; pos < mlen / 32; ++pos) {
	msg[pos] = message[pos];
}

if (mlen % 32 == 0) {
	msg[pos] = TOP_BIT_SET;
} else {
	msg[pos] = message[pos] | (TOP_BIT_SET >> (mlen % 32));
}

++pos;
for (; pos < nlen / 32 - 2; ++pos) {
	msg[pos] = 0;
}

msg[pos] = mlen & 0xffffffff;
msg[++pos] = mlen >> 32;

//Pre-processing: padding with zeros
//append "0" bit until message length in bits ≡ 448 (mod 512)
//append original length in bits mod (2 pow 64) to message


//Process the message in successive 512-bit chunks:
for (pos = 0; pos < nlen / 512; pos += 16) {
	//break chunk into sixteen 32-bit words M[j], 0 ≤ j ≤ 15
	//Initialize hash value for this chunk:
	uint32_t a = a0;
	uint32_t b = b0;
	uint32_t c = c0;
	uint32_t d = d0;
	
	//Main loop:
	for (int i=0; i<64; ++i) {
		uint32_t f, g;
        	if (i >= 0 && i < 16) {
			f = (b & c) | ((~b) & d);
			g = i;
		} else if (i >= 16 && i < 32) {
			f = (d & b) | ((~d) & c);
			g = (5*i + 1) % 16;
		} else if (i >= 32 && i < 48) {
			f = b ^ c ^ d;
			g = (3*i + 5) % 16;
		} else {
			f = c ^ (b | (~d));
			g = (7*i) % 16;
		}
 		uint32_t dt = d;
		d = c;
		c = b;
		b = b + hash_md5_leftrotate((a + f + k[i] + msg[pos+g]), s[i]);
		a = dt;
	}
	//Add this chunk's hash to result so far:
	a0 = a0 + a;
	b0 = b0 + b;
	c0 = c0 + c;
	d0 = d0 + d;
}

thehash[0] = a0;
thehash[1] = b0;
thehash[2] = c0;
thehash[3] = d0;

char buf[256];
sprintf(buf,"** %llu %llu - %u %u %u %u\n", mlen, nlen, a0, b0, c0, d0);
write(1,buf,strlen(buf));
}
