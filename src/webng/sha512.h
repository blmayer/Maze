#ifndef SHA512_H
#define SHA512_H

struct sha512_ctx {
	unsigned long long state[8];
	unsigned long long count;
	unsigned char buf[128];
};

void sha512_init(struct sha512_ctx *ctx);
void sha512_update(struct sha512_ctx *ctx, const unsigned char *data, int len);
void sha512_final(struct sha512_ctx *ctx, unsigned char out[64]);
void sha512(const unsigned char *data, int len, unsigned char out[64]);

#endif