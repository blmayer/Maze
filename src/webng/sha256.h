#ifndef SHA256_H
#define SHA256_H

struct sha256_ctx {
	unsigned int state[8];
	unsigned long long count;
	unsigned char buf[64];
};

void sha256_init(struct sha256_ctx *ctx);
void sha256_update(struct sha256_ctx *ctx, const unsigned char *data, int len);
void sha256_final(struct sha256_ctx *ctx, unsigned char out[32]);
void sha256(const unsigned char *data, int len, unsigned char out[32]);

#endif