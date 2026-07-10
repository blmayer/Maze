#include "sha256.h"
#include <string.h>

static const unsigned int K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define RR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (RR(x, 2) ^ RR(x, 13) ^ RR(x, 22))
#define EP1(x) (RR(x, 6) ^ RR(x, 11) ^ RR(x, 25))
#define SIG0(x) (RR(x, 7) ^ RR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (RR(x, 17) ^ RR(x, 19) ^ ((x) >> 10))

static void sha256_transform(struct sha256_ctx *ctx, const unsigned char *blk)
{
	unsigned int w[64], a, b, c, d, e, f, g, h, t1, t2;
	int i;

	for (i = 0; i < 16; i++) {
		w[i] = (blk[i * 4] << 24) | (blk[i * 4 + 1] << 16) |
		       (blk[i * 4 + 2] << 8) | blk[i * 4 + 3];
	}
	for (i = 16; i < 64; i++) {
		w[i] = SIG1(w[i - 2]) + w[i - 7] + SIG0(w[i - 15]) + w[i - 16];
	}

	a = ctx->state[0]; b = ctx->state[1];
	c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5];
	g = ctx->state[6]; h = ctx->state[7];

	for (i = 0; i < 64; i++) {
		t1 = h + EP1(e) + CH(e, f, g) + K[i] + w[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	ctx->state[0] += a; ctx->state[1] += b;
	ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f;
	ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(struct sha256_ctx *ctx)
{
	ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
	ctx->count = 0;
}

void sha256_update(struct sha256_ctx *ctx, const unsigned char *data, int len)
{
	int i, idx;
	idx = (int)(ctx->count % 64);
	ctx->count += len;
	for (i = 0; i < len; i++) {
		ctx->buf[idx++] = data[i];
		if (idx == 64) {
			sha256_transform(ctx, ctx->buf);
			idx = 0;
		}
	}
}

void sha256_final(struct sha256_ctx *ctx, unsigned char out[32])
{
	int i, idx;
	unsigned long long bits = ctx->count * 8;
	idx = (int)(ctx->count % 64);

	ctx->buf[idx++] = 0x80;
	if (idx > 56) {
		while (idx < 64) ctx->buf[idx++] = 0;
		sha256_transform(ctx, ctx->buf);
		idx = 0;
	}
	while (idx < 56) ctx->buf[idx++] = 0;
	for (i = 7; i >= 0; i--) {
		ctx->buf[56 + (7 - i)] = (unsigned char)(bits >> (i * 8));
	}
	sha256_transform(ctx, ctx->buf);

	for (i = 0; i < 8; i++) {
		out[i * 4]     = (ctx->state[i] >> 24) & 0xff;
		out[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
		out[i * 4 + 2] = (ctx->state[i] >> 8) & 0xff;
		out[i * 4 + 3] = ctx->state[i] & 0xff;
	}
}

void sha256(const unsigned char *data, int len, unsigned char out[32])
{
	struct sha256_ctx ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, data, len);
	sha256_final(&ctx, out);
}