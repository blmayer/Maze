/*
 * X25519 key exchange and Ed25519 signatures.
 *
 * Field arithmetic in GF(2^255 - 19) using 5 limbs of 51 bits each,
 * stored in unsigned long long. Products use __int128.
 *
 * X25519 uses the Montgomery ladder on Curve25519.
 * Ed25519 uses extended coordinates on the twisted Edwards curve.
 */

#include "tls.h"
#include "sha512.h"
#include <string.h>

typedef unsigned long long u64;
typedef __int128 u128;

/* A field element: 5 limbs, each < 2^52 after reduction */
typedef u64 fe[5];

#define MASK51 ((u64)0x7ffffffffffffULL)

/* ---- Field arithmetic ---------------------------------------------- */

static void fe_zero(fe o) { o[0]=o[1]=o[2]=o[3]=o[4]=0; }
static void fe_one(fe o) { o[0]=1; o[1]=o[2]=o[3]=o[4]=0; }
static void fe_copy(fe o, const fe a) {
	o[0]=a[0]; o[1]=a[1]; o[2]=a[2]; o[3]=a[3]; o[4]=a[4];
}

static void fe_add(fe o, const fe a, const fe b) {
	o[0]=a[0]+b[0]; o[1]=a[1]+b[1]; o[2]=a[2]+b[2];
	o[3]=a[3]+b[3]; o[4]=a[4]+b[4];
}

static void fe_sub(fe o, const fe a, const fe b) {
	/* Add 2*p to avoid underflow */
	o[0] = a[0] + 0xfffffffffffda - b[0];
	o[1] = a[1] + 0xffffffffffffe - b[1];
	o[2] = a[2] + 0xffffffffffffe - b[2];
	o[3] = a[3] + 0xffffffffffffe - b[3];
	o[4] = a[4] + 0xffffffffffffe - b[4];
}

static void fe_reduce(fe o) {
	u64 c;
	c = o[0] >> 51; o[0] &= MASK51; o[1] += c;
	c = o[1] >> 51; o[1] &= MASK51; o[2] += c;
	c = o[2] >> 51; o[2] &= MASK51; o[3] += c;
	c = o[3] >> 51; o[3] &= MASK51; o[4] += c;
	c = o[4] >> 51; o[4] &= MASK51; o[0] += c * 19;
}

static void fe_mul(fe o, const fe a, const fe b) {
	u128 t0,t1,t2,t3,t4;
	u64 b1_19 = b[1]*19, b2_19 = b[2]*19;
	u64 b3_19 = b[3]*19, b4_19 = b[4]*19;

	t0 = (u128)a[0]*b[0] + (u128)a[1]*b4_19 + (u128)a[2]*b3_19 +
	     (u128)a[3]*b2_19 + (u128)a[4]*b1_19;
	t1 = (u128)a[0]*b[1] + (u128)a[1]*b[0] + (u128)a[2]*b4_19 +
	     (u128)a[3]*b3_19 + (u128)a[4]*b2_19;
	t2 = (u128)a[0]*b[2] + (u128)a[1]*b[1] + (u128)a[2]*b[0] +
	     (u128)a[3]*b4_19 + (u128)a[4]*b3_19;
	t3 = (u128)a[0]*b[3] + (u128)a[1]*b[2] + (u128)a[2]*b[1] +
	     (u128)a[3]*b[0] + (u128)a[4]*b4_19;
	t4 = (u128)a[0]*b[4] + (u128)a[1]*b[3] + (u128)a[2]*b[2] +
	     (u128)a[3]*b[1] + (u128)a[4]*b[0];

	u64 c;
	o[0] = (u64)t0 & MASK51; c = (u64)(t0 >> 51);
	t1 += c; o[1] = (u64)t1 & MASK51; c = (u64)(t1 >> 51);
	t2 += c; o[2] = (u64)t2 & MASK51; c = (u64)(t2 >> 51);
	t3 += c; o[3] = (u64)t3 & MASK51; c = (u64)(t3 >> 51);
	t4 += c; o[4] = (u64)t4 & MASK51; c = (u64)(t4 >> 51);
	o[0] += c * 19;
	c = o[0] >> 51; o[0] &= MASK51; o[1] += c;
}

static void fe_sq(fe o, const fe a) { fe_mul(o, a, a); }

static void fe_mul121666(fe o, const fe a) {
	u128 t0 = (u128)a[0]*121666;
	u128 t1 = (u128)a[1]*121666;
	u128 t2 = (u128)a[2]*121666;
	u128 t3 = (u128)a[3]*121666;
	u128 t4 = (u128)a[4]*121666;
	u64 c;
	o[0] = (u64)t0 & MASK51; c = (u64)(t0 >> 51);
	t1 += c; o[1] = (u64)t1 & MASK51; c = (u64)(t1 >> 51);
	t2 += c; o[2] = (u64)t2 & MASK51; c = (u64)(t2 >> 51);
	t3 += c; o[3] = (u64)t3 & MASK51; c = (u64)(t3 >> 51);
	t4 += c; o[4] = (u64)t4 & MASK51; c = (u64)(t4 >> 51);
	o[0] += c * 19;
}

/* Fully reduce to [0, p) and write 32 bytes little-endian */
static void fe_tobytes(unsigned char out[32], fe h) {
	fe_reduce(h);
	fe_reduce(h);
	/* Now subtract p if h >= p */
	u64 q = (h[0] + 19) >> 51;
	q = (h[1] + q) >> 51;
	q = (h[2] + q) >> 51;
	q = (h[3] + q) >> 51;
	q = (h[4] + q) >> 51;
	h[0] += 19 * q;
	u64 c;
	c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
	c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
	c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
	c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
	h[4] &= MASK51;

	/* Pack 5 limbs of 51 bits into 32 bytes little-endian */
	u64 v[4];
	v[0] = h[0] | (h[1] << 51);
	v[1] = (h[1] >> 13) | (h[2] << 38);
	v[2] = (h[2] >> 26) | (h[3] << 25);
	v[3] = (h[3] >> 39) | (h[4] << 12);
	int i;
	for (i = 0; i < 4; i++) {
		out[i*8]   = v[i]; out[i*8+1] = v[i]>>8;
		out[i*8+2] = v[i]>>16; out[i*8+3] = v[i]>>24;
		out[i*8+4] = v[i]>>32; out[i*8+5] = v[i]>>40;
		out[i*8+6] = v[i]>>48; out[i*8+7] = v[i]>>56;
	}
}

static void fe_frombytes(fe h, const unsigned char s[32]) {
	u64 v[4];
	int i;
	for (i = 0; i < 4; i++) {
		v[i] = (u64)s[i*8] | ((u64)s[i*8+1]<<8) |
		       ((u64)s[i*8+2]<<16) | ((u64)s[i*8+3]<<24) |
		       ((u64)s[i*8+4]<<32) | ((u64)s[i*8+5]<<40) |
		       ((u64)s[i*8+6]<<48) | ((u64)s[i*8+7]<<56);
	}
	h[0] = v[0] & MASK51;
	h[1] = ((v[0] >> 51) | (v[1] << 13)) & MASK51;
	h[2] = ((v[1] >> 38) | (v[2] << 26)) & MASK51;
	h[3] = ((v[2] >> 25) | (v[3] << 39)) & MASK51;
	h[4] = (v[3] >> 12) & MASK51;
}

/* Compute 1/z via Fermat: z^(p-2) = z^(2^255-21) */
static void fe_inv(fe o, const fe z) {
	fe t0, t1, t2, t3;
	int i;
	fe_sq(t0, z);       /* t0 = z^2 */
	fe_sq(t1, t0);
	fe_sq(t1, t1);      /* t1 = z^8 */
	fe_mul(t1, z, t1);  /* t1 = z^9 */
	fe_mul(t0, t0, t1); /* t0 = z^11 */
	fe_sq(t2, t0);      /* t2 = z^22 */
	fe_mul(t1, t1, t2); /* t1 = z^(2^5-1) */
	fe_sq(t2, t1);
	for (i = 0; i < 4; i++) fe_sq(t2, t2); /* t2 = z^(2^10-2^5) */
	fe_mul(t1, t2, t1); /* t1 = z^(2^10-1) */
	fe_sq(t2, t1);
	for (i = 0; i < 9; i++) fe_sq(t2, t2); /* t2 = z^(2^20-2^10) */
	fe_mul(t2, t2, t1); /* t2 = z^(2^20-1) */
	fe_sq(t3, t2);
	for (i = 0; i < 19; i++) fe_sq(t3, t3); /* t3 = z^(2^40-2^20) */
	fe_mul(t2, t3, t2); /* t2 = z^(2^40-1) */
	fe_sq(t2, t2);
	for (i = 0; i < 9; i++) fe_sq(t2, t2); /* t2 = z^(2^50-2^10) */
	fe_mul(t1, t2, t1); /* t1 = z^(2^50-1) */
	fe_sq(t2, t1);
	for (i = 0; i < 49; i++) fe_sq(t2, t2); /* t2 = z^(2^100-2^50) */
	fe_mul(t2, t2, t1); /* t2 = z^(2^100-1) */
	fe_sq(t3, t2);
	for (i = 0; i < 99; i++) fe_sq(t3, t3); /* t3 = z^(2^200-2^100) */
	fe_mul(t2, t3, t2); /* t2 = z^(2^200-1) */
	fe_sq(t2, t2);
	for (i = 0; i < 49; i++) fe_sq(t2, t2); /* t2 = z^(2^250-2^50) */
	fe_mul(t1, t2, t1); /* t1 = z^(2^250-1) */
	fe_sq(t1, t1);      /* z^(2^251-2) */
	fe_sq(t1, t1);      /* z^(2^252-4) */
	fe_sq(t1, t1);      /* z^(2^253-8) */
	fe_sq(t1, t1);      /* z^(2^254-16) */
	fe_sq(t1, t1);      /* z^(2^255-32) */
	fe_mul(o, t1, t0);  /* z^(2^255-21) */
}

/* z^((p-5)/8) = z^(2^252-3) — used for Ed25519 sqrt */
static void fe_pow2523(fe o, const fe z) {
	fe t0, t1, t2;
	int i;
	fe_sq(t0, z);
	fe_sq(t1, t0);
	fe_sq(t1, t1);
	fe_mul(t1, z, t1);
	fe_mul(t0, t0, t1);
	fe_sq(t0, t0);
	fe_mul(t0, t1, t0);
	fe_sq(t1, t0);
	for (i = 0; i < 4; i++) fe_sq(t1, t1);
	fe_mul(t0, t1, t0);
	fe_sq(t1, t0);
	for (i = 0; i < 9; i++) fe_sq(t1, t1);
	fe_mul(t1, t1, t0);
	fe_sq(t2, t1);
	for (i = 0; i < 19; i++) fe_sq(t2, t2);
	fe_mul(t1, t2, t1);
	for (i = 0; i < 10; i++) fe_sq(t1, t1);
	fe_mul(t0, t1, t0);
	fe_sq(t1, t0);
	for (i = 0; i < 49; i++) fe_sq(t1, t1);
	fe_mul(t1, t1, t0);
	fe_sq(t2, t1);
	for (i = 0; i < 99; i++) fe_sq(t2, t2);
	fe_mul(t1, t2, t1);
	for (i = 0; i < 50; i++) fe_sq(t1, t1);
	fe_mul(t0, t1, t0);
	fe_sq(t0, t0);
	fe_sq(t0, t0);
	fe_mul(o, t0, z);
}

static int fe_isneg(const fe f) {
	unsigned char s[32];
	fe t;
	fe_copy(t, f);
	fe_tobytes(s, t);
	return s[0] & 1;
}

static int fe_isnonzero(const fe f) {
	unsigned char s[32];
	fe t;
	fe_copy(t, f);
	fe_tobytes(s, t);
	unsigned char d = 0;
	int i;
	for (i = 0; i < 32; i++) d |= s[i];
	return d != 0;
}

static void fe_neg(fe o, const fe a) {
	fe zero;
	fe_zero(zero);
	fe_sub(o, zero, a);
}

/* ---- X25519 Montgomery ladder --------------------------------------- */

static void x25519_scalar(unsigned char *out,
			   const unsigned char *scalar,
			   const unsigned char *point)
{
	unsigned char e[32];
	fe x1, x2, z2, x3, z3, t0, t1;
	int i, b, swap = 0;

	memcpy(e, scalar, 32);
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;

	fe_frombytes(x1, point);
	fe_one(x2); fe_zero(z2);     /* x2:z2 = 1:0 (point at infinity) */
	fe_copy(x3, x1); fe_one(z3); /* x3:z3 = u:1 */

	for (i = 254; i >= 0; i--) {
		b = (e[i >> 3] >> (i & 7)) & 1;
		swap ^= b;
		/* Conditional swap */
		{
			u64 mask = (u64)0 - (u64)swap;
			int j;
			for (j = 0; j < 5; j++) {
				u64 d = mask & (x2[j] ^ x3[j]);
				x2[j] ^= d; x3[j] ^= d;
				d = mask & (z2[j] ^ z3[j]);
				z2[j] ^= d; z3[j] ^= d;
			}
		}
		swap = b;

		fe_sub(t0, x3, z3);
		fe_sub(t1, x2, z2);
		fe_add(x2, x2, z2);
		fe_add(z2, x3, z3);
		fe_mul(z3, t0, x2);
		fe_mul(z2, z2, t1);
		fe_sq(t0, t1);
		fe_sq(t1, x2);
		fe_add(x3, z3, z2);
		fe_sub(z2, z3, z2);
		fe_mul(x2, t1, t0);
		fe_sub(t1, t1, t0);
		fe_sq(z2, z2);
		fe_mul121666(z3, t1);
		fe_sq(x3, x3);
		fe_add(t0, t0, z3);
		fe_mul(z3, x1, z2);
		fe_mul(z2, t1, t0);
	}
	/* Final swap */
	{
		u64 mask = (u64)0 - (u64)swap;
		int j;
		for (j = 0; j < 5; j++) {
			u64 d = mask & (x2[j] ^ x3[j]);
			x2[j] ^= d; x3[j] ^= d;
			d = mask & (z2[j] ^ z3[j]);
			z2[j] ^= d; z3[j] ^= d;
		}
	}

	fe_inv(z2, z2);
	fe_mul(x2, x2, z2);
	fe_tobytes(out, x2);
}

/* X25519 with basepoint 9 */
int curve25519_mult(unsigned char *a, unsigned char *out)
{
	unsigned char bp[32] = {9};
	x25519_scalar(out, a, bp);
	return 1;
}

/* General X25519: out = scalar * point */
void x25519(unsigned char out[32],
	    const unsigned char scalar[32],
	    const unsigned char point[32])
{
	x25519_scalar(out, scalar, point);
}

/* ---- Ed25519 -------------------------------------------------------- */

/*
 * Extended coordinates: (X, Y, Z, T) where x=X/Z, y=Y/Z, x*y=T/Z.
 * Curve: -x^2 + y^2 = 1 + d*x^2*y^2
 * d = -121665/121666
 */

typedef struct { fe X, Y, Z, T; } ge;

/* d = -121665/121666 mod p */
static const unsigned char d_bytes[32] = {
	0xa3,0x78,0x59,0x13,0xca,0x4d,0xeb,0x75,
	0xab,0xd8,0x41,0x41,0x4d,0x0a,0x70,0x00,
	0x98,0xe8,0x79,0x77,0x79,0x40,0xc7,0x8c,
	0x73,0xfe,0x6f,0x2b,0xee,0x6c,0x03,0x52
};

/* 2*d */
static const unsigned char d2_bytes[32] = {
	0x59,0xf1,0xb2,0x26,0x94,0x9b,0xd6,0xeb,
	0x56,0xb1,0x83,0x82,0x9a,0x14,0xe0,0x00,
	0x30,0xd1,0xf3,0xee,0xf2,0x80,0x8e,0x19,
	0xe7,0xfc,0xdf,0x56,0xdc,0xd9,0x06,0x24
};

/* Basepoint: y = 4/5 mod p, x is the positive root */
static const unsigned char by_bytes[32] = {
	0x58,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
	0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
	0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66,
	0x66,0x66,0x66,0x66,0x66,0x66,0x66,0x66
};

static const unsigned char bx_bytes[32] = {
	0x1a,0xd5,0x25,0x8f,0x60,0x2d,0x56,0xc9,
	0xb2,0xa7,0x25,0x95,0x60,0xc7,0x2c,0x69,
	0x5c,0xdc,0xd6,0xfd,0x31,0xe2,0xa4,0xc0,
	0xfe,0x53,0x6e,0xcd,0xd3,0x36,0x69,0x21
};

static void ge_zero(ge *p) {
	fe_zero(p->X); fe_one(p->Y); fe_one(p->Z); fe_zero(p->T);
}

/* p = p + q (extended coordinates addition) */
static void ge_add_full(ge *r, const ge *p, const ge *q) {
	fe a, b, c, d, e, f, g, h, dd;
	fe_frombytes(dd, d2_bytes);

	fe_sub(a, p->Y, p->X);
	fe_sub(b, q->Y, q->X);
	fe_mul(a, a, b);   /* A = (Y1-X1)*(Y2-X2) */
	fe_add(b, p->Y, p->X);
	fe_add(c, q->Y, q->X);
	fe_mul(b, b, c);   /* B = (Y1+X1)*(Y2+X2) */
	fe_mul(c, p->T, q->T);
	fe_mul(c, c, dd);  /* C = T1*T2*2d */
	fe_mul(d, p->Z, q->Z);
	fe_add(d, d, d);   /* D = 2*Z1*Z2 */
	fe_sub(e, b, a);   /* E = B - A */
	fe_sub(f, d, c);   /* F = D - C */
	fe_add(g, d, c);   /* G = D + C */
	fe_add(h, b, a);   /* H = B + A */
	fe_mul(r->X, e, f);
	fe_mul(r->Y, g, h);
	fe_mul(r->Z, f, g);
	fe_mul(r->T, e, h);
}

static void ge_double(ge *r, const ge *p) {
	fe a, b, c, d, e, f, g, h;

	/* Doubling formula for a=-1 twisted Edwards curve:
	 * A = X^2, B = Y^2, C = 2*Z^2
	 * D = a*A = -A
	 * E = (X+Y)^2 - A - B
	 * G = D + B, F = G - C, H = D - B
	 * X3 = E*F, Y3 = G*H, T3 = E*H, Z3 = F*G
	 */
	fe_sq(a, p->X);
	fe_sq(b, p->Y);
	fe_sq(c, p->Z); fe_add(c, c, c);
	fe_neg(d, a); /* D = -A */
	fe_add(e, p->X, p->Y);
	fe_sq(e, e); fe_sub(e, e, a); fe_sub(e, e, b); /* E */
	fe_add(g, d, b); /* G = D + B */
	fe_sub(h, d, b); /* H = D - B */
	fe_sub(f, g, c); /* F = G - C */
	fe_mul(r->X, e, f);
	fe_mul(r->Y, g, h);
	fe_mul(r->Z, f, g);
	fe_mul(r->T, e, h);
}

/* Fixed-base scalar multiplication using double-and-add */
static void ge_scalarmult_base(ge *r, const unsigned char scalar[32]) {
	ge base, q, tmp;
	int i;

	fe_frombytes(base.X, bx_bytes);
	fe_frombytes(base.Y, by_bytes);
	fe_one(base.Z);
	fe_mul(base.T, base.X, base.Y);

	ge_zero(&q);

	for (i = 255; i >= 0; i--) {
		ge_double(&tmp, &q);
		fe_copy(q.X, tmp.X); fe_copy(q.Y, tmp.Y);
		fe_copy(q.Z, tmp.Z); fe_copy(q.T, tmp.T);
		if ((scalar[i >> 3] >> (i & 7)) & 1) {
			ge_add_full(&tmp, &q, &base);
			fe_copy(q.X, tmp.X); fe_copy(q.Y, tmp.Y);
			fe_copy(q.Z, tmp.Z); fe_copy(q.T, tmp.T);
		}
	}
	fe_copy(r->X, q.X);
	fe_copy(r->Y, q.Y);
	fe_copy(r->Z, q.Z);
	fe_copy(r->T, q.T);
}

static void ge_tobytes(unsigned char out[32], const ge *p) {
	fe recip, x, y;
	fe_inv(recip, p->Z);
	fe_mul(x, p->X, recip);
	fe_mul(y, p->Y, recip);
	fe_tobytes(out, y);
	out[31] ^= fe_isneg(x) << 7;
}

/* Scalar multiplication of arbitrary point (for verification) */
static void ge_scalarmult(ge *r, const unsigned char scalar[32], const ge *p) {
	ge q, tmp;
	int i;
	ge_zero(&q);

	for (i = 255; i >= 0; i--) {
		ge_double(&tmp, &q);
		fe_copy(q.X, tmp.X); fe_copy(q.Y, tmp.Y);
		fe_copy(q.Z, tmp.Z); fe_copy(q.T, tmp.T);
		if ((scalar[i >> 3] >> (i & 7)) & 1) {
			ge_add_full(&tmp, &q, p);
			fe_copy(q.X, tmp.X); fe_copy(q.Y, tmp.Y);
			fe_copy(q.Z, tmp.Z); fe_copy(q.T, tmp.T);
		}
	}
	fe_copy(r->X, q.X);
	fe_copy(r->Y, q.Y);
	fe_copy(r->Z, q.Z);
	fe_copy(r->T, q.T);
}

/* sqrt(-1) mod p — used when recovering x from y on Ed25519 */
static const unsigned char sqrtm1_bytes[32] = {
	0xb0,0xa0,0x0e,0x4a,0x27,0x1b,0xee,0xc4,
	0x78,0xe4,0x2f,0xad,0x06,0x18,0x43,0x2f,
	0xa7,0xd7,0xfb,0x3d,0x99,0x00,0x4d,0x2b,
	0x0b,0xdf,0xc1,0x4f,0x80,0x24,0x83,0x2b
};

/* Decode a compressed Ed25519 point (RFC 8032 §5.1.3). Returns 0 on success. */
static int ge_frombytes(ge *h, const unsigned char s[32])
{
	fe u, v, v3, vxx, check, sqrtm1;
	unsigned char y_bytes[32];

	/* Clear the sign bit so y is a pure field element */
	memcpy(y_bytes, s, 32);
	y_bytes[31] &= 0x7f;

	fe_frombytes(h->Y, y_bytes);
	fe_one(h->Z);
	fe_sq(u, h->Y);
	fe_frombytes(v, d_bytes);
	fe_mul(v, u, v);          /* v = d * y^2 */
	fe_sub(u, u, h->Z);       /* u = y^2 - 1 */
	fe_add(v, v, h->Z);       /* v = d*y^2 + 1 */

	/* x = u * v^3 * (u * v^7)^((p-5)/8) */
	fe_sq(v3, v);
	fe_mul(v3, v3, v);        /* v^3 */
	fe_sq(h->X, v3);
	fe_mul(h->X, h->X, v);
	fe_mul(h->X, h->X, u);    /* uv^7 */
	fe_pow2523(h->X, h->X);
	fe_mul(h->X, h->X, v3);
	fe_mul(h->X, h->X, u);

	/* Check v*x^2 == ±u */
	fe_sq(vxx, h->X);
	fe_mul(vxx, vxx, v);
	fe_sub(check, vxx, u);
	if (fe_isnonzero(check)) {
		fe_add(check, vxx, u);
		if (fe_isnonzero(check))
			return -1;
		fe_frombytes(sqrtm1, sqrtm1_bytes);
		fe_mul(h->X, h->X, sqrtm1);
	}

	/* Match the sign bit from the encoding */
	if (fe_isneg(h->X) != (s[31] >> 7))
		fe_neg(h->X, h->X);

	fe_mul(h->T, h->X, h->Y);
	return 0;
}

/* Projective equality: X1/Z1 == X2/Z2 and Y1/Z1 == Y2/Z2 */
static int ge_equal(const ge *a, const ge *b)
{
	fe t0, t1;
	fe_mul(t0, a->X, b->Z);
	fe_mul(t1, b->X, a->Z);
	fe_sub(t0, t0, t1);
	if (fe_isnonzero(t0))
		return 0;
	fe_mul(t0, a->Y, b->Z);
	fe_mul(t1, b->Y, a->Z);
	fe_sub(t0, t0, t1);
	return !fe_isnonzero(t0);
}

/* Return 1 if s is a canonical scalar (0 <= s < L), else 0. */
static int sc_is_canonical(const unsigned char s[32])
{
	static const unsigned char L[32] = {
		0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
		0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x10
	};
	int i;
	/* Compare little-endian: s must be strictly less than L */
	for (i = 31; i >= 0; i--) {
		if (s[i] < L[i])
			return 1;
		if (s[i] > L[i])
			return 0;
	}
	return 0; /* s == L is not allowed */
}

/* ---- Ed25519 sign/verify -------------------------------------------- */

/* Reduce a 512-bit number (64 bytes LE) modulo the group order L.
 * L = 2^252 + 27742317777372353535851937790883648493
 * Uses 24 limbs of 21 bits for sufficient precision. */
static void sc_reduce(unsigned char out[32], const unsigned char h[64])
{
	/* Load into 24 limbs of ~21 bits each (covers 504 bits > 512) */
	long long s[24];
	int i;

	/* Each limb holds 21 bits from the byte stream */
	s[0]  = (long long)(h[0] | ((long long)h[1]<<8) | ((long long)h[2]<<16)) & 0x1fffff;
	s[1]  = (long long)(((long long)h[2]>>5) | ((long long)h[3]<<3) | ((long long)h[4]<<11) | ((long long)h[5]<<19)) & 0x1fffff;
	s[2]  = (long long)(((long long)h[5]>>2) | ((long long)h[6]<<6) | ((long long)h[7]<<14)) & 0x1fffff;
	s[3]  = (long long)(((long long)h[7]>>7) | ((long long)h[8]<<1) | ((long long)h[9]<<9) | ((long long)h[10]<<17)) & 0x1fffff;
	s[4]  = (long long)(((long long)h[10]>>4) | ((long long)h[11]<<4) | ((long long)h[12]<<12) | ((long long)h[13]<<20)) & 0x1fffff;
	s[5]  = (long long)(((long long)h[13]>>1) | ((long long)h[14]<<7) | ((long long)h[15]<<15)) & 0x1fffff;
	s[6]  = (long long)(((long long)h[15]>>6) | ((long long)h[16]<<2) | ((long long)h[17]<<10) | ((long long)h[18]<<18)) & 0x1fffff;
	s[7]  = (long long)(((long long)h[18]>>3) | ((long long)h[19]<<5) | ((long long)h[20]<<13)) & 0x1fffff;
	s[8]  = (long long)(h[21] | ((long long)h[22]<<8) | ((long long)h[23]<<16)) & 0x1fffff;
	s[9]  = (long long)(((long long)h[23]>>5) | ((long long)h[24]<<3) | ((long long)h[25]<<11) | ((long long)h[26]<<19)) & 0x1fffff;
	s[10] = (long long)(((long long)h[26]>>2) | ((long long)h[27]<<6) | ((long long)h[28]<<14)) & 0x1fffff;
	s[11] = (long long)(((long long)h[28]>>7) | ((long long)h[29]<<1) | ((long long)h[30]<<9) | ((long long)h[31]<<17)) & 0x1fffff;
	s[12] = (long long)(((long long)h[31]>>4) | ((long long)h[32]<<4) | ((long long)h[33]<<12) | ((long long)h[34]<<20)) & 0x1fffff;
	s[13] = (long long)(((long long)h[34]>>1) | ((long long)h[35]<<7) | ((long long)h[36]<<15)) & 0x1fffff;
	s[14] = (long long)(((long long)h[36]>>6) | ((long long)h[37]<<2) | ((long long)h[38]<<10) | ((long long)h[39]<<18)) & 0x1fffff;
	s[15] = (long long)(((long long)h[39]>>3) | ((long long)h[40]<<5) | ((long long)h[41]<<13)) & 0x1fffff;
	s[16] = (long long)(h[42] | ((long long)h[43]<<8) | ((long long)h[44]<<16)) & 0x1fffff;
	s[17] = (long long)(((long long)h[44]>>5) | ((long long)h[45]<<3) | ((long long)h[46]<<11) | ((long long)h[47]<<19)) & 0x1fffff;
	s[18] = (long long)(((long long)h[47]>>2) | ((long long)h[48]<<6) | ((long long)h[49]<<14)) & 0x1fffff;
	s[19] = (long long)(((long long)h[49]>>7) | ((long long)h[50]<<1) | ((long long)h[51]<<9) | ((long long)h[52]<<17)) & 0x1fffff;
	s[20] = (long long)(((long long)h[52]>>4) | ((long long)h[53]<<4) | ((long long)h[54]<<12) | ((long long)h[55]<<20)) & 0x1fffff;
	s[21] = (long long)(((long long)h[55]>>1) | ((long long)h[56]<<7) | ((long long)h[57]<<15)) & 0x1fffff;
	s[22] = (long long)(((long long)h[57]>>6) | ((long long)h[58]<<2) | ((long long)h[59]<<10) | ((long long)h[60]<<18)) & 0x1fffff;
	s[23] = (long long)(((long long)h[60]>>3) | ((long long)h[61]<<5) | ((long long)h[62]<<13)) & 0x1fffff;

	/* L in 21-bit limbs:
	 * L = 2^252 + l0 + l1*2^21 + ... where l_i are the 21-bit limbs.
	 * Since 2^252 lands in limb 12, and the low part of L is:
	 * 0x14def9dea2f79cd65812631a5cf5d3ed (128 bits, limbs 0..5)
	 */
	/* Reduction: s[12..23] -= s[12..23] * L_low, carefully propagating carries.
	 * This is equivalent to: for each high limb s[i] (i >= 12),
	 * subtract s[i] * L and add s[i] * 2^(252) which cancels with itself.
	 * But simpler: just compute (512-bit number) mod L using Python-style
	 * big integer arithmetic, since this is didactic code. */

	/* Simpler approach: convert back to bytes, do big-int mod L */
	/* Actually, let's just implement it correctly using the ref10 approach
	 * which subtracts multiples of L from the top limbs down. */

	/* L_low = l % 2^252 = 27742317777372353535851937790883648493 */
	/* Limb decomposition of L_low (21-bit limbs, little-endian):
	 * We need: L = sum(l_k * 2^(21k)) for k=0..11, plus 2^252 in limb 12 */
	static const long long l[12] = {
		0x13d3ed, /* bits 0-20 */
		0x0a2c7e, /* bits 21-41 */
		0x1806cb, /* bits 42-62 */
		0x0f4b2b, /* bits 63-83 */
		0x152cb2, /* bits 84-104 */
		0x0e5a23, /* bits 105-125 */
		0x000000, /* bits 126-146 (part of 2^128 region) */
		0x000000,
		0x000000,
		0x000000,
		0x000000,
		0x100000  /* bit 251 = 2^(21*11 + 20) = 2^251... hmm */
	};
	/* This is getting complicated. Let me use a much simpler approach:
	 * just work with the bytes directly using multi-precision arithmetic. */
	(void)l;
	(void)s;

	/* Simple approach: load h as a big integer, divide by L, take remainder */
	/* Using arrays of u64 for multiprecision */
	/* h = h[0] + h[1]*256 + ... (little-endian, 512 bits = 8 x u64) */
	unsigned long long num[8], L_arr[4], q, rem;
	for (i = 0; i < 8; i++) {
		num[i] = 0;
		int j;
		for (j = 0; j < 8 && i*8+j < 64; j++) {
			num[i] |= (unsigned long long)h[i*8+j] << (j*8);
		}
	}

	/* L as 4 x u64 */
	L_arr[0] = 0x5812631a5cf5d3edULL;
	L_arr[1] = 0x14def9dea2f79cd6ULL;
	L_arr[2] = 0;
	L_arr[3] = 0x1000000000000000ULL;

	/* We need num mod L. num is 512 bits, L is 253 bits.
	 * Simple approach: repeated subtraction of L << k for k from 259 down to 0.
	 * This is essentially long division. */

	/* Actually, the simplest correct approach for didactic code:
	 * convert to Python-style big integer and do modulo. */

	/* Let's do it byte by byte: represent as 64-byte LE integer, subtract L*q */

	/* Convert back from our broken limb representation to bytes */
	/* Forget the limb approach. Just do byte-level big-number mod. */

	unsigned char a[65]; /* 65 bytes to avoid overflow */
	for (i = 0; i < 64; i++) a[i] = h[i];
	a[64] = 0;

	/* L in bytes (LE) */
	static const unsigned char Lb[32] = {
		0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
		0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10
	};

	/* Trial subtraction: for each bit position from 263 down to 0,
	 * if a >= L << bit, subtract L << bit from a. */
	/* Max shift: 512 - 253 = 259 bits */
	int bit;
	for (bit = 259; bit >= 0; bit--) {
		/* Check if a >= L << bit */
		/* L << bit occupies bytes [bit/8 .. bit/8 + 32] with sub-byte shift */
		int byte_shift = bit / 8;
		int bit_shift = bit % 8;

		/* Compute L << bit into a temp buffer */
		unsigned char shifted[65];
		memset(shifted, 0, 65);
		int j, carry_s = 0;
		for (j = 0; j < 32; j++) {
			int v = ((int)Lb[j] << bit_shift) | carry_s;
			if (byte_shift + j < 65) {
				shifted[byte_shift + j] = v & 0xff;
			}
			carry_s = v >> 8;
		}
		if (byte_shift + 32 < 65) shifted[byte_shift + 32] = carry_s;

		/* Compare a >= shifted */
		int ge = 0;
		for (j = 64; j >= 0; j--) {
			if (a[j] > shifted[j]) { ge = 1; break; }
			if (a[j] < shifted[j]) { ge = 0; break; }
			if (j == 0) ge = 1; /* equal */
		}

		if (ge) {
			/* a -= shifted */
			int borrow = 0;
			for (j = 0; j < 65; j++) {
				int v = (int)a[j] - (int)shifted[j] - borrow;
				if (v < 0) { v += 256; borrow = 1; }
				else borrow = 0;
				a[j] = (unsigned char)v;
			}
		}
	}

	for (i = 0; i < 32; i++) out[i] = a[i];
}

/* out = (a * b + c) mod L, all 32-byte LE scalars */
static void sc_muladd(unsigned char out[32],
		      const unsigned char a[32],
		      const unsigned char b[32],
		      const unsigned char c[32])
{
	unsigned short prod[64];
	int i, j;
	memset(prod, 0, sizeof(prod));

	/* Schoolbook multiply a * b into prod (byte-level) */
	for (i = 0; i < 32; i++) {
		unsigned int carry = 0;
		for (j = 0; j < 32; j++) {
			carry += prod[i + j] +
				 (unsigned int)a[i] * (unsigned int)b[j];
			prod[i + j] = carry & 0xff;
			carry >>= 8;
		}
		prod[i + 32] += carry;
	}

	/* Add c */
	{
		unsigned int carry = 0;
		for (i = 0; i < 64; i++) {
			carry += prod[i] + (i < 32 ? (unsigned int)c[i] : 0);
			prod[i] = carry & 0xff;
			carry >>= 8;
		}
	}

	/* Reduce mod L */
	unsigned char h[64];
	for (i = 0; i < 64; i++) h[i] = (unsigned char)prod[i];
	sc_reduce(out, h);
}

void ed25519_public_from_seed(const unsigned char seed[32],
			      unsigned char pub[32])
{
	unsigned char h[64];
	ge A;
	sha512(seed, 32, h);
	h[0] &= 248;
	h[31] &= 127;
	h[31] |= 64;
	ge_scalarmult_base(&A, h);
	ge_tobytes(pub, &A);
}

void ed25519_sign(const unsigned char *msg, int msg_len,
		  const unsigned char seed[32], unsigned char sig[64])
{
	unsigned char h[64], nonce_hash[64], pub[32];
	unsigned char hram[64];
	ge R_point;
	unsigned char R_bytes[32], s[32];
	struct sha512_ctx shctx;

	/* Step 1: expand seed */
	sha512(seed, 32, h);
	h[0] &= 248;
	h[31] &= 127;
	h[31] |= 64;
	/* h[0..31] is the scalar a, h[32..63] is the nonce prefix */

	/* Compute public key */
	ge_scalarmult_base(&R_point, h);
	ge_tobytes(pub, &R_point);

	/* Step 2: nonce r = SHA-512(h[32..63] || msg) mod L */
	sha512_init(&shctx);
	sha512_update(&shctx, h + 32, 32);
	sha512_update(&shctx, msg, msg_len);
	sha512_final(&shctx, nonce_hash);
	unsigned char r[32];
	sc_reduce(r, nonce_hash);

	/* Step 3: R = r * B */
	ge_scalarmult_base(&R_point, r);
	ge_tobytes(R_bytes, &R_point);

	/* Step 4: S = r + SHA-512(R || pub || msg) * a mod L */
	sha512_init(&shctx);
	sha512_update(&shctx, R_bytes, 32);
	sha512_update(&shctx, pub, 32);
	sha512_update(&shctx, msg, msg_len);
	sha512_final(&shctx, hram);

	unsigned char hram_reduced[32];
	sc_reduce(hram_reduced, hram);
	sc_muladd(s, hram_reduced, h, r);

	memcpy(sig, R_bytes, 32);
	memcpy(sig + 32, s, 32);
}

/*
 * Ed25519 verification (RFC 8032 §5.1.7):
 * Check that [S]B = R + [k]A where k = SHA-512(R || A || M) mod L.
 * Returns 0 on success, -1 on failure.
 */
int ed25519_verify(const unsigned char *msg, int msg_len,
		   const unsigned char pub[32],
		   const unsigned char sig[64])
{
	unsigned char hram[64], k[32];
	const unsigned char *R = sig;
	const unsigned char *S = sig + 32;
	ge A, R_pt, SB, kA, rhs;
	struct sha512_ctx shctx;

	/* S must be a canonical scalar */
	if (!sc_is_canonical(S)) {
		puts("Ed25519: S not canonical");
		return -1;
	}

	/* Decode public key A and commitment R */
	if (ge_frombytes(&A, pub) < 0) {
		puts("Ed25519: bad public key");
		return -1;
	}
	if (ge_frombytes(&R_pt, R) < 0) {
		puts("Ed25519: bad R in signature");
		return -1;
	}

	/* k = SHA-512(R || A || M) mod L */
	sha512_init(&shctx);
	sha512_update(&shctx, R, 32);
	sha512_update(&shctx, pub, 32);
	sha512_update(&shctx, msg, msg_len);
	sha512_final(&shctx, hram);
	sc_reduce(k, hram);

	/* rhs = R + [k]A */
	ge_scalarmult(&kA, k, &A);
	ge_add_full(&rhs, &R_pt, &kA);

	/* lhs = [S]B */
	ge_scalarmult_base(&SB, S);

	if (!ge_equal(&SB, &rhs)) {
		puts("Ed25519: equation check failed");
		return -1;
	}
	return 0;
}

/* Legacy wrapper */
void i32_add(unsigned char *a, unsigned char *b, unsigned char *out)
{
	int carry = 0;
	int sum = 0;
	int i;
	for (i = 0; i < 32; i++) {
		sum = (int)a[i] + (int)b[i] + carry;
		out[i] = (unsigned char)(sum & 0xff);
		carry = sum >> 8;
	}
}
