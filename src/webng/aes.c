#include "aes.h"
#include <string.h>

/* ---- AES-128 core --------------------------------------------------- */

static const unsigned char sbox[256] = {
	0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,
	0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
	0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,
	0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
	0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,
	0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
	0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,
	0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
	0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,
	0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
	0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,
	0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
	0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,
	0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
	0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,
	0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
	0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,
	0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
	0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,
	0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
	0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,
	0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
	0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,
	0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
	0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,
	0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
	0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,
	0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
	0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,
	0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
	0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,
	0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const unsigned char rcon[10] = {
	0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static void key_expansion(const unsigned char key[16],
			   unsigned char rkeys[176])
{
	int i;
	unsigned char tmp[4];
	memcpy(rkeys, key, 16);

	for (i = 4; i < 44; i++) {
		memcpy(tmp, &rkeys[(i - 1) * 4], 4);
		if (i % 4 == 0) {
			unsigned char t = tmp[0];
			tmp[0] = sbox[tmp[1]] ^ rcon[i / 4 - 1];
			tmp[1] = sbox[tmp[2]];
			tmp[2] = sbox[tmp[3]];
			tmp[3] = sbox[t];
		}
		rkeys[i * 4]     = rkeys[(i - 4) * 4]     ^ tmp[0];
		rkeys[i * 4 + 1] = rkeys[(i - 4) * 4 + 1] ^ tmp[1];
		rkeys[i * 4 + 2] = rkeys[(i - 4) * 4 + 2] ^ tmp[2];
		rkeys[i * 4 + 3] = rkeys[(i - 4) * 4 + 3] ^ tmp[3];
	}
}

static void sub_bytes(unsigned char s[16])
{
	int i;
	for (i = 0; i < 16; i++) s[i] = sbox[s[i]];
}

static void shift_rows(unsigned char s[16])
{
	unsigned char t;
	/* Row 1: shift left 1 */
	t = s[1]; s[1] = s[5]; s[5] = s[9]; s[9] = s[13]; s[13] = t;
	/* Row 2: shift left 2 */
	t = s[2]; s[2] = s[10]; s[10] = t;
	t = s[6]; s[6] = s[14]; s[14] = t;
	/* Row 3: shift left 3 */
	t = s[15]; s[15] = s[11]; s[11] = s[7]; s[7] = s[3]; s[3] = t;
}

static unsigned char xtime(unsigned char x)
{
	return (x << 1) ^ ((x & 0x80) ? 0x1b : 0);
}

static void mix_columns(unsigned char s[16])
{
	int i;
	for (i = 0; i < 4; i++) {
		unsigned char a = s[i * 4], b = s[i * 4 + 1];
		unsigned char c = s[i * 4 + 2], d = s[i * 4 + 3];
		unsigned char e = a ^ b ^ c ^ d;
		s[i * 4]     ^= e ^ xtime(a ^ b);
		s[i * 4 + 1] ^= e ^ xtime(b ^ c);
		s[i * 4 + 2] ^= e ^ xtime(c ^ d);
		s[i * 4 + 3] ^= e ^ xtime(d ^ a);
	}
}

static void add_round_key(unsigned char s[16], const unsigned char *rk)
{
	int i;
	for (i = 0; i < 16; i++) s[i] ^= rk[i];
}

void aes128_encrypt_block(const unsigned char key[16],
			  const unsigned char in[16],
			  unsigned char out[16])
{
	unsigned char rkeys[176], s[16];
	int r;
	key_expansion(key, rkeys);
	memcpy(s, in, 16);
	add_round_key(s, rkeys);
	for (r = 1; r < 10; r++) {
		sub_bytes(s);
		shift_rows(s);
		mix_columns(s);
		add_round_key(s, &rkeys[r * 16]);
	}
	sub_bytes(s);
	shift_rows(s);
	add_round_key(s, &rkeys[160]);
	memcpy(out, s, 16);
}

/* ---- GCM mode ------------------------------------------------------- */

/* Increment the last 4 bytes of a 16-byte counter */
static void gcm_inc(unsigned char ctr[16])
{
	int i;
	for (i = 15; i >= 12; i--) {
		if (++ctr[i]) break;
	}
}

/* GF(2^128) multiplication for GHASH */
static void gf128_mul(const unsigned char x[16],
		      const unsigned char h[16],
		      unsigned char out[16])
{
	unsigned char v[16], z[16];
	int i, j;
	memcpy(v, h, 16);
	memset(z, 0, 16);

	for (i = 0; i < 16; i++) {
		for (j = 7; j >= 0; j--) {
			if (x[i] & (1 << j)) {
				int k;
				for (k = 0; k < 16; k++) z[k] ^= v[k];
			}
			/* v = v >> 1 in GF(2^128) with reduction */
			unsigned char carry = v[15] & 1;
			int k;
			for (k = 15; k > 0; k--) {
				v[k] = (v[k] >> 1) | (v[k - 1] << 7);
			}
			v[0] >>= 1;
			if (carry) v[0] ^= 0xe1; /* reduction poly */
		}
	}
	memcpy(out, z, 16);
}

/* GHASH: iterative multiplication */
static void ghash(const unsigned char h[16],
		  const unsigned char *data, int len,
		  unsigned char y[16])
{
	int i, j;
	unsigned char tmp[16];
	for (i = 0; i < len; i += 16) {
		int blen = (len - i >= 16) ? 16 : len - i;
		for (j = 0; j < blen; j++) y[j] ^= data[i + j];
		gf128_mul(y, h, tmp);
		memcpy(y, tmp, 16);
	}
}

int aes128_gcm_encrypt(const unsigned char key[16],
		       const unsigned char iv[12],
		       const unsigned char *aad, int aad_len,
		       const unsigned char *pt, int pt_len,
		       unsigned char *ct, unsigned char tag[16])
{
	unsigned char h[16] = {0}, j0[16], ctr[16], ectr[16], y[16];
	unsigned char len_block[16];
	int i;

	/* H = AES(K, 0^128) */
	aes128_encrypt_block(key, h, h);

	/* J0 = IV || 0^31 || 1 */
	memcpy(j0, iv, 12);
	j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

	/* Encrypt with CTR starting from J0 + 1 */
	memcpy(ctr, j0, 16);
	for (i = 0; i < pt_len; i += 16) {
		gcm_inc(ctr);
		aes128_encrypt_block(key, ctr, ectr);
		int blen = (pt_len - i >= 16) ? 16 : pt_len - i;
		int j;
		for (j = 0; j < blen; j++) ct[i + j] = pt[i + j] ^ ectr[j];
	}

	/* Compute GHASH */
	memset(y, 0, 16);
	/* AAD padded to 16 — ghash handles partial blocks already */
	if (aad_len > 0) ghash(h, aad, aad_len, y);

	/* CT padded to 16 */
	if (pt_len > 0) ghash(h, ct, pt_len, y);

	/* Length block: 64-bit AAD len || 64-bit CT len (in bits) */
	memset(len_block, 0, 16);
	{
		unsigned long long aad_bits = (unsigned long long)aad_len * 8;
		unsigned long long ct_bits = (unsigned long long)pt_len * 8;
		for (i = 0; i < 8; i++) {
			len_block[7 - i] = (aad_bits >> (i * 8)) & 0xff;
			len_block[15 - i] = (ct_bits >> (i * 8)) & 0xff;
		}
	}
	ghash(h, len_block, 16, y);

	/* Tag = GHASH XOR AES(K, J0) */
	aes128_encrypt_block(key, j0, ectr);
	for (i = 0; i < 16; i++) tag[i] = y[i] ^ ectr[i];

	return 0;
}

int aes128_gcm_decrypt(const unsigned char key[16],
		       const unsigned char iv[12],
		       const unsigned char *aad, int aad_len,
		       const unsigned char *ct, int ct_len,
		       unsigned char *pt, const unsigned char tag[16])
{
	unsigned char h[16] = {0}, j0[16], ctr[16], ectr[16], y[16];
	unsigned char len_block[16], check[16];
	int i;

	/* H = AES(K, 0^128) */
	aes128_encrypt_block(key, h, h);

	/* J0 */
	memcpy(j0, iv, 12);
	j0[12] = 0; j0[13] = 0; j0[14] = 0; j0[15] = 1;

	/* Verify tag first by computing GHASH over ciphertext */
	memset(y, 0, 16);
	if (aad_len > 0) ghash(h, aad, aad_len, y);
	if (ct_len > 0) ghash(h, ct, ct_len, y);

	memset(len_block, 0, 16);
	{
		unsigned long long aad_bits = (unsigned long long)aad_len * 8;
		unsigned long long ct_bits = (unsigned long long)ct_len * 8;
		for (i = 0; i < 8; i++) {
			len_block[7 - i] = (aad_bits >> (i * 8)) & 0xff;
			len_block[15 - i] = (ct_bits >> (i * 8)) & 0xff;
		}
	}
	ghash(h, len_block, 16, y);

	aes128_encrypt_block(key, j0, ectr);
	for (i = 0; i < 16; i++) check[i] = y[i] ^ ectr[i];

	/* Constant-time compare */
	unsigned char diff = 0;
	for (i = 0; i < 16; i++) diff |= check[i] ^ tag[i];
	if (diff != 0) return -1;

	/* Decrypt with CTR */
	memcpy(ctr, j0, 16);
	for (i = 0; i < ct_len; i += 16) {
		gcm_inc(ctr);
		aes128_encrypt_block(key, ctr, ectr);
		int blen = (ct_len - i >= 16) ? 16 : ct_len - i;
		int j;
		for (j = 0; j < blen; j++) pt[i + j] = ct[i + j] ^ ectr[j];
	}

	return 0;
}