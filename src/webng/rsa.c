/*
 * Didactic RSA for TLS 1.3 CertificateVerify:
 *   rsa_pss_rsae_sha256 (SignatureScheme 0x0804)
 *
 * Big integers are little-endian arrays of 32-bit limbs.
 * On the wire / in DER, RSA numbers are big-endian bytes.
 */

#include "rsa.h"
#include "sha256.h"
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---- Limb bigints --------------------------------------------------- */

#define BN_LIMBS (RSA_MAX_BYTES / 4) /* 128 limbs = 4096 bits */

typedef struct {
	unsigned int v[BN_LIMBS];
	int n; /* number of used limbs */
} bn;

static void bn_zero(bn *a)
{
	memset(a->v, 0, sizeof(a->v));
	a->n = 0;
}

static void bn_set_u32(bn *a, unsigned int x)
{
	bn_zero(a);
	if (x) {
		a->v[0] = x;
		a->n = 1;
	}
}

static void bn_norm(bn *a)
{
	while (a->n > 0 && a->v[a->n - 1] == 0)
		a->n--;
}

/* Import big-endian bytes */
static void bn_from_be(bn *a, const unsigned char *buf, int len)
{
	int i;
	bn_zero(a);
	/* skip leading zeros */
	while (len > 0 && *buf == 0) {
		buf++;
		len--;
	}
	for (i = 0; i < len; i++) {
		int bit = (len - 1 - i) * 8;
		int li = bit / 32;
		int sh = bit % 32;
		if (li >= BN_LIMBS)
			continue;
		a->v[li] |= ((unsigned int)buf[i]) << sh;
		if (li + 1 > a->n)
			a->n = li + 1;
	}
	bn_norm(a);
}

/* Export fixed-width big-endian (pad left with zeros) */
static void bn_to_be(const bn *a, unsigned char *buf, int len)
{
	int i;
	memset(buf, 0, len);
	for (i = 0; i < len; i++) {
		int bit = (len - 1 - i) * 8;
		int li = bit / 32;
		int sh = bit % 32;
		if (li < a->n)
			buf[i] = (unsigned char)((a->v[li] >> sh) & 0xff);
	}
}

static int bn_cmp(const bn *a, const bn *b)
{
	int i, na = a->n, nb = b->n;
	if (na > nb)
		return 1;
	if (na < nb)
		return -1;
	for (i = na - 1; i >= 0; i--) {
		if (a->v[i] > b->v[i])
			return 1;
		if (a->v[i] < b->v[i])
			return -1;
	}
	return 0;
}

static void bn_copy(bn *d, const bn *s)
{
	*d = *s;
}

/* d = a - b, assumes a >= b */
static void bn_sub(bn *d, const bn *a, const bn *b)
{
	long long c = 0;
	int i, n = a->n;
	for (i = 0; i < n; i++) {
		c = (long long)a->v[i] - (long long)(i < b->n ? b->v[i] : 0) +
		    c;
		d->v[i] = (unsigned int)c;
		c >>= 32; /* 0 or -1 */
	}
	d->n = n;
	for (; i < BN_LIMBS; i++)
		d->v[i] = 0;
	bn_norm(d);
}

/* schoolbook multiply: d = a * b (d must not alias a or b if overlapping) */
static void bn_mul(bn *d, const bn *a, const bn *b)
{
	int i, j;
	unsigned long long c;
	bn_zero(d);
	if (a->n == 0 || b->n == 0)
		return;
	for (i = 0; i < a->n; i++) {
		c = 0;
		for (j = 0; j < b->n; j++) {
			if (i + j >= BN_LIMBS)
				break;
			c += (unsigned long long)d->v[i + j] +
			     (unsigned long long)a->v[i] * b->v[j];
			d->v[i + j] = (unsigned int)c;
			c >>= 32;
		}
		if (i + j < BN_LIMBS && c)
			d->v[i + j] = (unsigned int)c;
	}
	d->n = a->n + b->n;
	if (d->n > BN_LIMBS)
		d->n = BN_LIMBS;
	bn_norm(d);
}

/* Bit length (for PSS emBits = modBits - 1) */
static int bn_bitlen(const bn *a)
{
	int i;
	unsigned int w;
	if (a->n == 0)
		return 0;
	w = a->v[a->n - 1];
	i = 32;
	while (i > 0 && ((w >> (i - 1)) & 1) == 0)
		i--;
	return (a->n - 1) * 32 + i;
}

/* r = a << bits (bits may be large) */
static void bn_shl(bn *d, const bn *a, int bits)
{
	int limb = bits / 32, sh = bits % 32;
	int i;
	bn_zero(d);
	if (a->n == 0)
		return;
	if (sh == 0) {
		for (i = a->n - 1; i >= 0; i--) {
			if (i + limb < BN_LIMBS)
				d->v[i + limb] = a->v[i];
		}
		d->n = a->n + limb;
	} else {
		unsigned long long c = 0;
		for (i = 0; i < a->n; i++) {
			c |= (unsigned long long)a->v[i] << sh;
			if (i + limb < BN_LIMBS)
				d->v[i + limb] = (unsigned int)c;
			c >>= 32;
		}
		if (c && a->n + limb < BN_LIMBS)
			d->v[a->n + limb] = (unsigned int)c;
		d->n = a->n + limb + 1;
	}
	if (d->n > BN_LIMBS)
		d->n = BN_LIMBS;
	bn_norm(d);
}

/*
 * Modular reduction: r = x mod m.
 * Binary long division: subtract m shifted to align MSBs (learning-friendly).
 */
static void bn_mod(bn *r, const bn *x, const bn *m)
{
	bn cur, ms;
	int xb, mb, shift;

	bn_copy(&cur, x);
	if (bn_cmp(&cur, m) < 0) {
		bn_copy(r, &cur);
		return;
	}
	xb = bn_bitlen(&cur);
	mb = bn_bitlen(m);
	for (shift = xb - mb; shift >= 0; shift--) {
		bn_shl(&ms, m, shift);
		if (bn_cmp(&cur, &ms) >= 0)
			bn_sub(&cur, &cur, &ms);
	}
	bn_copy(r, &cur);
}

/* r = (a * b) mod m */
static void bn_modmul(bn *r, const bn *a, const bn *b, const bn *m)
{
	bn t;
	bn_mul(&t, a, b);
	bn_mod(r, &t, m);
}

/* r = base^exp mod m  (exp is big-endian bytes) */
static void bn_modexp(bn *r, const bn *base, const unsigned char *exp,
		      int exp_len, const bn *m)
{
	bn res, b, t;
	int i, j;

	bn_set_u32(&res, 1);
	bn_copy(&b, base);
	/* skip leading zero bytes of exp */
	while (exp_len > 0 && *exp == 0) {
		exp++;
		exp_len--;
	}
	for (i = 0; i < exp_len; i++) {
		for (j = 7; j >= 0; j--) {
			bn_modmul(&t, &res, &res, m); /* square */
			bn_copy(&res, &t);
			if ((exp[i] >> j) & 1) {
				bn_modmul(&t, &res, &b, m);
				bn_copy(&res, &t);
			}
		}
	}
	bn_copy(r, &res);
}

/* ---- MGF1-SHA256 (RFC 8017 B.2.1) ------------------------------------ */

static void mgf1_sha256(const unsigned char *seed, int seed_len,
			unsigned char *mask, int mask_len)
{
	unsigned char cnt[4], hash[32];
	struct sha256_ctx ctx;
	int out = 0, c = 0;

	while (out < mask_len) {
		cnt[0] = (c >> 24) & 0xff;
		cnt[1] = (c >> 16) & 0xff;
		cnt[2] = (c >> 8) & 0xff;
		cnt[3] = c & 0xff;
		sha256_init(&ctx);
		sha256_update(&ctx, seed, seed_len);
		sha256_update(&ctx, cnt, 4);
		sha256_final(&ctx, hash);
		{
			int take = mask_len - out;
			if (take > 32)
				take = 32;
			memcpy(mask + out, hash, take);
			out += take;
		}
		c++;
	}
}

static int read_random(unsigned char *buf, int len)
{
	int fd = open("/dev/urandom", O_RDONLY);
	int total = 0, n;
	if (fd < 0)
		return -1;
	while (total < len) {
		n = read(fd, buf + total, len - total);
		if (n <= 0) {
			close(fd);
			return -1;
		}
		total += n;
	}
	close(fd);
	return 0;
}

/* ---- EMSA-PSS-SHA256 (saltLen = 32) ---------------------------------- */

static int pss_encode(const unsigned char *mhash /*32*/, int mod_bits,
		      unsigned char *em, int em_len)
{
	/* emBits = modBits - 1 per RFC 8017 */
	int em_bits = mod_bits - 1;
	int h_len = 32, s_len = 32;
	unsigned char salt[32], mp[8 + 32 + 32], h[32];
	unsigned char *db, *masked_db;
	int db_len, i;
	struct sha256_ctx ctx;

	if (em_len < h_len + s_len + 2)
		return -1;

	/* recompute em_len from em_bits if needed — caller sets em_len = ceil(emBits/8) */
	(void)em_bits;

	if (read_random(salt, 32) < 0)
		return -1;

	/* M' = 0x00×8 || mHash || salt */
	memset(mp, 0, 8);
	memcpy(mp + 8, mhash, 32);
	memcpy(mp + 40, salt, 32);
	sha256_init(&ctx);
	sha256_update(&ctx, mp, 8 + 32 + 32);
	sha256_final(&ctx, h);

	db_len = em_len - h_len - 1;
	db = em; /* DB sits at start of EM temporarily */
	memset(db, 0, db_len);
	db[db_len - s_len - 1] = 0x01;
	memcpy(db + db_len - s_len, salt, s_len);

	/* maskedDB = DB xor MGF(H) */
	{
		unsigned char mask[RSA_MAX_BYTES];
		mgf1_sha256(h, h_len, mask, db_len);
		for (i = 0; i < db_len; i++)
			db[i] ^= mask[i];
	}

	/* Clear the leftmost 8emLen - emBits bits */
	{
		int nz = 8 * em_len - em_bits;
		if (nz > 0)
			db[0] &= (unsigned char)(0xff >> nz);
	}

	masked_db = em;
	(void)masked_db;
	memcpy(em + db_len, h, h_len);
	em[em_len - 1] = 0xbc;
	return 0;
}

static int pss_verify(const unsigned char *mhash /*32*/, int mod_bits,
		      const unsigned char *em, int em_len)
{
	int em_bits = mod_bits - 1;
	int h_len = 32, s_len = 32;
	int db_len = em_len - h_len - 1;
	unsigned char mask[RSA_MAX_BYTES], db[RSA_MAX_BYTES];
	unsigned char h[32], mp[8 + 32 + 32], h2[32];
	const unsigned char *salt;
	int i, nz;
	struct sha256_ctx ctx;

	if (em_len < h_len + s_len + 2)
		return -1;
	if (em[em_len - 1] != 0xbc)
		return -1;

	memcpy(db, em, db_len);
	memcpy(h, em + db_len, h_len);

	/* Check leftmost bits are zero */
	nz = 8 * em_len - em_bits;
	if (nz > 0) {
		unsigned char top = (unsigned char)(0xff << (8 - nz));
		/* bits that must be zero */
		if (em[0] & ~((unsigned char)(0xff >> nz)))
			return -1;
		(void)top;
	}

	mgf1_sha256(h, h_len, mask, db_len);
	for (i = 0; i < db_len; i++)
		db[i] ^= mask[i];
	if (nz > 0)
		db[0] &= (unsigned char)(0xff >> nz);

	/* DB = PS || 0x01 || salt — PS must be zero */
	for (i = 0; i < db_len - s_len - 1; i++) {
		if (db[i] != 0)
			return -1;
	}
	if (db[db_len - s_len - 1] != 0x01)
		return -1;
	salt = db + db_len - s_len;

	memset(mp, 0, 8);
	memcpy(mp + 8, mhash, 32);
	memcpy(mp + 40, salt, 32);
	sha256_init(&ctx);
	sha256_update(&ctx, mp, 8 + 32 + 32);
	sha256_final(&ctx, h2);

	for (i = 0; i < 32; i++) {
		if (h[i] != h2[i])
			return -1;
	}
	return 0;
}

/* ---- Public RSA-PSS API --------------------------------------------- */

int rsa_pss_sha256_sign(const struct rsa_key *key,
			const unsigned char *msg, int msg_len,
			unsigned char *sig, int *sig_len)
{
	unsigned char mhash[32], em[RSA_MAX_BYTES];
	bn n, d, m, s;
	int mod_bits, em_len;

	if (key->n_len <= 0 || key->d_len <= 0 || key->n_len > RSA_MAX_BYTES)
		return -1;

	sha256(msg, msg_len, mhash);
	bn_from_be(&n, key->n, key->n_len);
	mod_bits = bn_bitlen(&n);
	em_len = (mod_bits + 6) / 8; /* ceil((modBits-1)/8) */
	if (em_len > key->n_len)
		em_len = key->n_len;
	/* TLS / PKCS#1: k = |n| octets for the signature */
	em_len = key->n_len;

	if (pss_encode(mhash, mod_bits, em, em_len) < 0)
		return -1;

	/* Ensure EM < n by construction of emBits = modBits-1 */
	bn_from_be(&m, em, em_len);
	if (bn_cmp(&m, &n) >= 0) {
		puts("RSA-PSS: encoded message >= modulus");
		return -1;
	}

	bn_from_be(&d, key->d, key->d_len);
	bn_modexp(&s, &m, key->d, key->d_len, &n);
	bn_to_be(&s, sig, key->n_len);
	*sig_len = key->n_len;
	return 0;
}

int rsa_pss_sha256_verify(const struct rsa_key *key,
			  const unsigned char *msg, int msg_len,
			  const unsigned char *sig, int sig_len)
{
	unsigned char mhash[32], em[RSA_MAX_BYTES];
	bn n, s, m;
	int mod_bits, em_len;

	if (key->n_len <= 0 || sig_len != key->n_len)
		return -1;

	sha256(msg, msg_len, mhash);
	bn_from_be(&n, key->n, key->n_len);
	bn_from_be(&s, sig, sig_len);
	if (bn_cmp(&s, &n) >= 0) {
		puts("RSA: signature out of range");
		return -1;
	}

	/* m = s^e mod n */
	bn_modexp(&m, &s, key->e, key->e_len, &n);
	em_len = key->n_len;
	bn_to_be(&m, em, em_len);
	mod_bits = bn_bitlen(&n);

	if (pss_verify(mhash, mod_bits, em, em_len) < 0) {
		puts("RSA-PSS: padding check failed");
		return -1;
	}
	return 0;
}

/* ---- Minimal ASN.1 DER helpers -------------------------------------- */

static int der_len(const unsigned char *p, int max, int *hdr)
{
	int len, n;
	if (max < 2)
		return -1;
	if (!(p[0] & 0x80)) {
		*hdr = 1;
		return p[0];
	}
	n = p[0] & 0x7f;
	if (n == 0 || n > 3 || max < 1 + n)
		return -1;
	len = 0;
	{
		int i;
		for (i = 0; i < n; i++)
			len = (len << 8) | p[1 + i];
	}
	*hdr = 1 + n;
	return len;
}

/* Skip tag+length, return content pointer and length */
static int der_enter(const unsigned char *p, int max, unsigned char tag,
		     const unsigned char **content, int *clen)
{
	int hdr, len;
	if (max < 1 || p[0] != tag)
		return -1;
	len = der_len(p + 1, max - 1, &hdr);
	if (len < 0 || 1 + hdr + len > max)
		return -1;
	*content = p + 1 + hdr;
	*clen = len;
	return 1 + hdr + len; /* total bytes consumed */
}

/* Read INTEGER into big-endian buffer, strip optional leading 0x00 */
static int der_integer(const unsigned char *p, int max,
		       unsigned char *out, int out_max, int *out_len,
		       int *consumed)
{
	const unsigned char *c;
	int clen, total, start = 0;

	total = der_enter(p, max, 0x02, &c, &clen);
	if (total < 0 || clen < 1)
		return -1;
	/* leading 0x00 means positive number with high bit set */
	if (clen > 1 && c[0] == 0x00) {
		start = 1;
	}
	*out_len = clen - start;
	if (*out_len > out_max)
		return -1;
	memcpy(out, c + start, *out_len);
	*consumed = total;
	return 0;
}

/* rsaEncryption OID: 1.2.840.113549.1.1.1 */
static const unsigned char oid_rsa[] = {
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01
};

int rsa_pub_from_cert(const unsigned char *der, int der_len,
		      struct rsa_key *key)
{
	int i, j;

	memset(key, 0, sizeof(*key));

	/* Find rsaEncryption OID, then the following BIT STRING */
	for (i = 0; i + (int)sizeof(oid_rsa) < der_len; i++) {
		if (memcmp(der + i, oid_rsa, sizeof(oid_rsa)) != 0)
			continue;

		/* Scan forward for BIT STRING 03 ... that holds RSAPublicKey */
		for (j = i; j + 4 < der_len; j++) {
			if (der[j] != 0x03)
				continue;
			{
				int hdr, blen;
				const unsigned char *bs;
				int t = der_enter(der + j, der_len - j, 0x03,
						  &bs, &blen);
				const unsigned char *pk;
				int pk_len, used, c1, c2;

				if (t < 0 || blen < 10)
					continue;
				/* unused bits byte must be 0 */
				if (bs[0] != 0x00)
					continue;
				pk = bs + 1;
				pk_len = blen - 1;
				/* RSAPublicKey ::= SEQUENCE { n INTEGER, e INTEGER } */
				if (pk[0] != 0x30)
					continue;
				{
					const unsigned char *seq;
					int seq_len;
					if (der_enter(pk, pk_len, 0x30, &seq,
						      &seq_len) < 0)
						continue;
					if (der_integer(seq, seq_len, key->n,
							RSA_MAX_BYTES,
							&key->n_len,
							&c1) < 0)
						continue;
					if (der_integer(seq + c1, seq_len - c1,
							key->e, RSA_MAX_BYTES,
							&key->e_len,
							&c2) < 0)
						continue;
					printf("RSA public key: n=%d bytes, e=%d bytes\n",
					       key->n_len, key->e_len);
					return 0;
				}
				(void)used;
				(void)hdr;
			}
		}
	}
	puts("No RSA public key found in certificate");
	return -1;
}

int rsa_priv_from_der(const unsigned char *der, int der_len,
		      struct rsa_key *key)
{
	const unsigned char *p = der;
	int max = der_len;
	const unsigned char *seq, *inner;
	int seq_len, inner_len, c, ver_len;
	unsigned char ver[8];
	int is_pkcs8 = 0;

	memset(key, 0, sizeof(*key));
	if (max < 1 || p[0] != 0x30)
		return -1;
	if (der_enter(p, max, 0x30, &seq, &seq_len) < 0)
		return -1;

	/*
	 * PKCS#8: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING }
	 * PKCS#1: SEQUENCE { version, n, e, d, ... }
	 * Detect PKCS#8 by looking for rsaEncryption OID near the start.
	 */
	{
		int k;
		for (k = 0; k + (int)sizeof(oid_rsa) < seq_len && k < 40; k++) {
			if (memcmp(seq + k, oid_rsa, sizeof(oid_rsa)) == 0) {
				is_pkcs8 = 1;
				break;
			}
		}
	}

	if (is_pkcs8) {
		/* Walk: version INTEGER, alg SEQUENCE, privateKey OCTET STRING */
		const unsigned char *q = seq;
		int qlen = seq_len;
		/* version */
		if (der_integer(q, qlen, ver, sizeof(ver), &ver_len, &c) < 0)
			return -1;
		q += c;
		qlen -= c;
		/* AlgorithmIdentifier SEQUENCE — skip */
		{
			int tot = der_enter(q, qlen, 0x30, &inner, &inner_len);
			if (tot < 0)
				return -1;
			q += tot;
			qlen -= tot;
		}
		/* OCTET STRING wrapping RSAPrivateKey */
		if (der_enter(q, qlen, 0x04, &inner, &inner_len) < 0)
			return -1;
		/* Recurse into PKCS#1 body */
		return rsa_priv_from_der(inner, inner_len, key);
	}

	/* PKCS#1 RSAPrivateKey */
	if (der_integer(seq, seq_len, ver, sizeof(ver), &ver_len, &c) < 0)
		return -1;
	seq += c;
	seq_len -= c;
	if (der_integer(seq, seq_len, key->n, RSA_MAX_BYTES, &key->n_len,
			&c) < 0)
		return -1;
	seq += c;
	seq_len -= c;
	if (der_integer(seq, seq_len, key->e, RSA_MAX_BYTES, &key->e_len,
			&c) < 0)
		return -1;
	seq += c;
	seq_len -= c;
	if (der_integer(seq, seq_len, key->d, RSA_MAX_BYTES, &key->d_len,
			&c) < 0)
		return -1;

	printf("Loaded RSA private key: n=%d bytes d=%d bytes\n",
	       key->n_len, key->d_len);
	return 0;
}
