#ifndef RSA_H
#define RSA_H

/* Max RSA modulus size we handle (4096-bit). */
#define RSA_MAX_BYTES 512

struct rsa_key {
	unsigned char n[RSA_MAX_BYTES]; /* modulus, big-endian */
	int n_len;
	unsigned char e[RSA_MAX_BYTES]; /* public exponent */
	int e_len;
	unsigned char d[RSA_MAX_BYTES]; /* private exponent (sign only) */
	int d_len;
};

/* RSA-PSS with SHA-256, salt length = 32 (TLS 1.3 rsa_pss_rsae_sha256).
 * Signature is big-endian, length = n_len.
 * Returns 0 on success, -1 on failure.
 */
int rsa_pss_sha256_sign(const struct rsa_key *key,
			const unsigned char *msg, int msg_len,
			unsigned char *sig, int *sig_len);

int rsa_pss_sha256_verify(const struct rsa_key *key,
			  const unsigned char *msg, int msg_len,
			  const unsigned char *sig, int sig_len);

/* Parse RSA public key from an X.509 DER certificate. */
int rsa_pub_from_cert(const unsigned char *der, int der_len,
		      struct rsa_key *key);

/* Parse RSA private key from PKCS#8 or PKCS#1 DER. */
int rsa_priv_from_der(const unsigned char *der, int der_len,
		      struct rsa_key *key);

#endif
