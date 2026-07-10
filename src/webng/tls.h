#ifndef TLS_H
#define TLS_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "rsa.h"

/* How we authenticate the server (CertificateVerify) */
#define SIGN_ALG_NONE           0
#define SIGN_ALG_ED25519        1
#define SIGN_ALG_RSA_PSS_SHA256 2 /* SignatureScheme 0x0804 */

/* A structure to hold TLS session state */
struct tlsSession {
	char ver[2];
	unsigned char type;
	unsigned char cipher[2];
	unsigned char cli_random[32];
	unsigned char ser_random[32];
	unsigned char cli_public[32];
	unsigned char ser_public[32];
	unsigned char ser_private[32];
	unsigned char cli_private[32];
	unsigned char id_len;
	unsigned char id[32];
	char *proto;
	char renegotiation_set;
	char master_secret_set;

	/* Key schedule state */
	unsigned char shared_secret[32];
	unsigned char hs_secret[32];
	unsigned char server_hs_key[16];
	unsigned char server_hs_iv[12];
	unsigned char client_hs_key[16];
	unsigned char client_hs_iv[12];
	unsigned char server_app_key[16];
	unsigned char server_app_iv[12];
	unsigned char client_app_key[16];
	unsigned char client_app_iv[12];
	unsigned long server_seq;
	unsigned long client_seq;

	/* Transcript hash (running SHA-256 of handshake messages) */
	unsigned char transcript[32];

	/* Certificate data */
	unsigned char cert_data[4096];
	int cert_len;

	/* Signing algorithm in use for this session */
	int sign_alg; /* SIGN_ALG_* */

	/* Ed25519 material */
	unsigned char sign_key[32];  /* Ed25519 seed */
	unsigned char sign_pub[32];  /* Ed25519 public key (ours or peer) */

	/* RSA material (rsa_pss_rsae_sha256) */
	struct rsa_key rsa;

	/* Optional pin: peer cert key must match what we loaded */
	int expect_pub_set;
	int expect_alg;
	unsigned char expect_pub[32];       /* Ed25519 pin */
	struct rsa_key expect_rsa;          /* RSA pin (n, e) */

	/* Handshake message buffer for transcript */
	unsigned char hs_buf[16384];
	int hs_buf_len;

	/* Saved transcript hash at CH..SH boundary */
	unsigned char ch_sh_hash[32];
	int ch_sh_len; /* hs_buf length at CH..SH boundary */

	/* Traffic secrets (needed for Finished computation) */
	unsigned char s_hs_traffic[32];
	unsigned char c_hs_traffic[32];

	int is_server;
};

/* ---- Existing handshake parsing ------------------------------------- */

int do_tls_handshake(int conn, unsigned char *msg, struct tlsSession *session);
int parse_handshake(int conn, unsigned char *fragment, struct tlsSession *ssl);
int parse_alert_message(unsigned char *fragment);
int parse_client_hello(unsigned char *message, struct tlsSession *session);
int generate_server_keys(struct tlsSession *session);
int curve25519_mult(unsigned char *a, unsigned char *out);
void i32_add(unsigned char *a, unsigned char *b, unsigned char *out);
int send_alert_message(int conn, int mess_code);
int send_server_hello(int conn, struct tlsSession *session);
int send_server_cert(int conn, struct tlsSession *session);

/* ---- Extension parsing ---------------------------------------------- */

int parse_extensions(unsigned char *msg, struct tlsSession *session);
short parse_server_name_ext(unsigned char **msg);
short parse_supported_groups_ext(unsigned char **msg);
short parse_ec_point_formats_ext(unsigned char **msg);
short parse_signature_algorithms_ext(unsigned char **msg);
short parse_use_srtp_ext(unsigned char **msg);
short parse_proto_negotiation_ext(unsigned char **msg);
short parse_padding_ext(unsigned char **msg);
short parse_encrypt_then_mac_ext(unsigned char **msg);
short parse_master_secret_ext(unsigned char **msg, struct tlsSession *ses);
short parse_session_ticket_ext(unsigned char **msg);
short parse_suported_versions_ext(unsigned char **msg, struct tlsSession *ses);
short parse_key_exchange_modes_ext(unsigned char **msg);
short parse_key_share_ext(unsigned char **msg, struct tlsSession *session);
short parse_renegotiation_ext(unsigned char **msg, struct tlsSession *ses);
short parse_unknown_ext(unsigned char **msg);

/* ---- Extension writing ---------------------------------------------- */

int write_renegotiation_ext(unsigned char *buff);
int write_key_share_ext(unsigned char *buff, struct tlsSession session);
int write_supported_versions_ext(unsigned char *buff);

/* Client hello extensions */
int build_client_hello(unsigned char *buf, struct tlsSession *s,
		       const char *host);
int build_supported_versions_ext(unsigned char *buf);
int build_key_share_ext(unsigned char *buf, struct tlsSession *s);
int build_signature_algorithms_ext(unsigned char *buf);
int build_supported_groups_ext(unsigned char *buf);
int build_server_name_ext(unsigned char *buf, const char *hostname);

/* ---- Crypto helpers ------------------------------------------------- */

void hmac_sha256(const unsigned char *key, int key_len,
		 const unsigned char *data, int data_len,
		 unsigned char out[32]);
void hkdf_extract(const unsigned char *salt, int salt_len,
		  const unsigned char *ikm, int ikm_len,
		  unsigned char out[32]);
void hkdf_expand_label(const unsigned char *secret,
		       const char *label, const unsigned char *ctx,
		       int ctx_len, unsigned char *out, int out_len);

/* ---- Key schedule --------------------------------------------------- */

int derive_handshake_keys(struct tlsSession *s);
int derive_application_keys(struct tlsSession *s);

/* ---- Encrypted record I/O ------------------------------------------- */

int tls_send_record(int conn, struct tlsSession *s,
		    unsigned char type, const unsigned char *data, int len,
		    int is_server_writing);
int tls_recv_record(int conn, struct tlsSession *s,
		    unsigned char *out, int *out_len, unsigned char *type,
		    int is_server_reading);

/* ---- Complete handshake flows --------------------------------------- */

int do_server_handshake(int conn, struct tlsSession *s);
int do_client_handshake(int conn, struct tlsSession *s, const char *host);

/* ---- Application data I/O ------------------------------------------- */

int tls_write(int conn, struct tlsSession *s,
	      const unsigned char *data, int len);
int tls_read(int conn, struct tlsSession *s,
	     unsigned char *data, int max_len);

/* ---- Certificate loading -------------------------------------------- */

int load_certificate(const char *cert_path, struct tlsSession *s);
int load_private_key(const char *key_path, struct tlsSession *s);
int extract_ed25519_pub_from_cert(const unsigned char *der, int der_len,
				  unsigned char pub[32]);
int extract_public_from_cert(const unsigned char *der, int der_len,
			     struct tlsSession *s);

/* ---- X25519 / Ed25519 ----------------------------------------------- */

void x25519(unsigned char out[32], const unsigned char scalar[32],
	    const unsigned char point[32]);
void ed25519_sign(const unsigned char *msg, int msg_len,
		  const unsigned char seed[32], unsigned char sig[64]);
int ed25519_verify(const unsigned char *msg, int msg_len,
		   const unsigned char pub[32],
		   const unsigned char sig[64]);
void ed25519_public_from_seed(const unsigned char seed[32],
			      unsigned char pub[32]);

#endif
