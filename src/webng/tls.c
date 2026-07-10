#include "tls.h"
#include "sha256.h"
#include "aes.h"
#include "rsa.h"

/* Forward declarations for internal helpers */
static void transcript_hash(struct tlsSession *s);
static void transcript_append(struct tlsSession *s,
			      const unsigned char *data, int len);
static void make_nonce(const unsigned char *base_iv, unsigned long seq,
		       unsigned char nonce[12]);
static int read_fully(int conn, unsigned char *buf, int len);

int do_tls_handshake(int conn, unsigned char *msg, struct tlsSession *session)
{
	/* ---- Read the Record Layer -------------------------------------- */

	/* Handshake type */
	if (msg[0] > 23 || msg[0] < 20) {
		return 0; // Not handshake!
	}

	/* Version */
	session->ver[0] = msg[1];
	session->ver[1] = msg[2];

	/* Length of data fragment to read */
	short data_len = (msg[3] << 8) + msg[4];

	/* Some prints */
	printf("type: %u\n", msg[0]);
	printf("version: %d.%d\n", session->ver[0], session->ver[1]);
	printf("data_len: %d\n", data_len);

	/* Fragment */
	for (int i = 0; i < data_len; i++) {
		printf("%02x ", msg[i + 5]);
	}
	puts("");

	/* ---- Parse the fragment ----------------------------------------- */
	unsigned char *frag = &msg[5];

	switch (msg[0]) {
	case 21:
		puts("parsing alert message");
		return parse_alert_message(frag);
	case 22:
		puts("Parsing a TLS handshake");
		return parse_handshake(conn, frag, session);
	default:
		return 0;
	}
}

int parse_handshake(int conn, unsigned char *fragment, struct tlsSession *ssl)
{
	/* Get handshake type */
	char type = *fragment++;

	/* Length of the fragment */
	unsigned int data_len = 0;
	data_len = (unsigned char)*fragment++ << 16;
	data_len += (unsigned char)*fragment++ << 8;
	data_len += (unsigned char)*fragment++;
	printf("handshake type: %d, data len: %d\n", type, data_len);

	switch (type) {
	case 1:
		puts("Handshake is a client hello");
		parse_client_hello(fragment, ssl);

		/* Check version */
		if (ssl->ver[1] != 4) {
			send_alert_message(conn, 70);
			puts("sent alert 70");
			return -1;
		}

		/* Add ClientHello handshake to transcript
		 * (type + 3-byte length + data) */
		ssl->hs_buf_len = 0;
		transcript_append(ssl, fragment - 4, data_len + 4);

		/* Send response */
		send_server_hello(conn, ssl);
		puts("sent server hello");
		break;
	}

	return 1;
}

int parse_alert_message(unsigned char *fragment)
{
	printf("alert level: %d\n", *fragment++);
	printf("alert description: %d\n", *fragment++);
	return 2;
}

int parse_client_hello(unsigned char *msg, struct tlsSession *session)
{
	/* Clear some fields */
	session->renegotiation_set = 0;
	session->master_secret_set = 0;
	session->cipher[0] = 0;
	session->cipher[1] = 0;

	/* Version: for now only TLS 1.3 is supported */
	printf("version: %d.%d\n", msg[0], msg[1]);
	if (*msg++ != 3 || *msg++ != 3) {
		printf("Unsupported TLS version");
		return -1;
	}

	/* Random bytes */
	for (int i = 0; i < 32; i++) {
		session->cli_random[i] = *msg++;
	}

	/* Session id */
	session->id_len = *msg++; // byte 35 has the session id length
	printf("session id len: %d\n", session->id_len);
	if (session->id_len > 0 && session->id_len < 33) {
		printf("session id: ");
		for (int i = 0; i < session->id_len; i++) {
			printf("%02x ", *msg);
			session->id[i] = *msg++;
		}
		puts("");
	}

	/* Cipher suites parsing */
	short ciphers_len = *msg++ << 8;
	ciphers_len += *msg++;
	printf("ciphers len: %d\n", ciphers_len);
	for (int i = 0; i < ciphers_len; i += 2) {
		printf("%02x ", *msg++);
		printf("%02x\n", *msg++);

		/* For now the only supported is 13 01 */
		if (*(msg - 2) == 0x13 && *(msg - 1) == 0x01) {
			session->cipher[0] = *(msg - 2);
			session->cipher[1] = *(msg - 1);
		}
	}

	/* Compression methods */
	short cmp_len = *msg++;
	printf("compression len: %d\n", cmp_len);

	/* TLS 1.3 only has compression 0 */
	for (int i = 0; i < cmp_len; i++) {
		printf("compression %d: %d\n", i, *msg++);
	}

	/* Extensions */
	puts("Parsing extensions");
	parse_extensions(msg, session);

	puts("client info:");
	printf("tls version %02x %02x\n", session->ver[0], session->ver[1]);
	puts("session id:");
	for (int i = 0; i < session->id_len; i++) {
		printf("%02x ", session->id[i]);
	}
	puts("");
	printf("cipher: %02x %02x\n", session->cipher[0], session->cipher[1]);
	puts("client random:");
	for (int i = 0; i < 32; i++) {
		printf("%02x ", session->cli_random[i]);
	}
	puts("");
	puts("client public key:");
	for (int i = 0; i < 32; i++) {
		printf("%02x ", session->cli_public[i]);
	}
	puts("");
	printf("Renegotiation ext: %d\n", session->renegotiation_set);
	puts("Done parsing client hello");
	return 0;
}

int send_alert_message(int conn, int mess_code)
{
	char message[7] = {21, 3, 3, 0, 2, 2, mess_code};

	write(conn, &message, 7);
	return 1;
}

int send_server_hello(int conn, struct tlsSession *session)
{
	/* Calculate length of data */
	short server_hello_len = 5;	  // Record header
	server_hello_len += 4;		     // Handshake header
	server_hello_len += 2;		     // Server version
	server_hello_len += 32;		     // Server random
	server_hello_len += 1;		     // id length indicator
	server_hello_len += session->id_len; // Client id length
	server_hello_len += 2;		     // Cypher len
	server_hello_len += 1;		     // Compression method
	server_hello_len += 2;		     // Extensions length indicator

	/* Optional extensions */
	short ext_len = 6; // Supported versions len
	ext_len += 40;     // Key share length
	if (session->renegotiation_set) {
		ext_len += 5;
	}

	/* Allocate the calculated length */
	unsigned char server_hello_data[server_hello_len + ext_len];

	/* Fill in fields */
	server_hello_data[0] = 0x16;
	server_hello_data[1] = 0x03;
	server_hello_data[2] = 0x03;
	server_hello_data[3] = (server_hello_len + ext_len - 5) >> 8;
	server_hello_data[4] = (server_hello_len + ext_len - 5) & 0xff;

	/* Handshake header */
	server_hello_data[5] = 0x02;
	server_hello_data[6] = 0;
	server_hello_data[7] = (server_hello_len + ext_len - 9) >> 8;
	server_hello_data[8] = (server_hello_len + ext_len - 9) & 0xff;

	/* Server version */
	server_hello_data[9] = 0x03;
	server_hello_data[10] = 0x03;

	/* Generate server random data and public key */
	generate_server_keys(session);

	/* Copy server random into message */
	for (int i = 0; i < 32; i++) {
		server_hello_data[11 + i] = session->ser_random[i];
	}

	/* Echo session id */
	server_hello_data[43] = session->id_len;
	for (int i = 0; i < session->id_len; i++) {
		server_hello_data[44 + i] = session->id[i];
	}
	int offset = session->id_len + 44;

	/* Cipher suite */
	server_hello_data[offset++] = session->cipher[0];
	server_hello_data[offset++] = session->cipher[1];

	/* Compression method */
	server_hello_data[offset++] = 0;

	/* Extensions length */
	server_hello_data[offset++] = (ext_len >> 8) & 0xff;
	server_hello_data[offset++] = ext_len & 0xff;

	/* Key share ext */
	offset += write_key_share_ext(&server_hello_data[offset], *session);

	/* Supported versions ext */
	offset += write_supported_versions_ext(&server_hello_data[offset]);

	/* Renegotiation ext */
	if (session->renegotiation_set) {
		offset += write_renegotiation_ext(&server_hello_data[offset]);
	}

	puts("server hello bytes:");
	for (int i = 0; i < server_hello_len + ext_len; i++) {
		printf("%02x ", server_hello_data[i]);
	}
	puts("");
	write(conn, &server_hello_data, server_hello_len + ext_len);

	/* Add ServerHello handshake (without record header) to transcript */
	transcript_append(session, &server_hello_data[5],
			  server_hello_len + ext_len - 5);

	return 0;
}

/* Read exactly len cryptographically random bytes, or fail */
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

int generate_server_keys(struct tlsSession *session)
{
	/* Generate 32 bytes for private key and server random */
	if (read_random(session->ser_private, 32) < 0 ||
	    read_random(session->ser_random, 32) < 0)
		return -1;

	/* Generate public key */
	curve25519_mult(session->ser_private, session->ser_public);

	return 1;
}

/* ---- HMAC-SHA256 ---------------------------------------------------- */

void hmac_sha256(const unsigned char *key, int key_len,
		 const unsigned char *data, int data_len,
		 unsigned char out[32])
{
	unsigned char kpad[64], ipad[64], opad[64];
	unsigned char kh[32];
	struct sha256_ctx ctx;
	int i;

	/* If key > 64, hash it first */
	if (key_len > 64) {
		sha256(key, key_len, kh);
		key = kh;
		key_len = 32;
	}

	memset(kpad, 0, 64);
	memcpy(kpad, key, key_len);
	for (i = 0; i < 64; i++) {
		ipad[i] = kpad[i] ^ 0x36;
		opad[i] = kpad[i] ^ 0x5c;
	}

	/* Inner: SHA256(ipad || data) */
	unsigned char inner[32];
	sha256_init(&ctx);
	sha256_update(&ctx, ipad, 64);
	sha256_update(&ctx, data, data_len);
	sha256_final(&ctx, inner);

	/* Outer: SHA256(opad || inner) */
	sha256_init(&ctx);
	sha256_update(&ctx, opad, 64);
	sha256_update(&ctx, inner, 32);
	sha256_final(&ctx, out);
}

/* ---- HKDF (RFC 5869) ------------------------------------------------ */

void hkdf_extract(const unsigned char *salt, int salt_len,
		  const unsigned char *ikm, int ikm_len,
		  unsigned char out[32])
{
	if (salt == NULL || salt_len == 0) {
		unsigned char zeros[32] = {0};
		hmac_sha256(zeros, 32, ikm, ikm_len, out);
	} else {
		hmac_sha256(salt, salt_len, ikm, ikm_len, out);
	}
}

void hkdf_expand_label(const unsigned char *secret,
		       const char *label, const unsigned char *ctx,
		       int ctx_len, unsigned char *out, int out_len)
{
	/*
	 * TLS 1.3 HKDF-Expand-Label:
	 * HkdfLabel = length(2) || "tls13 " || label || context
	 * info = struct { uint16 length; opaque label<7..255>;
	 *                 opaque context<0..255>; }
	 */
	unsigned char info[512];
	int label_len = strlen(label);
	int tls_label_len = 6 + label_len; /* "tls13 " + label */
	int pos = 0;

	/* Length of output (2 bytes) */
	info[pos++] = (out_len >> 8) & 0xff;
	info[pos++] = out_len & 0xff;

	/* Label with "tls13 " prefix */
	info[pos++] = tls_label_len;
	memcpy(&info[pos], "tls13 ", 6);
	pos += 6;
	memcpy(&info[pos], label, label_len);
	pos += label_len;

	/* Context */
	info[pos++] = ctx_len;
	if (ctx_len > 0) {
		memcpy(&info[pos], ctx, ctx_len);
		pos += ctx_len;
	}

	/* HKDF-Expand with T(1) only (out_len <= 32 for SHA-256) */
	unsigned char t1_input[512 + 1];
	memcpy(t1_input, info, pos);
	t1_input[pos] = 0x01;
	unsigned char tmp[32];
	hmac_sha256(secret, 32, t1_input, pos + 1, tmp);
	memcpy(out, tmp, out_len);
}

/* ---- Transcript hashing --------------------------------------------- */

static void transcript_hash(struct tlsSession *s)
{
	sha256(s->hs_buf, s->hs_buf_len, s->transcript);
}

static void transcript_append(struct tlsSession *s,
			      const unsigned char *data, int len)
{
	if (s->hs_buf_len + len <= (int)sizeof(s->hs_buf)) {
		memcpy(s->hs_buf + s->hs_buf_len, data, len);
		s->hs_buf_len += len;
	}
}

/* ---- Key schedule --------------------------------------------------- */

int derive_handshake_keys(struct tlsSession *s)
{
	unsigned char early_secret[32];
	unsigned char derived[32];
	unsigned char empty_hash[32];
	unsigned char zeros[32] = {0};

	/* early_secret = HKDF-Extract(0, 0) — no PSK */
	hkdf_extract(NULL, 0, zeros, 32, early_secret);

	/* derived = Derive-Secret(early, "derived", "") */
	sha256(NULL, 0, empty_hash); /* hash of empty string */
	hkdf_expand_label(early_secret, "derived", empty_hash, 32,
			  derived, 32);

	/* handshake_secret = HKDF-Extract(derived, shared_secret) */
	hkdf_extract(derived, 32, s->shared_secret, 32, s->hs_secret);

	/* Compute transcript hash up to ServerHello */
	transcript_hash(s);

	/* Save the CH..SH transcript hash and buffer position */
	memcpy(s->ch_sh_hash, s->transcript, 32);
	s->ch_sh_len = s->hs_buf_len;

	/* Traffic secrets */
	hkdf_expand_label(s->hs_secret, "c hs traffic",
			  s->transcript, 32, s->c_hs_traffic, 32);
	hkdf_expand_label(s->hs_secret, "s hs traffic",
			  s->transcript, 32, s->s_hs_traffic, 32);

	/* Derive keys and IVs */
	hkdf_expand_label(s->c_hs_traffic, "key", NULL, 0,
			  s->client_hs_key, 16);
	hkdf_expand_label(s->c_hs_traffic, "iv", NULL, 0,
			  s->client_hs_iv, 12);
	hkdf_expand_label(s->s_hs_traffic, "key", NULL, 0,
			  s->server_hs_key, 16);
	hkdf_expand_label(s->s_hs_traffic, "iv", NULL, 0,
			  s->server_hs_iv, 12);

	/* Reset sequence numbers */
	s->server_seq = 0;
	s->client_seq = 0;

	puts("Handshake keys derived.");
	return 0;
}

int derive_application_keys(struct tlsSession *s)
{
	unsigned char derived[32];
	unsigned char empty_hash[32];
	unsigned char zeros[32] = {0};
	unsigned char master[32];

	/* derived = Derive-Secret(hs_secret, "derived", "") */
	sha256(NULL, 0, empty_hash);
	hkdf_expand_label(s->hs_secret, "derived", empty_hash, 32,
			  derived, 32);

	/* master_secret = HKDF-Extract(derived, 0) — no PSK */
	hkdf_extract(derived, 32, zeros, 32, master);

	/* Compute transcript hash up to server Finished */
	transcript_hash(s);

	/* Traffic secrets */
	unsigned char c_app_traffic[32], s_app_traffic[32];
	hkdf_expand_label(master, "c ap traffic",
			  s->transcript, 32, c_app_traffic, 32);
	hkdf_expand_label(master, "s ap traffic",
			  s->transcript, 32, s_app_traffic, 32);

	/* Derive keys and IVs */
	hkdf_expand_label(c_app_traffic, "key", NULL, 0,
			  s->client_app_key, 16);
	hkdf_expand_label(c_app_traffic, "iv", NULL, 0,
			  s->client_app_iv, 12);
	hkdf_expand_label(s_app_traffic, "key", NULL, 0,
			  s->server_app_key, 16);
	hkdf_expand_label(s_app_traffic, "iv", NULL, 0,
			  s->server_app_iv, 12);

	/* Reset sequence numbers for application data */
	s->server_seq = 0;
	s->client_seq = 0;

	printf("Application keys derived.\n");
	return 0;
}

/* ---- Encrypted record I/O ------------------------------------------- */

/* Build per-record nonce: XOR base IV with sequence number */
static void make_nonce(const unsigned char *base_iv, unsigned long seq,
		       unsigned char nonce[12])
{
	int i;
	memcpy(nonce, base_iv, 12);
	for (i = 0; i < 8; i++) {
		nonce[11 - i] ^= (seq >> (i * 8)) & 0xff;
	}
}

static int read_fully(int conn, unsigned char *buf, int len)
{
	int total = 0, n;
	while (total < len) {
		n = read(conn, buf + total, len - total);
		if (n <= 0) return n;
		total += n;
	}
	return total;
}

int tls_send_record(int conn, struct tlsSession *s,
		    unsigned char type, const unsigned char *data, int len,
		    int is_server_writing)
{
	/* Build the inner plaintext: data || content_type */
	unsigned char pt[16384 + 1];
	memcpy(pt, data, len);
	pt[len] = type;
	int pt_len = len + 1;

	/* Build the record header (AAD) */
	unsigned char hdr[5];
	int ct_len = pt_len + 16; /* ciphertext + tag */
	hdr[0] = 0x17; /* application_data */
	hdr[1] = 0x03;
	hdr[2] = 0x03;
	hdr[3] = (ct_len >> 8) & 0xff;
	hdr[4] = ct_len & 0xff;

	/* Select key/iv based on who is writing */
	unsigned char *key, *iv;
	unsigned long *seq;
	if (is_server_writing) {
		key = s->server_hs_key;
		iv = s->server_hs_iv;
		seq = &s->server_seq;
	} else {
		key = s->client_hs_key;
		iv = s->client_hs_iv;
		seq = &s->client_seq;
	}

	unsigned char nonce[12];
	make_nonce(iv, *seq, nonce);

	(*seq)++;

	unsigned char ct[16384 + 17];
	unsigned char tag[16];
	aes128_gcm_encrypt(key, nonce, hdr, 5, pt, pt_len, ct, tag);

	/* Send: header + ciphertext + tag */
	write(conn, hdr, 5);
	write(conn, ct, pt_len);
	write(conn, tag, 16);

	return 0;
}

int tls_recv_record(int conn, struct tlsSession *s,
		    unsigned char *out, int *out_len, unsigned char *type,
		    int is_server_reading)
{
	/* Read record header */
	unsigned char hdr[5];
	if (read_fully(conn, hdr, 5) <= 0) return -1;

	/* Check for ChangeCipherSpec (pass through) */
	if (hdr[0] == 0x14) {
		int rec_len = (hdr[3] << 8) | hdr[4];
		unsigned char tmp[256];
		read_fully(conn, tmp, rec_len);
		*type = 0x14;
		*out_len = 0;
		return 0;
	}

	int rec_len = (hdr[3] << 8) | hdr[4];
	if (rec_len < 17 || rec_len > 16384 + 256) return -1;

	unsigned char ct[16384 + 256];
	if (read_fully(conn, ct, rec_len) <= 0) return -1;

	int ct_len = rec_len - 16;
	unsigned char *tag = ct + ct_len;

	/* Select key/iv */
	unsigned char *key, *iv;
	unsigned long *seq;
	if (is_server_reading) {
		key = s->client_hs_key;
		iv = s->client_hs_iv;
		seq = &s->client_seq;
	} else {
		key = s->server_hs_key;
		iv = s->server_hs_iv;
		seq = &s->server_seq;
	}

	unsigned char nonce[12];
	make_nonce(iv, *seq, nonce);
	(*seq)++;

	unsigned char pt[16384 + 1];
	if (aes128_gcm_decrypt(key, nonce, hdr, 5, ct, ct_len, pt, tag) < 0) {
		puts("Record decryption failed (bad tag)");
		return -1;
	}

	/* Inner content type is the last byte of plaintext */
	*type = pt[ct_len - 1];
	*out_len = ct_len - 1;
	memcpy(out, pt, *out_len);

	return 0;
}

/* Application data send/recv use app keys */
int tls_write(int conn, struct tlsSession *s,
	      const unsigned char *data, int len)
{
	unsigned char pt[16384 + 1];
	memcpy(pt, data, len);
	pt[len] = 0x17; /* application_data content type */
	int pt_len = len + 1;

	unsigned char hdr[5];
	int ct_len = pt_len + 16;
	hdr[0] = 0x17;
	hdr[1] = 0x03;
	hdr[2] = 0x03;
	hdr[3] = (ct_len >> 8) & 0xff;
	hdr[4] = ct_len & 0xff;

	unsigned char *key, *iv;
	unsigned long *seq;
	if (s->is_server) {
		key = s->server_app_key;
		iv = s->server_app_iv;
		seq = &s->server_seq;
	} else {
		key = s->client_app_key;
		iv = s->client_app_iv;
		seq = &s->client_seq;
	}

	unsigned char nonce[12];
	make_nonce(iv, *seq, nonce);
	(*seq)++;

	unsigned char ct[16384 + 17];
	unsigned char tag[16];
	aes128_gcm_encrypt(key, nonce, hdr, 5, pt, pt_len, ct, tag);

	write(conn, hdr, 5);
	write(conn, ct, pt_len);
	write(conn, tag, 16);

	return len;
}

int tls_read(int conn, struct tlsSession *s,
	     unsigned char *data, int max_len)
{
again:;
	unsigned char hdr[5];
	if (read_fully(conn, hdr, 5) <= 0) return -1;

	/* Skip ChangeCipherSpec */
	if (hdr[0] == 0x14) {
		int rec_len = (hdr[3] << 8) | hdr[4];
		unsigned char tmp[256];
		read_fully(conn, tmp, rec_len);
		goto again;
	}

	/* Alert */
	if (hdr[0] == 0x15) {
		int rec_len = (hdr[3] << 8) | hdr[4];
		unsigned char tmp[256];
		read_fully(conn, tmp, rec_len);
		return -1;
	}

	int rec_len = (hdr[3] << 8) | hdr[4];
	if (rec_len < 17) return -1;

	unsigned char ct[16384 + 256];
	if (read_fully(conn, ct, rec_len) <= 0) return -1;

	int ct_len = rec_len - 16;
	unsigned char *tag = ct + ct_len;

	unsigned char *key, *iv;
	unsigned long *seq;
	if (s->is_server) {
		key = s->client_app_key;
		iv = s->client_app_iv;
		seq = &s->client_seq;
	} else {
		key = s->server_app_key;
		iv = s->server_app_iv;
		seq = &s->server_seq;
	}

	unsigned char nonce[12];
	make_nonce(iv, *seq, nonce);
	(*seq)++;

	unsigned char pt[16384 + 1];
	if (aes128_gcm_decrypt(key, nonce, hdr, 5, ct, ct_len, pt, tag) < 0) {
		puts("Application record decryption failed");
		return -1;
	}

	/* Inner content type is the last non-zero byte */
	int inner_len = ct_len - 1;
	unsigned char inner_type = pt[inner_len];

	/* Skip non-application-data records (e.g. NewSessionTicket) */
	if (inner_type != 0x17) {
		goto again;
	}

	if (inner_len > max_len) inner_len = max_len;
	memcpy(data, pt, inner_len);

	return inner_len;
}

/* ---- Certificate loading -------------------------------------------- */

/* Simple base64 decode */
static int b64_decode(const char *src, int src_len,
		      unsigned char *dst, int dst_max)
{
	static const unsigned char b64[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
		"ghijklmnopqrstuvwxyz0123456789+/";
	int i, j = 0;
	unsigned char buf[4];

	for (i = 0; i < src_len && j < dst_max; ) {
		int k, n = 0;
		memset(buf, 0, 4);
		for (k = 0; k < 4 && i < src_len; ) {
			char c = src[i++];
			if (c == '=') { buf[k++] = 0; continue; }
			if (c == '\n' || c == '\r' || c == ' ') continue;
			unsigned char *p = memchr(b64, c, 64);
			if (!p) continue;
			buf[k++] = p - b64;
			n++;
		}
		if (n == 0) break;
		if (j < dst_max) dst[j++] = (buf[0] << 2) | (buf[1] >> 4);
		if (j < dst_max && n > 2) dst[j++] = (buf[1] << 4) | (buf[2] >> 2);
		if (j < dst_max && n > 3) dst[j++] = (buf[2] << 6) | buf[3];
	}
	return j;
}

/*
 * Pull the Ed25519 public key out of a DER certificate.
 * Ed25519 SPKI ends with BIT STRING: 03 21 00 || 32-byte key.
 * (Signature BIT STRINGs are longer, so 0x21 is a reliable marker.)
 */
int extract_ed25519_pub_from_cert(const unsigned char *der, int der_len,
				  unsigned char pub[32])
{
	int i;

	for (i = 0; i + 35 <= der_len; i++) {
		if (der[i] == 0x03 && der[i + 1] == 0x21 &&
		    der[i + 2] == 0x00) {
			memcpy(pub, &der[i + 3], 32);
			return 0;
		}
	}
	return -1;
}

/* Prefer Ed25519; fall back to RSA. Fills s->sign_alg and key material. */
int extract_public_from_cert(const unsigned char *der, int der_len,
			     struct tlsSession *s)
{
	if (extract_ed25519_pub_from_cert(der, der_len, s->sign_pub) == 0) {
		s->sign_alg = SIGN_ALG_ED25519;
		puts("Certificate public key: Ed25519");
		return 0;
	}
	if (rsa_pub_from_cert(der, der_len, &s->rsa) == 0) {
		s->sign_alg = SIGN_ALG_RSA_PSS_SHA256;
		puts("Certificate public key: RSA (will use PSS-SHA256)");
		return 0;
	}
	puts("No supported public key in certificate (want Ed25519 or RSA)");
	return -1;
}

/* RFC 8446 §4.4.3 signature context for server CertificateVerify */
static int build_cert_verify_content(struct tlsSession *s,
				     unsigned char *out, int out_max)
{
	int pos = 0;
	const char *ctx = "TLS 1.3, server CertificateVerify";
	int ctx_len = (int)strlen(ctx);

	if (out_max < 64 + ctx_len + 1 + 32)
		return -1;
	memset(out, 0x20, 64);
	pos = 64;
	memcpy(out + pos, ctx, ctx_len);
	pos += ctx_len;
	out[pos++] = 0;
	memcpy(out + pos, s->transcript, 32);
	pos += 32;
	return pos;
}

int load_certificate(const char *cert_path, struct tlsSession *s)
{
	FILE *f = fopen(cert_path, "r");
	if (!f) { perror("open cert"); return -1; }

	char pem[8192];
	int pem_len = fread(pem, 1, sizeof(pem) - 1, f);
	fclose(f);
	pem[pem_len] = 0;

	/* Find base64 content between BEGIN/END */
	char *start = strstr(pem, "-----BEGIN CERTIFICATE-----");
	if (!start) return -1;
	start = strchr(start, '\n');
	if (!start) return -1;
	start++;

	char *end = strstr(start, "-----END CERTIFICATE-----");
	if (!end) return -1;

	s->cert_len = b64_decode(start, end - start,
				 s->cert_data, sizeof(s->cert_data));
	printf("Loaded certificate: %d bytes DER\n", s->cert_len);

	/*
	 * On the client, loading a cert means "I trust this key" (a pin).
	 * Store the expected public key separately so the on-wire cert
	 * can be compared later. Server also calls this; load_private_key
	 * then sets the private half.
	 */
	if (extract_public_from_cert(s->cert_data, s->cert_len, s) == 0) {
		s->expect_pub_set = 1;
		s->expect_alg = s->sign_alg;
		if (s->sign_alg == SIGN_ALG_ED25519) {
			memcpy(s->expect_pub, s->sign_pub, 32);
			puts("Pinned Ed25519 public key from certificate");
		} else if (s->sign_alg == SIGN_ALG_RSA_PSS_SHA256) {
			s->expect_rsa = s->rsa;
			puts("Pinned RSA public key from certificate");
		}
	}

	return 0;
}

int load_private_key(const char *key_path, struct tlsSession *s)
{
	FILE *f = fopen(key_path, "r");
	if (!f) { perror("open key"); return -1; }

	char pem[8192];
	int pem_len = fread(pem, 1, sizeof(pem) - 1, f);
	fclose(f);
	pem[pem_len] = 0;

	/* PKCS#8 ("BEGIN PRIVATE KEY") or PKCS#1 ("BEGIN RSA PRIVATE KEY") */
	char *start = strstr(pem, "-----BEGIN PRIVATE KEY-----");
	char *end = NULL;
	int is_rsa_pem = 0;
	if (start) {
		end = strstr(start, "-----END PRIVATE KEY-----");
	} else {
		start = strstr(pem, "-----BEGIN RSA PRIVATE KEY-----");
		if (!start)
			return -1;
		end = strstr(start, "-----END RSA PRIVATE KEY-----");
		is_rsa_pem = 1;
	}
	if (!end) return -1;
	start = strchr(start, '\n');
	if (!start) return -1;
	start++;

	unsigned char der[4096];
	int der_len = b64_decode(start, end - start, der, sizeof(der));

	/*
	 * Try Ed25519 PKCS#8 first: look for 04 20 || 32-byte seed.
	 * Skip this for "BEGIN RSA PRIVATE KEY" files.
	 */
	if (!is_rsa_pem && der_len >= 48) {
		int i;
		for (i = 0; i + 33 <= der_len; i++) {
			if (der[i] == 0x04 && der[i + 1] == 0x20) {
				/* Heuristic: Ed25519 keys are short (~48 bytes) */
				if (der_len < 96) {
					memcpy(s->sign_key, &der[i + 2], 32);
					ed25519_public_from_seed(s->sign_key,
								 s->sign_pub);
					s->sign_alg = SIGN_ALG_ED25519;
					printf("Loaded Ed25519 private key\n");
					return 0;
				}
			}
		}
	}

	/* RSA private key (PKCS#8 or PKCS#1 DER) */
	if (rsa_priv_from_der(der, der_len, &s->rsa) == 0) {
		s->sign_alg = SIGN_ALG_RSA_PSS_SHA256;
		return 0;
	}

	puts("Failed to load private key (want Ed25519 or RSA)");
	return -1;
}

/* ---- Server handshake completion ------------------------------------ */

int do_server_handshake(int conn, struct tlsSession *s)
{
	s->is_server = 1;

	/* Compute shared secret: X25519(server_private, client_public) */
	unsigned char scalar[32];
	memcpy(scalar, s->ser_private, 32);
	scalar[0] &= 248;
	scalar[31] &= 127;
	scalar[31] |= 64;
	x25519(s->shared_secret, scalar, s->cli_public);

	printf("Shared secret computed\n");

	/* Derive handshake keys using transcript(CH..SH) */
	derive_handshake_keys(s);

	/* Send ChangeCipherSpec (middlebox compatibility) */
	unsigned char ccs[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
	write(conn, ccs, 6);

	/* ---- Encrypted Extensions ---------------------------------------- */
	{
		/* Minimal EncryptedExtensions: just empty */
		unsigned char ee[6];
		ee[0] = 0x08; /* handshake type: encrypted_extensions */
		ee[1] = 0; ee[2] = 0; ee[3] = 2; /* length = 2 */
		ee[4] = 0; ee[5] = 0; /* extensions length = 0 */
		transcript_append(s, ee, 6);
		tls_send_record(conn, s, 0x16, ee, 6, 1);
	}

	/* ---- Certificate ------------------------------------------------- */
	{
		/* Certificate message:
		 * type(1) + length(3) + request_context_len(1) +
		 * cert_list_len(3) + cert_entry: cert_len(3) + cert_data + ext_len(2)
		 */
		unsigned char cert_msg[4096 + 32];
		int pos = 0;

		cert_msg[pos++] = 0x0b; /* certificate */
		/* Handshake length */
		int hs_len = 1 + 3 + 3 + s->cert_len + 2;
		cert_msg[pos++] = (hs_len >> 16) & 0xff;
		cert_msg[pos++] = (hs_len >> 8) & 0xff;
		cert_msg[pos++] = hs_len & 0xff;
		/* Request context (empty for server) */
		cert_msg[pos++] = 0;
		/* Certificate list length */
		int list_len = 3 + s->cert_len + 2;
		cert_msg[pos++] = (list_len >> 16) & 0xff;
		cert_msg[pos++] = (list_len >> 8) & 0xff;
		cert_msg[pos++] = list_len & 0xff;
		/* Certificate entry: length */
		cert_msg[pos++] = (s->cert_len >> 16) & 0xff;
		cert_msg[pos++] = (s->cert_len >> 8) & 0xff;
		cert_msg[pos++] = s->cert_len & 0xff;
		/* Certificate data */
		memcpy(&cert_msg[pos], s->cert_data, s->cert_len);
		pos += s->cert_len;
		/* Extensions (empty) */
		cert_msg[pos++] = 0;
		cert_msg[pos++] = 0;

		transcript_append(s, cert_msg, pos);
		tls_send_record(conn, s, 0x16, cert_msg, pos, 1);
	}

	/* ---- CertificateVerify ------------------------------------------- */
	{
		/*
		 * Sign the transcript hash. TLS 1.3 allows several schemes;
		 * we support Ed25519 (0x0807) and rsa_pss_rsae_sha256 (0x0804).
		 */
		transcript_hash(s);

		unsigned char sig_content[200];
		int sig_pos = build_cert_verify_content(s, sig_content,
							sizeof(sig_content));
		if (sig_pos < 0)
			return -1;

		unsigned char sig[RSA_MAX_BYTES];
		int sig_len = 0;
		unsigned char scheme[2];

		if (s->sign_alg == SIGN_ALG_ED25519) {
			ed25519_sign(sig_content, sig_pos, s->sign_key, sig);
			sig_len = 64;
			scheme[0] = 0x08;
			scheme[1] = 0x07; /* ed25519 */
			puts("CertificateVerify: Ed25519");
		} else if (s->sign_alg == SIGN_ALG_RSA_PSS_SHA256) {
			if (rsa_pss_sha256_sign(&s->rsa, sig_content, sig_pos,
						sig, &sig_len) < 0) {
				puts("RSA-PSS sign failed");
				return -1;
			}
			scheme[0] = 0x08;
			scheme[1] = 0x04; /* rsa_pss_rsae_sha256 */
			printf("CertificateVerify: RSA-PSS-SHA256 (%d bytes)\n",
			       sig_len);
		} else {
			puts("No signing key loaded");
			return -1;
		}

		/* CertificateVerify: type(1) + len(3) + scheme(2) + sig_len(2) + sig */
		unsigned char cv[8 + RSA_MAX_BYTES];
		int hs_len = 2 + 2 + sig_len;
		int cv_len = 4 + hs_len;
		cv[0] = 0x0f;
		cv[1] = (hs_len >> 16) & 0xff;
		cv[2] = (hs_len >> 8) & 0xff;
		cv[3] = hs_len & 0xff;
		cv[4] = scheme[0];
		cv[5] = scheme[1];
		cv[6] = (sig_len >> 8) & 0xff;
		cv[7] = sig_len & 0xff;
		memcpy(&cv[8], sig, sig_len);

		transcript_append(s, cv, cv_len);
		tls_send_record(conn, s, 0x16, cv, cv_len, 1);
	}

	/* ---- Finished ---------------------------------------------------- */
	{
		transcript_hash(s);

		/* finished_key = HKDF-Expand-Label(s_hs_traffic, "finished", "", 32) */
		unsigned char finished_key[32];
		hkdf_expand_label(s->s_hs_traffic, "finished", NULL, 0,
				  finished_key, 32);

		/* verify_data = HMAC(finished_key, transcript_hash) */
		unsigned char verify_data[32];
		hmac_sha256(finished_key, 32, s->transcript, 32, verify_data);

		/* Finished message */
		unsigned char fin[36];
		fin[0] = 0x14; /* finished */
		fin[1] = 0; fin[2] = 0; fin[3] = 32;
		memcpy(&fin[4], verify_data, 32);

		transcript_append(s, fin, 36);
		tls_send_record(conn, s, 0x16, fin, 36, 1);
	}

	/* ---- Read client's ChangeCipherSpec and Finished ----------------- */
	{
		unsigned char buf[256];
		int buf_len;
		unsigned char rtype;

		/* May receive ChangeCipherSpec first */
		if (tls_recv_record(conn, s, buf, &buf_len, &rtype, 1) < 0) {
			puts("Failed to read client CCS/Finished");
			return -1;
		}
		if (rtype == 0x14) {
			/* ChangeCipherSpec, read next record for Finished */
			if (tls_recv_record(conn, s, buf, &buf_len, &rtype, 1) < 0) {
				puts("Failed to read client Finished");
				return -1;
			}
		}

		if (rtype != 0x16 || buf[0] != 0x14) {
			puts("Expected client Finished");
			return -1;
		}

		/* Verify client's finished */
		unsigned char c_finished_key[32];
		hkdf_expand_label(s->c_hs_traffic, "finished", NULL, 0,
				  c_finished_key, 32);

		/* The transcript for client finished = everything up to server finished */
		transcript_hash(s);
		unsigned char expected[32];
		hmac_sha256(c_finished_key, 32, s->transcript, 32, expected);

		if (memcmp(&buf[4], expected, 32) != 0) {
			puts("Client Finished verification failed");
			return -1;
		}
		puts("Client Finished verified OK");
	}

	/* Derive application keys using transcript through server Finished
	 * (before adding client Finished to transcript) */
	derive_application_keys(s);

	puts("Server TLS 1.3 handshake complete");
	return 0;
}

/* ---- Client handshake ----------------------------------------------- */

int do_client_handshake(int conn, struct tlsSession *s, const char *host)
{
	s->is_server = 0;
	s->hs_buf_len = 0;
	s->server_seq = 0;
	s->client_seq = 0;

	/* Generate client key pair */
	if (read_random(s->cli_private, 32) < 0 ||
	    read_random(s->cli_random, 32) < 0)
		return -1;
	curve25519_mult(s->cli_private, s->cli_public);

	/* Generate random session id */
	s->id_len = 32;
	if (read_random(s->id, 32) < 0)
		return -1;

	/* Build and send ClientHello */
	unsigned char ch_buf[512];
	int ch_len = build_client_hello(ch_buf, s, host);

	/* The TLS record header wraps the ClientHello */
	unsigned char record[5 + 512];
	record[0] = 0x16; /* handshake */
	record[1] = 0x03; record[2] = 0x01; /* legacy TLS 1.0 */
	record[3] = (ch_len >> 8) & 0xff;
	record[4] = ch_len & 0xff;
	memcpy(&record[5], ch_buf, ch_len);
	write(conn, record, 5 + ch_len);

	/* Add CH handshake message (without record header) to transcript */
	transcript_append(s, ch_buf, ch_len);

	puts("ClientHello sent");

	/* ---- Read ServerHello ------------------------------------------- */
	unsigned char sh_record[5];
	if (read_fully(conn, sh_record, 5) <= 0) {
		puts("Failed to read ServerHello record");
		return -1;
	}

	int sh_rec_len = (sh_record[3] << 8) | sh_record[4];
	unsigned char sh_buf[512];
	if (read_fully(conn, sh_buf, sh_rec_len) <= 0) {
		puts("Failed to read ServerHello body");
		return -1;
	}

	/* Parse ServerHello handshake message */
	if (sh_buf[0] != 0x02) {
		printf("Expected ServerHello (type 2), got %d\n", sh_buf[0]);
		return -1;
	}

	/* Add SH to transcript */
	transcript_append(s, sh_buf, sh_rec_len);

	/* Parse the ServerHello to extract server's key share */
	int pos = 4; /* skip type(1) + length(3) */
	pos += 2; /* server version (legacy 0x0303) */

	/* Server random */
	memcpy(s->ser_random, &sh_buf[pos], 32);
	pos += 32;

	/* Session id */
	unsigned char sh_id_len = sh_buf[pos++];
	pos += sh_id_len;

	/* Cipher suite */
	s->cipher[0] = sh_buf[pos++];
	s->cipher[1] = sh_buf[pos++];

	/* Compression */
	pos++; /* skip 0 */

	/* Extensions */
	int ext_total = (sh_buf[pos] << 8) | sh_buf[pos + 1];
	pos += 2;

	int ext_end = pos + ext_total;
	while (pos < ext_end) {
		int ext_type = (sh_buf[pos] << 8) | sh_buf[pos + 1];
		pos += 2;
		int ext_len = (sh_buf[pos] << 8) | sh_buf[pos + 1];
		pos += 2;

		if (ext_type == 0x0033) { /* key_share */
			/* group(2) + key_len(2) + key(32) */
			pos += 2; /* skip group */
			int klen = (sh_buf[pos] << 8) | sh_buf[pos + 1];
			pos += 2;
			/* X25519 is always 32 bytes; reject anything else */
			if (klen != 32 || pos + klen > sh_rec_len) {
				puts("Bad key_share length in ServerHello");
				return -1;
			}
			memcpy(s->ser_public, &sh_buf[pos], 32);
			pos += klen;
		} else {
			pos += ext_len;
		}
	}

	printf("Parsed ServerHello, cipher: %02x%02x\n",
	       s->cipher[0], s->cipher[1]);

	/* Compute shared secret */
	unsigned char scalar[32];
	memcpy(scalar, s->cli_private, 32);
	scalar[0] &= 248;
	scalar[31] &= 127;
	scalar[31] |= 64;
	x25519(s->shared_secret, scalar, s->ser_public);

	/* Derive handshake keys */
	derive_handshake_keys(s);

	/* ---- Read encrypted handshake messages --------------------------- */
	/* Read: possibly CCS, then EncryptedExtensions, Certificate,
	 * CertificateVerify, Finished — all as encrypted records */

	unsigned char msg[16384];
	int msg_len;
	unsigned char rtype;
	int got_finished = 0;

	while (!got_finished) {
		if (tls_recv_record(conn, s, msg, &msg_len, &rtype, 0) < 0) {
			puts("Failed to read server handshake record");
			return -1;
		}

		if (rtype == 0x14) {
			puts("Received ChangeCipherSpec (skipping)");
			continue;
		}

		if (rtype != 0x16) {
			printf("Unexpected record type: %02x\n", rtype);
			continue;
		}

		/* Process handshake messages within the record */
		int mpos = 0;
		while (mpos < msg_len) {
			unsigned char hs_type = msg[mpos];
			int hs_len = (msg[mpos + 1] << 16) |
				     (msg[mpos + 2] << 8) | msg[mpos + 3];
			int total_hs = 4 + hs_len;

			switch (hs_type) {
			case 0x08: /* EncryptedExtensions */
				puts("Received EncryptedExtensions");
				transcript_append(s, &msg[mpos], total_hs);
				break;
			case 0x0b: /* Certificate */ {
				/*
				 * TLS 1.3 Certificate (after hs header):
				 * context_len(1) + list_len(3) +
				 * cert_len(3) + cert_data + ext_len(2)
				 */
				const unsigned char *p = &msg[mpos + 4];
				int ctx_len = p[0];
				p += 1 + ctx_len;
				/* skip certificate_list length */
				p += 3;
				int clen = (p[0] << 16) | (p[1] << 8) | p[2];
				p += 3;

				if (clen <= 0 || clen > (int)sizeof(s->cert_data)) {
					puts("Certificate too large or empty");
					return -1;
				}
				memcpy(s->cert_data, p, clen);
				s->cert_len = clen;
				printf("Received Certificate (%d bytes DER)\n",
				       clen);

				/* Peer signing key lives in this cert */
				if (extract_public_from_cert(s->cert_data,
							     s->cert_len,
							     s) < 0)
					return -1;

				/*
				 * If the user pinned a cert (load_certificate),
				 * the on-wire key must match that pin.
				 * Without a pin we still verify CertificateVerify
				 * against this key — that binds the handshake to
				 * the cert, but a full trust store is still needed
				 * for real MITM resistance.
				 */
				if (s->expect_pub_set) {
					if (s->expect_alg != s->sign_alg) {
						puts("Certificate key type "
						     "does not match pin");
						return -1;
					}
					if (s->sign_alg == SIGN_ALG_ED25519) {
						int i, diff = 0;
						for (i = 0; i < 32; i++)
							diff |= s->expect_pub[i] ^
								s->sign_pub[i];
						if (diff != 0) {
							puts("Ed25519 pin mismatch");
							return -1;
						}
					} else if (s->sign_alg ==
						   SIGN_ALG_RSA_PSS_SHA256) {
						if (s->expect_rsa.n_len !=
							    s->rsa.n_len ||
						    memcmp(s->expect_rsa.n,
							   s->rsa.n,
							   s->rsa.n_len) != 0 ||
						    s->expect_rsa.e_len !=
							    s->rsa.e_len ||
						    memcmp(s->expect_rsa.e,
							   s->rsa.e,
							   s->rsa.e_len) != 0) {
							puts("RSA pin mismatch");
							return -1;
						}
					}
					puts("Certificate matches pinned key");
				} else {
					puts("No pin set — accepting peer "
					     "cert key for this session only");
				}

				transcript_append(s, &msg[mpos], total_hs);
				break;
			}
			case 0x0f: /* CertificateVerify */ {
				puts("Received CertificateVerify");

				/*
				 * Verify BEFORE appending this message.
				 * Transcript hash covers CH .. Certificate.
				 */
				if (hs_len < 8) {
					puts("CertificateVerify too short");
					return -1;
				}
				unsigned char sa0 = msg[mpos + 4];
				unsigned char sa1 = msg[mpos + 5];
				int sig_len = (msg[mpos + 6] << 8) |
					      msg[mpos + 7];
				/* hs_len covers scheme(2)+sig_len(2)+sig */
				if (sig_len < 64 || sig_len > RSA_MAX_BYTES ||
				    hs_len < 4 + sig_len) {
					puts("Bad signature length");
					return -1;
				}

				transcript_hash(s);

				unsigned char sig_content[200];
				int sig_pos = build_cert_verify_content(
					s, sig_content, sizeof(sig_content));
				if (sig_pos < 0)
					return -1;

				if (sa0 == 0x08 && sa1 == 0x07) {
					/* ed25519 */
					if (s->sign_alg != SIGN_ALG_ED25519 ||
					    sig_len != 64) {
						puts("Ed25519 scheme/key mismatch");
						return -1;
					}
					if (ed25519_verify(sig_content, sig_pos,
							   s->sign_pub,
							   &msg[mpos + 8]) < 0) {
						puts("CertificateVerify FAILED");
						return -1;
					}
				} else if (sa0 == 0x08 && sa1 == 0x04) {
					/* rsa_pss_rsae_sha256 */
					if (s->sign_alg !=
					    SIGN_ALG_RSA_PSS_SHA256) {
						puts("RSA scheme/key mismatch");
						return -1;
					}
					if (rsa_pss_sha256_verify(
						    &s->rsa, sig_content,
						    sig_pos, &msg[mpos + 8],
						    sig_len) < 0) {
						puts("CertificateVerify FAILED");
						return -1;
					}
				} else {
					printf("Unsupported signature scheme "
					       "%02x%02x\n",
					       sa0, sa1);
					return -1;
				}
				puts("CertificateVerify OK");

				transcript_append(s, &msg[mpos], total_hs);
				break;
			}
			case 0x14: /* Finished */
				puts("Received server Finished");
				/* Verify server finished */
				{
					transcript_hash(s);
					unsigned char sfk[32];
					hkdf_expand_label(s->s_hs_traffic,
						"finished", NULL, 0,
						sfk, 32);
					unsigned char expected[32];
					hmac_sha256(sfk, 32,
						s->transcript, 32, expected);
					if (memcmp(&msg[mpos + 4],
						   expected, 32) != 0) {
						puts("Server Finished verify FAILED");
						return -1;
					}
					puts("Server Finished verified OK");
				}
				transcript_append(s, &msg[mpos], total_hs);
				got_finished = 1;
				break;
			default:
				printf("Unknown hs type: %02x\n", hs_type);
				transcript_append(s, &msg[mpos], total_hs);
				break;
			}
			mpos += total_hs;
		}
	}

	/* ---- Send client ChangeCipherSpec and Finished ------------------- */
	unsigned char ccs[] = {0x14, 0x03, 0x03, 0x00, 0x01, 0x01};
	write(conn, ccs, 6);

	/* Client finished — sent with handshake keys */
	{
		transcript_hash(s);
		unsigned char cfk[32];
		hkdf_expand_label(s->c_hs_traffic, "finished", NULL, 0,
				  cfk, 32);
		unsigned char verify_data[32];
		hmac_sha256(cfk, 32, s->transcript, 32, verify_data);

		unsigned char fin[36];
		fin[0] = 0x14;
		fin[1] = 0; fin[2] = 0; fin[3] = 32;
		memcpy(&fin[4], verify_data, 32);

		tls_send_record(conn, s, 0x16, fin, 36, 0);
	}

	/* Derive application keys from transcript through server Finished */
	derive_application_keys(s);

	puts("Client TLS 1.3 handshake complete");
	return 0;
}