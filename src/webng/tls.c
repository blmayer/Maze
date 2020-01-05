#include "tls.h"

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
	server_hello_data[3] = (server_hello_len + ext_len - 5) << 8;
	server_hello_data[4] = server_hello_len + ext_len - 5;

	/* Handshake header */
	server_hello_data[5] = 0x02;
	server_hello_data[6] = 0;
	server_hello_data[7] = (server_hello_len + ext_len - 9) << 8;
	server_hello_data[8] = server_hello_len + ext_len - 9;

	/* Server version */
	server_hello_data[9] = 0x03;
	server_hello_data[10] = 0x03;

	/* Generate server random data and public key */
	generate_server_keys(session);

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
	server_hello_data[offset++] = ext_len << 8;
	server_hello_data[offset++] = ext_len;

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
	write(conn, &server_hello_data, server_hello_len);

	return 0;
}

int generate_server_keys(struct tlsSession *session)
{
	/* Generate 32 bytes for private key and server random */
	int rand = open("/dev/urandom", O_RDONLY);
	if (rand < 0) {
		return rand;
	}
	read(rand, &session->ser_private, 32);
	read(rand, &session->ser_random, 32);
	close(rand);

	/* Generate public key */
	curve25519_mult(session->ser_private, session->ser_public);

	return 1;
}

// int send_server_cert(int conn, struct tlsSession *session) {}