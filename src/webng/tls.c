#include "tls.h"
#include "webng.h"

int do_tls_handshake(int conn, struct tlsSession *session)
{
	/* Wait for minimum data */
	int mess_len = get_ready_bytes(conn);
	if (mess_len < 5) {
		return -1;
	}

	/* ---- Read the Record Layer -------------------------------------- */

	/* First five bytes gives us enough info */
	unsigned char header[5];
	read(conn, header, 5);

	/* Handshake type */
	if (header[0] > 23 || header[0] < 20) {
		return -2; // Not handshake!
	}

	/* Version */
	session->ver[0] = header[1];
	session->ver[1] = header[2];

	/* Length of data fragment to read */
	short data_len = (header[3] << 8) + header[4];

	/* Some prints */
	printf("type: %u\n", header[0]);
	printf("version: %d.%d\n", session->ver[0], session->ver[1]);
	printf("data_len: %d\n", data_len);

	/* Fragment */
	unsigned char *fragment = malloc(data_len);
	read(conn, fragment, data_len);
	for (int i = 0; i < data_len; i++) {
		printf("%02x ", fragment[i]);
	}
	puts("");

	/* ---- Parse the fragment ----------------------------------------- */

	switch (header[0]) {
	case 21:
		puts("parsing alert message");
		parse_alert_message(fragment);
		break;
	case 22:
		puts("Parsing a TLS handshake");
		parse_handshake(conn, fragment, session);
	}

	puts("Done handshake");
	free(fragment);

	return 1;
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
		parse_client_hello(fragment, ssl_conn);

		/* Send response */
		send_server_hello(conn, ssl);
		puts("sent server hello");
		break;
	}

	return 0;
}

int parse_alert_message(unsigned char *fragment)
{
	printf("alert level: %d\n", *fragment++);
	printf("alert description: %d\n", *fragment++);
	return 0;
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
		ssl_conn->cli_random[i] = *msg++;
	}

	/* Session id */
	ssl_conn->id_len = *msg++; // byte 35 has the session id length
	printf("session id len: %d\n", ssl_conn->id_len);
	if (ssl_conn->id_len > 0 && ssl_conn->id_len < 33) {
		printf("session id: ");
		for (int i = 0; i < ssl_conn->id_len; i++) {
			printf("%02x ", *msg);
			ssl_conn->id[i] = *msg++;
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
	parse_extensions(msg, ssl_conn);
	puts("Done parsing client hello");

	return 0;
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

	/* Generate 32 bytes of random data */
	int rand = open("/dev/urandom", O_RDONLY);
	if (rand < 0) {
		return rand;
	}
	read(rand, &server_hello_data[11], 32);
	close(rand);

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