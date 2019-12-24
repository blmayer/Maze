#include "tls.h"
#include "webng.h"

const char SUPPORTED_VERSIONS_EXT[6] = {0x0, 0x2b, 0x0, 0x2, 0x3, 0x4};

int do_tls_handshake(int conn, struct sslSession *session)
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
	unsigned short data_len = (header[3] << 8) + header[4];

	/* Some prints */
	printf("type: %u\n", header[0]);
	printf("version: %d.%d\n", session->ver[0], session->ver[1]);
	printf("data_len: %d\n", data_len);

	/* Fragment */
	char *fragment = malloc(data_len);
	read(conn, fragment, data_len);
	for (int i = 0; i < data_len; i++) {
		printf("%02x ", (unsigned char)fragment[i]);
	}
	puts("");

	/* ---- Parse the fragment ----------------------------------------- */

	switch (header[0]) {
	case 22:
		puts("Parsing a TLS handshake");
		parse_handshake(conn, fragment, session);
	}

	puts("Done handshake");
	free(fragment);

	return 1;
}

int parse_handshake(int conn, char *fragment, struct sslSession *ssl_conn)
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
		send_server_hello(conn, ssl_conn);
		break;
	}

	return 0;
}

int parse_client_hello(char *msg, struct sslSession *ssl_conn)
{
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
	unsigned short ciphers_len = *msg++ << 8;
	ciphers_len += *msg++;
	printf("ciphers len: %d\n", ciphers_len);
	for (int i = 0; i < ciphers_len; i++) {
		printf("%02x ", (unsigned char)*msg++);
	}

	/* Compression methods */
	unsigned short cmp_len = *msg++;
	printf("\ncompression len: %d\n", cmp_len);

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

int send_server_hello(int conn, struct sslSession *ssl_conn)
{
	/* Calculate length of data */
	unsigned short server_hello_len = 5;  // Record header
	server_hello_len += 4;		      // Handshake header
	server_hello_len += 2;		      // Server version
	server_hello_len += 32;		      // Server random
	server_hello_len += 1;		      // id length indicator
	server_hello_len += ssl_conn->id_len; // Client id length
	server_hello_len += 2;		      // Cypher len
	server_hello_len += 1;		      // Compression method
	server_hello_len += 2;		      // Extensions length indicator
	server_hello_len += 6;		      // Supported versions len
	server_hello_len += 40; // Key share length

	/* Allocate the calculated length */
	unsigned char server_hello_data[server_hello_len];

	/* Generate 32 bytes of random data */
	int rand = open("/dev/urandom", O_RDONLY);
	if(rand < 0) {
		return rand;
	}
	read(rand, &server_hello_data[11], 32);
	return 0;
}