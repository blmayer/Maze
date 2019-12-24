#include "tls.h"
#include "webng.h"

/*
 * TODO: Use an int to keep track of *msg
 */
int parse_extensions(unsigned char *msg, struct tlsSession *session)
{
	/* Length of all extensions */
	short exts_len = *msg++ << 8;
	exts_len += *msg++;

	/* Loop in all extensions */
	while (exts_len) {
		printf("extensions len: %d\n", exts_len);

		/* Extension id or type */
		unsigned short ext_type = *msg++ << 8;
		ext_type += *msg++;
		exts_len -= 2;
		printf("extension: %d\n", ext_type);

		/* Continue parsing with the correct method */
		switch (ext_type) {
		case 0:
			puts("Reading SNI");
			exts_len -= parse_server_name_ext(&msg);
			break;
		case 10:
			puts("Reading supported groups");
			exts_len -= parse_supported_groups_ext(&msg);
			break;
		case 11:
			puts("Reading EC point formats");
			exts_len -= parse_ec_point_formats_ext(&msg);
			break;
		case 13:
			puts("Reading signature algorithms");
			exts_len -= parse_signature_algorithms_ext(&msg);
			break;
		case 14:
			puts("Reading SRTP extension");
			exts_len -= parse_use_srtp_ext(&msg);
			break;
		case 16:
			puts("Reading protocol negotiation extension");
			exts_len -= parse_proto_negotiation_ext(&msg);
			break;
		case 21:
			puts("Reading Padding extension");
			exts_len -= parse_padding_ext(&msg);
			break;
		case 22:
			puts("Reading Encrypt-then-MAC extension");
			exts_len -= parse_encrypt_then_mac_ext(&msg);
			break;
		case 23:
			puts("Reading Extended Master Secret Extension");
			exts_len -= parse_extended_master_secret_ext(&msg);
			break;
		case 35:
			puts("Reading SessionTicket TLS Extension");
			exts_len -= parse_session_ticket_ext(&msg);
			break;
		default:
			printf("Unknown extension: %d\n", ext_type);
			unsigned short ext_len = *msg++ << 8;
			ext_len += *msg++;
			printf("this ext len: %d\n", ext_len);
			exts_len -= ext_len;
		}
	}

	return 0;
}

short parse_server_name_ext(unsigned char **msg)
{
	/* Server name extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	/* This is a list */
	short list_len = *(*msg)++ << 8;
	list_len += *(*msg)++;
	printf("Server names list len: %d\n", list_len);

	/* Loop in the list of names */
	while (list_len) {
		/* Types: 0: host name */
		unsigned char name_type = *(*msg)++;
		printf("name type: %d\n", name_type);

		/* Case hostname */
		short name_len;
		if (name_type == 0) {
			/* String length */
			name_len = *(*msg)++ << 8;
			name_len += *(*msg)++;
			if (name_len == 0) {
				puts("Invalid name length");
				break;
			}

			printf("Host name len: %d\n", name_len);
			list_len -= name_len;
			while (name_len-- > 0) {
				printf("%c", *(*msg)++);
			}

			puts("");
		}

		/* Go to next item in list */
		list_len -= 3;
	}

	puts("parsed name ext");
	return ext_len + 2;
}

short parse_supported_groups_ext(unsigned char **msg)
{
	/* Supported groups extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	/* This is a list */
	short list_len = *(*msg)++ << 8;
	list_len += *(*msg)++;
	printf("Supported groups list len: %d\n", list_len);

	/* Loop in the list of groups */
	for (int i = 0; i < list_len; i += 2) {
		printf("%02x ", *(*msg)++);
		printf("%02x\n", *(*msg)++);
	}

	puts("parsed supported groups ext");
	return ext_len + 2;
}

short parse_ec_point_formats_ext(unsigned char **msg)
{
	/* EC point formats extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	// Just print the formats
	for (int i = 0; i < ext_len; i += 2) {
		printf("%02x ", *(*msg)++);
		printf("%02x\n", *(*msg)++);
	}

	puts("parsed EC point formats ext");
	return ext_len + 2;
}

short parse_signature_algorithms_ext(unsigned char **msg)
{
	/* Signature algorithms extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	/* This is a list */
	short list_len = *(*msg)++ << 8;
	list_len += *(*msg)++;
	printf("algorithms list len: %d\n", list_len);

	/* Loop in the list of groups */
	for (int i = 0; i < list_len; i += 2) {
		printf("%02x ", *(*msg)++);
		printf("%02x\n", *(*msg)++);
	}

	puts("parsed signature algorithms ext");
	return ext_len + 2;
}

short parse_use_srtp_ext(unsigned char **msg)
{
	/* SRTP Protection Profile */
	unsigned short profile = **msg++ << 8;
	profile += **msg++;
	printf("profiles: %d\n", profile);

	/* Read profiles */
	while (profile--) {
		printf("Profile value: %02x ", **msg++);
		printf("%02x\n", **msg++);
	}

	/* Length of SRTP MKI */
	unsigned char mki_len = **msg++;
	printf("mki_len: %d\n", mki_len);

	/* Read MKI */
	while (mki_len--) {
		printf("%c", **msg++);
	}

	return 2 + profile + mki_len;
}

short parse_proto_negotiation_ext(unsigned char **msg)
{
	/* App-Layer protocol negotiation length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	/* This is a list */
	short list_len = *(*msg)++ << 8;
	list_len += *(*msg)++;
	printf("protocol names list len: %d\n", list_len);

	/* Loop in the list of names */
	while (list_len) {
		/* String length */
		unsigned char name_len = *(*msg)++;
		if (name_len == 0) {
			puts("Invalid name length");
			break;
		}

		printf("protocol name len: %d\n", name_len);
		list_len -= name_len;
		while (name_len--) {
			printf("%c", *(*msg)++);
		}
		puts("");

		/* Go to next item in list */
		list_len--;
	}

	puts("parsed protocol negotiation ext");
	return ext_len + 2;
}

short parse_padding_ext(unsigned char **msg)
{
	/* Padding extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	printf("skipping %d bytes\n", ext_len);
	*(*msg) += ext_len;

	return ext_len + 2;
}

short parse_encrypt_then_mac_ext(unsigned char **msg)
{
	/* Encrypt-on-MAC extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	/* This must be zero */
	return ext_len + 2;
}

unsigned short parse_extended_master_secret_ext(char **msg)
{
	/* Extended master secret extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	/* This must be zero */
	return ext_len + 2;
}

short parse_session_ticket_ext(unsigned char **msg)
{
	/* Ticket extension length */
	unsigned short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	/* We don't resume session tickets, skip the bytes */
	for (int i = 0; i < ext_len; i++) {
		printf("%02x ", **msg++);
	}
	puts("");

	puts("Parsed session ticket");
	return ext_len + 2;
}

unsigned char *write_key_share_ext(struct sslSession session)
{
	/**
	 * In order these bytes are
	 * The first two first identify the extension
	 * Second couple is the length of the extension
	 * Third couple is the value for the x25519 curve
	 * Then the key size: 32 bytes
	 */
	unsigned static char ext_data[40] = {0, 0x33, 0, 0x24, 0, 0x1d, 0, 0x20};

	/* Fill with the public key */
	for(int i = 0; i < 32; i++) {
		ext_data[i+8] = session.public[i];
	}

int write_supported_versions_ext(unsigned char *buff)
{
	/* The supported verions is just 1.3 hardcoded */
	*buff = 0;
	buff[1] = 0x2b;
	buff[2] = 0;
	buff[3] = 0x2;
	buff[4] = 0x3;
	buff[5] = 0x4;

	return 6;
}