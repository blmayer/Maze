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
			exts_len -= parse_master_secret_ext(&msg, session);
			break;
		case 35:
			puts("Reading SessionTicket TLS Extension");
			exts_len -= parse_session_ticket_ext(&msg);
			break;
		case 43:
			puts("Reading Supported Versions TLS Extension");
			exts_len -= parse_suported_versions_ext(&msg, session);
			break;
		case 45:
			puts("Reading Pre-Shared Key Exchange Modes TLS "
			     "Extension");
			exts_len -= parse_key_exchange_modes_ext(&msg);
			break;
		case 51:
			puts("Reading KeyShare TLS Extension");
			exts_len -= parse_key_share_ext(&msg, session);
			break;
		case 65281:
			puts("Reading Renegotiation info TLS Extension");
			exts_len -= parse_renegotiation_ext(&msg, session);
			break;
		default:
			printf("Unknown extension: %d\n", ext_type);
			exts_len -= parse_unknown_ext(&msg);
			break;
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
	short profile = *(*msg)++ << 8;
	profile += *(*msg)++;
	printf("profiles: %d\n", profile);

	/* Read profiles */
	while (profile--) {
		printf("Profile value: %02x ", *(*msg)++);
		printf("%02x\n", *(*msg)++);
	}

	/* Length of SRTP MKI */
	unsigned char mki_len = *(*msg)++;
	printf("mki_len: %d\n", mki_len);

	/* Read MKI */
	while (mki_len--) {
		printf("%c", *(*msg)++);
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

short parse_master_secret_ext(unsigned char **msg, struct tlsSession *ses)
{
	/* Extended master secret extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);
	ses->master_secret_set = 1;

	/* This must be zero */
	return ext_len + 2;
}

short parse_session_ticket_ext(unsigned char **msg)
{
	/* Ticket extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	/* We don't resume session tickets, skip the bytes */
	for (int i = 0; i < ext_len; i++) {
		printf("%02x ", *(*msg)++);
	}
	puts("");

	puts("parsed session ticket");
	return ext_len + 2;
}

short parse_suported_versions_ext(unsigned char **msg, struct tlsSession *ses)
{
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	unsigned char versions_len = *(*msg)++;
	for (int i = 0; i < versions_len; i++) {
		printf("%02x ", *(*msg)++);
		if (*(*msg - 1) == 0x03 && **msg == 0x04) {
			ses->ver[0] = 0x03;
			ses->ver[1] = 0x04;
		}
	}
	puts("");

	puts("parsed supported versions extension");
	return ext_len + 2;
}

short parse_key_exchange_modes_ext(unsigned char **msg)
{
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("extension len: %d\n", ext_len + 2);

	for (int i = 0; i < ext_len; i++) {
		printf("%02x ", *(*msg)++);
	}
	puts("");

	puts("parsed key modes ticket");
	return ext_len + 2;
}

short parse_key_share_ext(unsigned char **msg, struct tlsSession *session)
{
	/* Key share extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("key share extension len: %d\n", ext_len + 2);

	/* Always advance past the whole extension body (bounds-safe) */
	unsigned char *body = *msg;
	unsigned char *end = body + ext_len;
	*msg = end;

	if (ext_len < 8) {
		puts("key share extension too short");
		return ext_len + 2;
	}

	/* Size of key share */
	short key_share_len = (body[0] << 8) | body[1];
	printf("key share len: %d\n", key_share_len);

	/* Curve type */
	printf("%02x ", body[2]);
	printf("%02x\n", body[3]);

	/* Size of key */
	short key_len = (body[4] << 8) | body[5];
	printf("key len: %d\n", key_len);

	/*
	 * X25519 public keys are always 32 bytes. Refuse anything else
	 * so a hostile ClientHello cannot smash past cli_public[32].
	 */
	if (key_len != 32 || body + 6 + 32 > end) {
		printf("Rejecting key_share with length %d (want 32)\n",
		       key_len);
		return ext_len + 2;
	}

	/* Save the key */
	for (int i = 0; i < 32; i++) {
		session->cli_public[i] = body[6 + i];
		printf("%02x ", session->cli_public[i]);
	}
	puts("");

	puts("Parsed key share extension");
	return ext_len + 2;
}

short parse_renegotiation_ext(unsigned char **msg, struct tlsSession *ses)
{
	/* Renegotiation extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("renegotiation extension len: %d\n", ext_len + 2);

	/* Skip the bytes */
	for (int i = 0; i < ext_len; i++) {
		printf("%02x ", *(*msg)++);
	}
	puts("");

	ses->renegotiation_set = 1;

	puts("Parsed renegotiation extension");
	return ext_len + 2;
}

short parse_unknown_ext(unsigned char **msg)
{
	/* Unknown extension length */
	short ext_len = *(*msg)++ << 8;
	ext_len += *(*msg)++;
	printf("unknown extension len: %d\n", ext_len + 2);

	/* Skip the bytes */
	for (int i = 0; i < ext_len; i++) {
		printf("%02x ", *(*msg)++);
	}
	puts("");

	puts("skipped Unknown extension");
	return ext_len + 2;
}

int write_renegotiation_ext(unsigned char *buff)
{
	/* The renegotiation info ext is hardcoded */
	*buff = 0xff;
	buff[1] = 0x01;
	buff[2] = 0x00;
	buff[3] = 0x01;
	buff[4] = 0x00;

	return 5;
}

int write_key_share_ext(unsigned char *buff, struct tlsSession session)
{
	/**
	 * In order these bytes are
	 * The first two first identify the extension
	 * Second couple is the length of the extension
	 * Third couple is the value for the x25519 curve
	 * Then the key size: 32 bytes
	 */
	*buff = 0;
	buff[1] = 0x33;
	buff[2] = 0;
	buff[3] = 0x24;
	buff[4] = 0;
	buff[5] = 0x1d;
	buff[6] = 0;
	buff[7] = 0x20;

	/* Fill with the public key */
	for (int i = 0; i < 32; i++) {
		buff[i + 8] = session.ser_public[i];
	}

	return 40;
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

/* ---- Client-side extension builders --------------------------------- */

int build_server_name_ext(unsigned char *buf, const char *hostname)
{
	int name_len = strlen(hostname);
	int list_len = name_len + 3; /* type(1) + len(2) + name */
	int ext_len = list_len + 2;  /* list_len(2) + list */
	int pos = 0;

	/* Extension type: SNI = 0x0000 */
	buf[pos++] = 0x00; buf[pos++] = 0x00;
	/* Extension data length */
	buf[pos++] = (ext_len >> 8) & 0xff;
	buf[pos++] = ext_len & 0xff;
	/* Server name list length */
	buf[pos++] = (list_len >> 8) & 0xff;
	buf[pos++] = list_len & 0xff;
	/* Host name type = 0 */
	buf[pos++] = 0x00;
	/* Host name length */
	buf[pos++] = (name_len >> 8) & 0xff;
	buf[pos++] = name_len & 0xff;
	/* Host name */
	memcpy(&buf[pos], hostname, name_len);
	pos += name_len;

	return pos;
}

int build_supported_groups_ext(unsigned char *buf)
{
	int pos = 0;
	/* Extension type: supported_groups = 0x000a */
	buf[pos++] = 0x00; buf[pos++] = 0x0a;
	/* Length: 4 bytes */
	buf[pos++] = 0x00; buf[pos++] = 0x04;
	/* Groups list length: 2 */
	buf[pos++] = 0x00; buf[pos++] = 0x02;
	/* x25519 = 0x001d */
	buf[pos++] = 0x00; buf[pos++] = 0x1d;
	return pos;
}

int build_signature_algorithms_ext(unsigned char *buf)
{
	int pos = 0;
	/* Extension type: signature_algorithms = 0x000d */
	buf[pos++] = 0x00; buf[pos++] = 0x0d;
	/* Length: 2 + list (we advertise two schemes) */
	buf[pos++] = 0x00; buf[pos++] = 0x06;
	/* Algorithms list length: 4 (two schemes × 2 bytes) */
	buf[pos++] = 0x00; buf[pos++] = 0x04;
	/* rsa_pss_rsae_sha256 = 0x0804 (TLS 1.3 RSA certs) */
	buf[pos++] = 0x08; buf[pos++] = 0x04;
	/* ed25519 = 0x0807 */
	buf[pos++] = 0x08; buf[pos++] = 0x07;
	return pos;
}

int build_supported_versions_ext(unsigned char *buf)
{
	int pos = 0;
	/* Extension type: supported_versions = 0x002b */
	buf[pos++] = 0x00; buf[pos++] = 0x2b;
	/* Length: 3 */
	buf[pos++] = 0x00; buf[pos++] = 0x03;
	/* Versions list length: 2 */
	buf[pos++] = 0x02;
	/* TLS 1.3 = 0x0304 */
	buf[pos++] = 0x03; buf[pos++] = 0x04;
	return pos;
}

int build_key_share_ext(unsigned char *buf, struct tlsSession *s)
{
	int pos = 0;
	/* Extension type: key_share = 0x0033 */
	buf[pos++] = 0x00; buf[pos++] = 0x33;
	/* Extension data length: 38 (2+2+2+32) */
	buf[pos++] = 0x00; buf[pos++] = 0x26;
	/* Client key shares length: 36 */
	buf[pos++] = 0x00; buf[pos++] = 0x24;
	/* x25519 group */
	buf[pos++] = 0x00; buf[pos++] = 0x1d;
	/* Key length */
	buf[pos++] = 0x00; buf[pos++] = 0x20;
	/* Public key */
	memcpy(&buf[pos], s->cli_public, 32);
	pos += 32;
	return pos;
}

int build_client_hello(unsigned char *buf, struct tlsSession *s,
		       const char *host)
{
	int pos = 0;

	/* Handshake type: ClientHello = 1 */
	buf[pos++] = 0x01;
	/* Length placeholder (fill later) */
	int len_pos = pos;
	pos += 3;

	/* Client version: legacy 0x0303 (TLS 1.2) */
	buf[pos++] = 0x03; buf[pos++] = 0x03;

	/* Client random */
	memcpy(&buf[pos], s->cli_random, 32);
	pos += 32;

	/* Session ID */
	buf[pos++] = s->id_len;
	memcpy(&buf[pos], s->id, s->id_len);
	pos += s->id_len;

	/* Cipher suites: length = 2, just TLS_AES_128_GCM_SHA256 */
	buf[pos++] = 0x00; buf[pos++] = 0x02;
	buf[pos++] = 0x13; buf[pos++] = 0x01;

	/* Compression methods: 1 byte, value 0 */
	buf[pos++] = 0x01; buf[pos++] = 0x00;

	/* Extensions */
	int ext_start = pos;
	pos += 2; /* extensions length placeholder */

	pos += build_server_name_ext(&buf[pos], host);
	pos += build_supported_groups_ext(&buf[pos]);
	pos += build_signature_algorithms_ext(&buf[pos]);
	pos += build_supported_versions_ext(&buf[pos]);
	pos += build_key_share_ext(&buf[pos], s);

	/* Fill extension length */
	int ext_len = pos - ext_start - 2;
	buf[ext_start] = (ext_len >> 8) & 0xff;
	buf[ext_start + 1] = ext_len & 0xff;

	/* Fill handshake length */
	int hs_len = pos - 4;
	buf[len_pos] = (hs_len >> 16) & 0xff;
	buf[len_pos + 1] = (hs_len >> 8) & 0xff;
	buf[len_pos + 2] = hs_len & 0xff;

	return pos;
}