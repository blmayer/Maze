#define NULL (void *)0

/* A structure to hold SSL information needed to exchange messages */
struct sslSession {
	char ver[2];
	unsigned char random[32];
	unsigned char id[32];
	unsigned short cypher;
	unsigned char type;
	char *proto;
};

/* Parses the ssl handshake */
struct sslSession *do_ssl_handshake(int conn);

/* Parses the internal tls fragment */
int parse_tls_handshake(unsigned char *fragment, struct sslSession *ssl_conn);

/* Parse the tls client hello message */
int parse_tls_client_hello(unsigned char *message, struct sslSession *ssl_conn);

int parse_extensions(unsigned char *msg, struct sslSession *sslConn);

unsigned short parse_server_name_ext(unsigned char **msg);

unsigned short parse_supported_groups_ext(unsigned char **msg);

unsigned short parse_ec_point_formats_ext(unsigned char **msg);

unsigned short parse_signature_algorithms_ext(unsigned char **msg);

unsigned short parse_use_srtp_ext(unsigned char **msg);

unsigned short parse_proto_negotiation_ext(unsigned char **msg);
