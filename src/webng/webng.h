/*
 *  This is the file that defines our structures used in our functions, here
 *  we have the cryptographic key, encrypting requests; the request struct
 *  to hold the information pertaining to a request; and the response struct
 *  holding the response information.
 */

#ifndef LIBWEB_H
#define LIBWEB_H

/*
 * Objects definitions
 */

/* Our structure that contains the response's data */
struct response {
	int status;
	unsigned char *type;
	unsigned char *path;
	float vers;
	unsigned char *serv;
	unsigned char *date;
	unsigned char *conn;
	unsigned char *auth;
	unsigned char *key;
	unsigned char *cenc;
	unsigned char *ctype;
	int clen;
	unsigned char *ttype;
	unsigned char *body;
};

/* Our structure that contains the request's data */
struct request {
	unsigned char *type;
	unsigned char *url;
	float vers;
	unsigned char *host;
	unsigned char *conn;
	unsigned char *user;
	unsigned char *auth;
	unsigned char *key;
	unsigned char *cenc;
	unsigned char *ctype;
	int clen;
	unsigned char *ttype;
	unsigned char *body;
};

struct url {
	unsigned char *proto;
	unsigned char *ip;
	unsigned char *domain;
	unsigned char *path;
	unsigned char *pars;
};

/*
 * Funtion prototypes
 */

/* Reads data in chunked format from a socket */
unsigned char *read_chunks(int conn);

/* Reads data in the HTTP header format from a socket */
unsigned char *get_header(int conn);

/* Extracts a token from a string */
unsigned char *get_token(unsigned char *source, char par[]);

/* Extracts the path from an URL */
int parse_URL(char *url, struct url *addr);

/* Parses a string and populates the request structure */
int parse_request(unsigned char *message, struct request *req);

/* Parses a string and populates the reponse structure */
int parse_response(unsigned char *message, struct response *res);

/* Creates a HTTP header string */
unsigned char *create_req_header(struct request req);

/* Creates a response with header and optional body */
unsigned char *create_res_header(struct response res);

/* Reads a message and encodes it */
unsigned char *encode(unsigned char *message, unsigned char key[]);

/* Reads an encrypted message and decodes it */
unsigned char *decode(unsigned char *cypher, unsigned char key[]);

#endif

