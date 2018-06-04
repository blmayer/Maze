/*
 *  This is the file that defines our structures used in our functions, here
 *  we have the cryptographic key, encrypting requests; the request struct
 *  to hold the information pertaining to a request; and the response struct
 *  holding the response information.
 */

#ifndef WEBNG_H
#define WEBNG_H

/*
 * Objects definitions
 */

/* Our structure that contains the response's data */
struct response {
	int status;
	char *type;
	char *path;
	float vers;
	char *serv;
	char *date;
	char *conn;
	char *auth;
	char *key;
	char *cenc;
	char *ctype;
	int clen;
	char *ttype;
	char *body;
};

/* Our structure that contains the request's data */
struct request {
	char *type;
	char *url;
	float vers;
	char *host;
	char *conn;
	char *user;
	char *auth;
	char *key;
	char *cenc;
	char *ctype;
	int clen;
	char *ttype;
	char *body;
};

struct url {
	char *proto;
	char *ip;
	char *port;
	char *domain;
	char *path;
	char *pars;
};

/*
 * Funtion prototypes
 */

/* Reads data in chunked format from a socket */
char *read_chunks(int conn);

/* Reads data in the HTTP header format from a socket */
char *get_header(int conn);

/* Extracts a token from a string */
char *get_token(char *source, char par[]);

/* Extracts the path from an URL */
short parse_URL(char *url, struct url *addr);

/* Parses a string and populates the request structure */
short parse_request(char *message, struct request *req);

/* Parses a string and populates the reponse structure */
short parse_response(char *message, struct response *res);

/* Creates a HTTP header string */
char *create_req_header(struct request req);

/* Creates a response with header and optional body */
char *create_res_header(struct response res);

/* Parses a list of numbers from a string to an array */
short *to_key(char *key_list);

/* Reads a message and encodes it */
short *encode(char *message, short *key);

/* Reads an encrypted message and decodes it */
char *decode(int *cypher, int *key);

#endif

