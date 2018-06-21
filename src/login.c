/*
 * ****************************************************************************
 *
 * FUNCTION:	authorization:  Checks the autorization code in a client's re -
 *		rest and return a status;
 *		handle_login:   Function that when called authorizes or not an
 *		user.
 *
 * AUTHOR:	  Brian Mayer	blmayer@icloud.com
 *
 * Copyright (C) 2018	Brian Lee Mayer
 *
 * ****************************************************************************
 */

#include "login.h"

short authorization(unsigned char *auth_code)
{	
	/* Here we read the auth code from request and check its validity */
	char *method = strtok(auth_code, " ");	/* Get the hashing method */
	if(strcasecmp(method, "Basic") != 0) {
		/* Method not supported */
		puts("\t\tError authenticating user: unsupported method.");
		return 501;
	}
	
	/* Process the authorization line into tokens */
	strtok(NULL, " ");			/* This gives login:passwd */
	unsigned char *login = strtok(NULL, ":");	/* The user login */
	unsigned char *passwd = strtok(NULL, "");	/* The password */
	
	/* Load our users file */
	char *users_db = load_file("db/users.txt");
	if(users_db == NULL) {
		/* Could not open our file */
		perror("\t\tError authenticating user");
		return 500;
	}
	
	/* Check if the user exists in our database */
	char* db_login = strstr(users_db, login); 	/* user:SHA1(passwd) */
	if(db_login == NULL) {
		/* User doesn't exists, unauthorized */
		puts("\t\tUser does not exists in database.");
		return 403;
	}
	
	/* Now we check if the password is correct */
	unsigned char *db_passwd = strtok(db_login, ":");
	unsigned char enc_passwd[SHA_DIGEST_LENGTH + 1];
	SHA1(passwd, strlen(passwd), enc_passwd);	/* SHA1(passwd) */
	
	/* Check if hashes are equal */
	if(strcmp(db_passwd, enc_passwd) != 0) {
		/* User exists but is not authorized */
		puts("\t\tUnauthorized user, wrong password.");
		return 401;
	}
	
	/* User is authorized */
	puts("\t\tAuthorized user.");
	return 200;
}

