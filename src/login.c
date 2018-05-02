/*
 * ****************************************************************************
 *
 * PROJECT:     Servrian
 *
 * TITLE:       
 *
 * FUNCTION:
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * NOTES:       This is the function that will process the authorization an
 *              authentication requested in the POST /login request. It takes
 *              only one argument: the key made in the login script, in the
 *              browser. Then we do all checks and send the appropriate return
 *              value.
 *
 * COPYRIGHT:   All rigths reserved. All wrongs deserved. (Peter D. Hipson)
 *
 * ****************************************************************************
 */

#include "login.h"

int authorization(char *auth_code) {
    
    // Here we read the auth code from request and check its validity
    char *method = strtok(auth_code, " ");          // Get the hashing method
    if(strcasecmp(method, "Basic") != 0) {
        // Method not supported
        puts("\t\tError authenticating user: unsupported method.");
        return -2;
    }
    
    // Process the authorization line into tokens
    strtok(NULL, " ");                              // This gives login:passwd
    char *login = strtok(NULL, ":");                // The user login
    char *passwd = strtok(NULL, "");                // The user's password
    
    // Load our users file
    char *users_db = load_file("db/users.txt");
    if(users_db == NULL) {
        // Could not open our file
        perror("\t\tError authenticating user");
        return -3;
    }
    
    // Check if the user exists in our database
    char* db_login = get_token(users_db, login);    // Gives user:SHA1(passwd) 
    if(db_login == NULL) {
        // User doesn't exists, unauthorized
        puts("\t\tUser does not exists in database.");
        return -1;
    }
    
    // Now we check if the password is correct
    char *db_passwd = strtok(db_login, ":");        // The db's hashed password
    char enc_passwd[SHA_DIGEST_LENGTH + 1];         // Hashed passwd variable
    SHA1(passwd, strlen(passwd), enc_passwd);       // This is the SHA1(passwd)
    
    // Check if hashes are equal
    if(strcmp(db_passwd, enc_passwd) != 0) {
        // User exists but is not authorized
        puts("\t\tUnauthorized user, wrong password.");
        return 1;
    }
    
    // User is authorized
    puts("\t\tAuthorized user.");
    return 0;
}

int handle_login(int conn, struct header req) {
    
    // We need to read the encrypted credentials in the header
    req.auth = get_token(req.rest, "Authorization: ");

    // Check the user credentials
    if(authorization(req.auth) == 0) {
        // User is authorized, logged in
    } 

    return 0;
}
