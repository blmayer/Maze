/*
 *  This is the function that sends the file requested in a response, it takes
 *  two arguments: the client's connection and the file requested in the GET
 *  message.
 */

#ifndef LOGIN_H
#define LOGIN_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include "auxfns.h"

// Receives client's parameters and sends a file
int authorization(char *auth_code); 

// The login function that does everything
int handle_login(int conn, struct header req);

#endif

