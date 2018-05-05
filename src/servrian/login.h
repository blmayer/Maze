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
#include <webng.h>
#include "aux.h"

/* Receives client's auth parameters and checks */
int authorization(unsigned char *auth_code); 

#endif

