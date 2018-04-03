/*
 *  This is the function that sends a GET request of a file, it takes
 *  two arguments: the client's connection and the file requested in the GET
 *  message.
 */

#ifndef GETFN_H
#define GETFN_H

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <web.h>
#include "auxfns.h"

/* Receives client's parameters and sends a file */
int send_get(int conn, struct request req);

#endif

