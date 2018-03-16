/*
 *  This is the main communication function, it is called when the user enters
 *  the url to connect to, this is equivalent to a tab. The function receives 
 *  an URL as argument, it then opens a TCP socket and tries to connect to the
 *  specified URL. Here a request should be elaborated and a response read, or
 *  discard the connection if it doesn't communicate correctly. 
 */

#ifndef CONNECT_H
#define CONNECT_H

#include <sys/socket.h>
#include <unistd.h>
#include "headers.h"
#include "auxfns.h"
#include "headfn.h"
#include "getfn.h"
#include "postfn.h"

/* This function connects to an URL and communicates */
int connect(char *server_url);

#endif

