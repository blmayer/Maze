/*
 *  Here we have auxiliary functions intended to be used by other functions.
 */

#ifndef AUXFNS_H
#define AUXFNS_H

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <math.h>
#include <openssl/sha.h>
#include "headers.h" 
#include "transform.h"

/* Header processing tools */

char *mime_type(char *ext);

unsigned char *create_request(struct request req, int encrypted);

#endif

