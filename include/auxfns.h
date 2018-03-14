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
#include <time.h>
#include <math.h>
#include <openssl/sha.h>
#include "header.h" 
#include "transform.h"

/* File operations definitions */

int file_size(char *path);

char *load_file(char *path);

int write_log(char buff[512]);

/* Header processing tools */

char *get_token(char *source, char par[]);

char *age_line();

char *mime_type(char *ext);

char *create_response(struct header req, int encrypted);

#endif

