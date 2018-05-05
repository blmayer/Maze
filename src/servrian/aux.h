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

/* File operations definitions */

int file_size(char *path);

char *load_file(char *path);

int write_log(char buff[512]);

/* Header processing tools */

char *date_line();

char *mime_type(char *ext);

#endif

