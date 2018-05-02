/*
 * ****************************************************************************
 *
 * PROJECT:     Maze
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * Copyright (C) 2018    Brian Lee Mayer
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * ****************************************************************************
 */

#include "auxfns.h"

/* File operations definitions */

int file_size(char *path) {
    
    /* Get the length of the file requested */
    FILE *page_file = fopen(path, "r");
    
    if(page_file == NULL) {
        perror("\t\tSomething went wrong.");
        return -1;
    }
    
    fseek(page_file, 0, SEEK_END);      /* Seek to the last byte of the file */
    int page_size = ftell(page_file);   /* The SEEK position is the file size */
    fclose(page_file);
    
    return page_size;
}

char *load_file(char *path) {
    
    /* Open the file for reading */
    FILE *page_file = fopen(path, "rb");
    
    if(page_file == NULL) {
        perror("\t\tCannot open file");
        return NULL;
    }
    
    fseek(page_file, 0, SEEK_END);      /* Seek to the last byte of the file */
    int page_size = ftell(page_file);   /* The SEEK position is the file size */
    rewind(page_file);                  /* Go back to the start of the file */
    
    /* Read it all in one operation and close */
    char buff[page_size + 1];
    fread(buff, page_size, sizeof(unsigned char), page_file);
    fclose(page_file);                  /* Close the file */
    buff[page_size] = 0;                /* Add the terminating zero */
   
    return strdup(buff);
}

int write_log(char *buff) {
    FILE *log_file = fopen("logs/log.txt", "a");
    
    if(log_file == NULL) {
        perror("\t\tError oppening file");
        exit(1);
    }
    
    fprintf(log_file, "Received:\n%s\n", buff);
    fclose(log_file);
    
    return 0;
}

/* Header processing tools */

char *mime_type(char *path) {
    
    char *mime;

    /* Match the extension against some cases */
    switch(strcmp(strchr(path, '.'), ".bsog")) {
        case 6:
            mime = "Content-Type: text/html\r\n";
            break;
        
        case 1:
            mime = "Content-Type: text/css\r\n";
            break;
        
        case 2:
            mime = "Content-Type: application/javascript\r\n";
            break;
        
        case 14:
            mime = "Content-Type: image/png\r\n";
            break;
        
        case 17:
            mime = "Content-Type: image/svg+xml\r\n";
            break;
        
        case 7:
            mime = "Content-Type: image/x-icon\r\n";
            break;
            
        case 21:
            mime = "Content-Type: application/x-font-woff\r\n";
            break;
            
        default:
            mime = "Content-Type: application/octet-stream\r\n";
            break;
    }
    
    /* Duplicate the token found to not get lost with function */
    return strdup(mime);
}

