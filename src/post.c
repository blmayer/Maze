/*
 * ****************************************************************************
 *
 * PROJECT:     Servrian
 *
 * FUNCTION:    This is the function that will process the file requested in a
 *              POST, it takes three arguments: The endpoint chosen will
 *              determine what script (function) would handle the request.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * Copyright (c) 2018    Brian Mayer
 *
 * ****************************************************************************
 */

#include "post.h"
#include "login.h"

int handle_post(unsigned int conn, struct response res){
    
    /* Choose what to do depending on the path */
    int *ret = 0;
    switch(strcmp(res.path, "webpages/login")) {
        case 0:
        puts("\t\tAuthorizing...");
        *ret = authorization(res.auth);
        break;
    }
    
    /* Read the requested file */
    char *file_content = load_file(res.path);     /* Read the file requested */
    
    if(!file_content) {
        /* Something went wrong, probably file was not found */
        res.status = 404;
        file_content = load_file("webpages/404.html");
    }
    
    /* Calculate body length */
    int con_len = strlen(file_content);
    
    /* Create the head */
    unsigned char *head = create_res_header(res);
    
    /* Send the head */
    write(conn, head, strlen(head));
    
    /* Send the body */
    write(conn, file_content, con_len);
    
    printf("\tFile %s served.\n", res.path);
    return 0;
}

