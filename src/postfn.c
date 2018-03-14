/*
 * ****************************************************************************
 *
 * PROJECT:     Servrian
 *
 * TITLE:       
 *
 * FUNCTION:    This is the function that will process the file requested in a
 *              POST, it takes three arguments: The endpoint chosen will
 *              determine what script (function) would handle the request.
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * NOTES:
 *
 * COPYRIGHT:   All rigths reserved. All wrongs deserved. (Peter D. Hipson)
 *
 * ****************************************************************************
 */

#include "postfn.h"
#include "login.h"

int handle_post(int conn, struct header req, int encrypted){
    
    /* Choose what to do depending on the path */
    int *ret;
    switch(strcmp(req.path, "webpages/login")) {
        case 0:
        puts("\t\tAuthorizing...");
        *ret = handle_login(conn, req);
        break;
    }
    
    /* Get the content length */
    char *clen = get_token(req.rest, "Content-Length: ");
    if(clen != NULL) {
        req.clen = atoi(clen);
    }
    
    /* Read the requested file */
    char *file_content = load_file(req.path);     /* Read the file requested */
    
    if(!file_content) {
        /* Something went wrong, problably file was not found */
        req.status = 404;
        file_content = load_file("webpages/404.html");
    }
    
    /* Calculate body length */
    int con_len = strlen(file_content);
    
    /* Create the head */
    char *head = create_response(req, encrypted);
    
    /* Send the head */
    write(conn, head, strlen(head));
    
    /* Send the body */
    write(conn, file_content, con_len);
    
    printf("\tFile %s served.\n", req.path);
    return 0;
}

