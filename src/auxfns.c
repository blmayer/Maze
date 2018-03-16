/*
 * ****************************************************************************
 *
 * PROJECT:     Maze
 *
 * TITLE:       Auxiliary Functions
 *
 * FUNCTIONS:   
 *
 * AUTHOR:      Brian Mayer blmayer@icloud.com
 *
 * NOTES:       
 *
 * COPYRIGHT:   All rigths reserved. All wrongs deserved. (Peter D. Hipson)
 *
 * ***************************************************************************
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

char *get_token(char *source, char par[]) {
    
    /* Search for the parameter passed */
    char *tag = strcasestr(source, par);
    
    /* Check if parameter exists in header */
    if(tag == NULL) {
        return NULL;
    }
    
    char *token = strtok(tag + strlen(par), "\r\n");
    
    /* Duplicate the token found to not get lost with function */
    return strdup(token);
}

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

char *create_request(struct header req, int encrypted){
    
    /* URL request line */
    int req_size = strlen(req.type) + strlen(req.url) + 9; /* Includes end 0 */
    char req_line[req_size];

    /* Host line */
    int host_size =  

    /* Client identification */
    char *user = "User-Agent: Maze/<VERSION> (x86_64)\r\n";

    /* Connection line */
    char *conn_type = "Keep-Alive";

    /* Now assemble they all into one string, first calculate the length */
    int head_len = strlen(user);
    head_len += strlen(mime) + strlen(con_len) + strlen(conn_type) + 2;
    head_len += req.clen;
    
    
    /* The header string */
    unsigned char head[head_len + req.clen];
    sprintf(head, "%s%s%s%s", status_line, date_line, server, conn_type);
    sprintf(head + strlen(head), "%s%s\r\n", mime, con_len);

    /* The body of the response */
    strcat(head, req.body);

    if(encrypted){
        strcpy(head, encode(head));
    }

    return strdup(head);
}

