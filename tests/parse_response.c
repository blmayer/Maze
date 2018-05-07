/* Test file for parsing requests headers */
#include <stdio.h>
#include <webng.h>

int main(void)
{
	unsigned char response[] = "HTTP/1.1 200 OK\r\n"
				   "Server: Servrian-0.0.1\r\n"
				   "Date: Mon, 07 May 2018 02:57:50 GMT\r\n"
				   "Content-Type: text/html\r\n"
				   "Content-Length: 1600\r\n"
				   "Connection: Keep-Alive\r\n";

	struct response res = {0};
	if(parse_response(response, &res) != 0)
	{
		puts("Failed to parse the header.");
	}

	/* Print values for checking */
	puts("\tParsed:");
	printf("\tType: %s\n", res.type);
	printf("\tPath: %s\n", res.path);
	printf("\tVersion: %.1f\n", res.vers);
	printf("\tStatus: %d\n", res.status);
	printf("\tServer: %s\n", res.serv);
	printf("\tDate: %s\n", res.date);
	printf("\tConnection: %s\n", res.conn);
	printf("\tContent Type: %s\n", res.ctype);
	printf("\tContent Length: %d\n", res.clen);
	printf("\tAuthorization: %s\n", res.auth);
	printf("\tKey: %s\n", res.key);

	return 0;
}

