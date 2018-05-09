/* Test file for create_res_header */
#include <stdio.h>
#include <webng.h>

int main(void)
{
	struct response res = {0};
	res.status = 200;
	res.vers = -1.0;
	res.serv = "test";
	res.conn = "Keep-Alive";
	res.date = "today";
	res.ctype = "text";
	res.clen = 1000;

	printf("Header is:\n'%s'\n", create_res_header(res));

	/* ---- Encoded version --------------------- */

	res.key = "iyudr&^R$$$&ES&*#4dR^&&^$#";
	printf("Encoded header is:\n'%s'\n", create_res_header(res));

	return 0;
}

