/* Test file for the parse_URL function */
#include <stdio.h>
#include <webng.h>

int main(int argc, char *argv[])
{
	if(argc > 2)
	{
		puts("Please supply exactly one argument");
		return 1;
	}

	struct url addr = {0};
	parse_URL(argv[1], &addr);

	printf("parsed:\nproto: %s\ndomain: %s\nport: %s\npath: %s\npars: %s\n",
		addr.proto, addr.domain, addr.port, addr.path, addr.pars);

	return 0;
}

