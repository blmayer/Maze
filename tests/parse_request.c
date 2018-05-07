/* Test file for parsing requests headers */
#include <stdio.h>
#include <webng.h>

int main(void)
{
	unsigned char request[] = "GET / HTTP/1.1\r\n"
		  		  "Host: localhost\r\n"
		  		  "User-Agent: Maze-0.0.1\r\n"
		  		  "Connection: Keep-Alive\r\n"
		  		  "Accept: */*\r\n"
		  		  "Key: l1:#:Af2iI@b[eC;>iuy<5~+>zx{4ok?grvA<bu}=-hb<q~2vd$Hfi%g~z][>nfst!$&yIJK[9$Ba]1z$_nq{Dsdtu]J.x9Bgocf-7q=xn|sv~mB(`fHae)ub9aIH^b=r{Bk_K-<0r!F2}z(~-`EA(s$F,Bwxm-~wrEnels)f%cqEr)5{saG3w?s{2cogqhBxev]{iArw`IuFCma-/(E[.|$-GtHh]8;5h?yon]5zeKGx2l<]mqdm?]3/i+r37uf.r,,bcmI=nCpAnqGcFh9`*x|}z`CKKd$n<3;)c@]<yd|a.&|(]%365ns4#.is^$Ka.t(p}}k3kw;nd]!cp/857ou#@nmdIED@e/Eq*[f^Bja6wmAhF}1b^&8),t]diE6ouEHl;44%-@l`_z{mt?KJ(1/3zq+m^c=,-3b]p-<9o3rH3GA~oIo|/%0/eH3.kdc}o*o%|7z/Chiu`Hv$@|t^8-(?g.AGA8j7sw-=1<b><7Kn$s|C1vGzc05(=f3?m>,\r\n";

	struct request req = {0};
	if(parse_request(request, &req) != 0)
	{
		puts("Failed to parse the header.");
	}

	/* Print values for checking */
	puts("\tParsed:");
	printf("\tType: %s\n", req.type);
	printf("\tPath: %s\n", req.url);
	printf("\tVersion: %.1f\n", req.vers);
	printf("\tUser: %s\n", req.user);
	printf("\tHost: %s\n", req.host);
	printf("\tConnection: %s\n", req.conn);
	printf("\tContent Type: %s\n", req.ctype);
	printf("\tContent Length: %d\n", req.clen);
	printf("\tAuthorization: %s\n", req.auth);
	printf("\tKey: %s\n", req.key);

	return 0;
}

