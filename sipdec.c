/**
 * sipdec - secure image decrypt utility
 * Author: Edvinas Stunzenas <edvinas.stunzenas@gmail.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "sipop.h"

static void
sip_usage(void)
{
	fprintf(stderr, "Usage: sipenc [-c] <source-file> <output-file>\n");
}

int
main(int argc, char *argv[])
{
	int opt;
	char *srcfile;
	char *dstfile;
	int check = 0;

	while ((opt = getopt(argc, argv, "c")) != -1) {
		switch (opt) {
		case 'c':
			check = 1;
			break;
		default:
			sip_usage();
			exit(EXIT_FAILURE);
		}
	}

	if (optind >= argc) {
		sip_usage();
		exit(EXIT_FAILURE);
	}

	if (check) {
		if (argc - optind < 1) {
			sip_usage();
			return 1;
		}

		srcfile = argv[optind];

		if (sip_check(srcfile)) {
			return 1;
		}
	} else {
		if (argc - optind < 2) {
			sip_usage();
			return 1;
		}

		srcfile = argv[optind];
		dstfile = argv[optind + 1];

		if (sip_decode(srcfile, dstfile)) {
			return 1;
		}
	}

	return 0;
}
