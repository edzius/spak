/**
 * sipenc - secure image encrypt utility
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
	fprintf(stderr, "Usage: sipenc [-m MARK] <source-file> <output-file>\n");
}

int
main(int argc, char *argv[])
{
	int opt;
	char *srcfile;
	char *dstfile;
	char *mark = NULL;

	while ((opt = getopt(argc, argv, "m:")) != -1) {
		switch (opt) {
		case 'm':
			mark = optarg;
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

	if (argc - optind < 2) {
		sip_usage();
		exit(EXIT_FAILURE);
	}

	srcfile = argv[optind];
	dstfile = argv[optind + 1];

	if (sip_encode(srcfile, dstfile, mark)) {
		return 1;
	}

	return 0;
}
