/**
 * sip - secure image packer utility
 * Author: Edvinas Stunzenas <edvinas.stunzenas@gmail.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#include "sipop.h"

#define SIP_OP_NONE	0
#define SIP_OP_ENCODE	1
#define SIP_OP_DECODE	2
#define SIP_OP_CHECK	3

static char sip_ops_short[] = "edcm:";

static struct option sip_ops_long[] = {
        { "encode",          0, 0, 'e' },
        { "decode",          0, 0, 'd' },
        { "check",           0, 0, 'c' },
        { "mark",            1, 0, 'm' },
        { 0, 0, 0, 0 }
};

static void
sip_usage(void)
{
	fprintf(stderr, "Usage: sip [options] <source-file> <output-file>\n"
		"  -e, --encode             Image encode operation\n"
		"  -d, --decode             Image decode operation\n"
		"  -c, --check              Validate provided image\n"
		"  -m, --mark [MARK]        Encoding specific mark\n"
	       );
}

int
main(int argc, char *argv[])
{
	int ret;
	int opt, index;
	int op = SIP_OP_NONE;
	char *srcfile;
	char *dstfile;
	char *mark = NULL;

	while ((opt = getopt_long(argc, argv, sip_ops_short, sip_ops_long, &index)) != -1) {
		switch (opt) {
		case 'e':
			op = SIP_OP_ENCODE;
			break;
		case 'd':
			op = SIP_OP_DECODE;
			break;
		case 'c':
			op = SIP_OP_CHECK;
			break;
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

	switch (op) {
	case SIP_OP_CHECK:
		srcfile = argv[optind];

		ret = sip_check(srcfile);
		break;
	case SIP_OP_ENCODE:
		srcfile = argv[optind];
		dstfile = argv[optind + 1];

		ret = sip_encode(srcfile, dstfile, mark);
		break;
	case SIP_OP_DECODE:
		srcfile = argv[optind];
		dstfile = argv[optind + 1];

		ret = sip_decode(srcfile, dstfile);
		break;
	default:
		fprintf(stderr, "Unknown command\n");
		exit(EXIT_FAILURE);
	}

	if (ret) {
		printf("FAILED\n");
		return 1;
	}

	return 0;
}
