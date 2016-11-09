#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "os.h"
#include "proto.h"

int
main(int argc, char *argv[])
{

	const char     *opts;
	int		ch;
	int		vflag = 0;
	bool		fflag = false;
	struct vpn_state vpn;
	char           *config_fname;

	opts = "vfc:";
	config_fname = "vpnd.conf";

	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'v':
			vflag++;
			break;
		case 'f':
			fflag = true;
			break;
		case 'c':
			config_fname = optarg;
			break;
		default:
			fprintf(stderr, "usage: vpnd [-vfc]\n");
			fprintf(stderr, "  -f: foreground mode (default: daemon)\n");
			fprintf(stderr, "  -v: verbosity (default: NOTICE; use once for\n");
			fprintf(stderr, "      INFO, multiple times for DEBUG)\n");
			fprintf(stderr, "  -c: config file (default: vpnd.conf)\n");
			exit(EXIT_FAILURE);
		}
	}

	if (init(&vpn, vflag, fflag, argv[0], config_fname)) {
		if (!fflag)
			daemon(0, 0);

		return run(&vpn) ? EXIT_SUCCESS : EXIT_FAILURE;
	} else {
		return EXIT_FAILURE;
	}
}
