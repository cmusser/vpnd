#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "os.h"
#include "proto.h"
#include "setup.h"

#define VPND_CONF_FILENAME "/etc/vpnd.conf"

int
main(int argc, char *argv[])
{

	const char     *opts;
	int		ch;
	int		vflag = 0;
	bool		dflag = false;
	struct vpn_state vpn;
	char           *config_fname;

	opts = "vVfc:";
	config_fname = VPND_CONF_FILENAME;

	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'v':
			vflag++;
			break;
		case 'V':
			printf("vpnd %s\n", VPND_VERSION);
			exit(0);
			break;
		case 'd':
			dflag = true;
			break;
		case 'c':
			config_fname = optarg;
			break;
		default:
			fprintf(stderr, "usage: vpnd [-vVfc]\n");
			fprintf(stderr, "  -d: run as a daemon (default: run in foreground)\n");
			fprintf(stderr, "  -v: verbosity (default: NOTICE; use once for\n");
			fprintf(stderr, "      INFO, multiple times for DEBUG)\n");
			fprintf(stderr, "  -V: display version, then exit\n");
			fprintf(stderr, "  -c: config file (default: %s)\n", VPND_CONF_FILENAME);
			exit(EXIT_FAILURE);
		}
	}

	if (init(&vpn, vflag, dflag, argv[0], config_fname)) {
		if (dflag)
			daemon(0, 0);

		return run(&vpn) ? EXIT_SUCCESS : EXIT_FAILURE;
	} else {
		return EXIT_FAILURE;
	}
}
