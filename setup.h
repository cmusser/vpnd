#ifndef _VPND_SETUP_H_
#define _VPND_SETUP_H_

#include "vpnd.h"

bool		init(struct vpn_state *vpn, int verbose, bool daemon_mode, char *prog_name, char *config_fname);

#endif				/* !_VPND_SETUP_H_ */
