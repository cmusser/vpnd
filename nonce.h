#ifndef _VPND_NONCE_H_
#define _VPND_NONCE_H_

#include "vpnd.h"

bool		check_nonce(struct vpn_state *vpn, unsigned char *nonce);
void		purge_late(struct vpn_state *vpn);

#endif				/* !_VPND_NONCE_H_ */
