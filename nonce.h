#ifndef _VPND_NONCE_H_
#define _VPND_NONCE_H_

#include "vpnd.h"

bool		read_nonce(struct vpn_state *vpn, nonce_type type);
void		write_nonce(struct vpn_state *vpn, nonce_type type);
uint32_t	cur_key_late_packets(struct vpn_state *vpn);
bool		check_nonce(struct vpn_state *vpn, unsigned char *nonce);
void		purge_late(struct vpn_state *vpn);

#endif				/* !_VPND_NONCE_H_ */
