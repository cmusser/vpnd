#ifndef _VPND_DIAG_H_
#define _VPND_DIAG_H_

#include <syslog.h>
#include <time.h>

#include "vpnd.h"

void		log_msg   (struct vpn_state *vpn, int priority, const char *msg,...);
char           *time_str(time_t time, char *time_str, size_t len);
void		log_invalid_msg_for_state(struct vpn_state *vpn, message_type msg_type);
void		log_nonce (struct vpn_state *vpn, char *prefix, nonce_type type, unsigned char *nonce);
void		log_retransmit(struct vpn_state *vpn, message_type msg_type);
void		log_skip_retransmit(struct vpn_state *vpn, uintptr_t timer_id);
void		log_stats (struct vpn_state *vpn);
void		tx_graphite_stats(struct vpn_state *vpn, int client_fd);

#endif				/* !_VPND_DIAG_H_ */
