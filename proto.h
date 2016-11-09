#ifndef _VPND_PROTO_H_
#define _VPND_PROTO_H_

#include "vpnd.h"

#define DATA_SZ 1500
/* Message data structure definitions */
struct vpn_msg {
	unsigned char	type;
	unsigned char	data[DATA_SZ];
};

bool		init(struct vpn_state *vpn, int vflag, bool fflag, char *prog_name, char *config_fname);
void		return_to_init_state(struct vpn_state *vpn);
void		change_state(struct vpn_state *vpn, vpn_state new_state);
bool		tx_encrypted(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);
void		tx_peer_info(struct vpn_state *vpn);
void		tx_new_public_key(struct vpn_state *vpn);
void		tx_key_ready(struct vpn_state *vpn);
void		process_peer_info(struct vpn_state *vpn, struct vpn_msg *msg, struct sockaddr *peer_addr, socklen_t peer_addr_len);
void		process_key_switch_start(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_key_switch_ack(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_key_ready(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_debug_string(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);

void		process_rx_data(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);
void		ext_sock_input(struct vpn_state *vpn);
void		ctrl_sock_input(struct vpn_state *vpn);
void		stats_sock_input(struct vpn_state *vpn);
void		stdin_input(struct vpn_state *vpn);
bool		check_peer_alive(struct vpn_state *vpn, struct timespec now);
void		process_timeout(struct vpn_state *vpn, struct kevent *kev);


#endif /* !_VPND_PROTO_H_ */
