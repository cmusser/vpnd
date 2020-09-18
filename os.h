#ifndef _VPND_OS_H_
#define _VPND_OS_H_

#include "vpnd.h"

bool		open_tun_sock(struct vpn_state *vpn, char *tun_name_str);
bool		init_event_processing(struct vpn_state *vpn, bool daemon_mode);
bool		get_forwarding(struct vpn_state *vpn, sa_family_t addr_family);
void		set_forwarding(struct vpn_state *vpn, sa_family_t addr_family, bool value);
void		set_tun_addrs(struct vpn_state *vpn, char *host_addr_str, tun_addr_mode mode);
void		set_tun_state(struct vpn_state *vpn, intf_action action);
void		configure_route_on_host(struct vpn_state *vpn, char *net_addr_str, route_action action);
void		configure_route_on_net_gw(struct vpn_state *vpn, route_action action);
void		get_cur_monotonic(struct timespec *tp);
void		add_timer (struct vpn_state *vpn, timer_type ttype);
bool		run       (struct vpn_state *vpn);
#endif				/* !_VPND_OS_H_ */
