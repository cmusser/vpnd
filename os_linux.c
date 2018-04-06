#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <net/if.h>
#include <linux/if_tun.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "diag.h"
#include "nonce.h"
#include "os.h"
#include "proto.h"
#include "util.h"

#define DUMMY_REMOTE_NET_ADDR "192.168.239.254"

bool
open_tun_sock(struct vpn_state *vpn, char *tun_dev_str)
{
	bool		ok = true;

	return ok;
}

void
init_event_processing(struct vpn_state *vpn, bool stdin_events)
{
}

bool
get_forwarding(struct vpn_state *vpn, sa_family_t addr_family)
{
	bool		flag_bool = false;

	return flag_bool;
}

void
set_forwarding(struct vpn_state *vpn, sa_family_t addr_family, bool value)
{
}

void
set_tun_addrs(struct vpn_state *vpn, char *host_addr_str, tun_addr_mode mode)
{
	char		cmd       [256] = {'\0'};

	switch (mode) {
	case HOST_LOCAL:
		snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s %s %s",
		    vpn->tun_name, host_addr_str, DUMMY_REMOTE_NET_ADDR);
		break;
	case HOST_REMOTE:
		snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s %s %s",
		    vpn->tun_name, DUMMY_REMOTE_NET_ADDR, host_addr_str);
		break;
	default:
		log_msg(vpn, LOG_WARNING, "%s: %s tunnel addr mode (%d)",
		    VPN_ROLE_STR(vpn->role), TUN_ADDR_MODE_STR(mode), mode);
		return;
	}

	spawn_subprocess(vpn, cmd);
	log_msg(vpn, LOG_NOTICE, "%s configured tunnel with host on %s end: %s",
		    VPN_ROLE_STR(vpn->role), TUN_ADDR_MODE_STR(mode), cmd);
}

void
set_tun_state(struct vpn_state *vpn, intf_action action)
{
	char		cmd       [256] = {'\0'};
#ifdef __NetBSD__
	const char     *tun_addr = DUMMY_REMOTE_NET_ADDR;
#else
	const char     *tun_addr = "";
#endif

	switch (action) {
	case UP:
		snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s %s up",
		    vpn->tun_name, tun_addr);
		break;
	case DOWN:
		snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s %s down",
		    vpn->tun_name, tun_addr);
		break;
	default:
		log_msg(vpn, LOG_WARNING, "%s action (%d) for tunnel state",
		    INTF_ACTION_STR(action), action);
		return;
	}
	spawn_subprocess(vpn, cmd);
	log_msg(vpn, LOG_NOTICE, "%s configured tunnel state to %s: %s",
	    VPN_ROLE_STR(vpn->role), INTF_ACTION_STR(action), cmd);
}

void
configure_route_on_host(struct vpn_state *vpn, char *net_addr_str, route_action action)
{
	char		cmd       [256] = {'\0'};

	switch (action) {
	case ADD:
		snprintf(cmd, sizeof(cmd), "/sbin/route add %s/%u -interface %s",
		    net_addr_str, vpn->rx_peer_info.host_prefix_len, vpn->tun_name);
		break;
	case DELETE:
		snprintf(cmd, sizeof(cmd), "/sbin/route delete %s/%u -interface %s",
		    net_addr_str, vpn->rx_peer_info.host_prefix_len, vpn->tun_name);
		break;
	default:
		log_msg(vpn, LOG_WARNING, "%s route action (%d)",
		    ROUTE_ACTION_STR(action), action);
		return;
	}
	spawn_subprocess(vpn, cmd);
	log_msg(vpn, LOG_NOTICE, "%s route %s: %s",
	    VPN_ROLE_STR(vpn->role), ROUTE_ACTION_STR(action), cmd);
}

void
configure_route_on_net_gw(struct vpn_state *vpn, char *remote_network_str, route_action action)
{
	char		cmd       [256] = {'\0'};

#ifdef __NetBSD__
	const char     *route_param = "-link ";
#else
	const char     *route_param = "";
#endif

	switch (action) {
	case ADD:
		snprintf(cmd, sizeof(cmd), "/sbin/route add %s/%u %s-interface %s",
		    remote_network_str, vpn->remote_network_prefix_len,
		    route_param, vpn->tun_name);
		break;
	case DELETE:
		snprintf(cmd, sizeof(cmd), "/sbin/route delete %s/%u %s-interface %s",
		    remote_network_str, vpn->remote_network_prefix_len,
		    route_param, vpn->tun_name);
		break;
	default:
		log_msg(vpn, LOG_WARNING, "%s route action (%d)",
		    ROUTE_ACTION_STR(action), action);
		return;
	}
	spawn_subprocess(vpn, cmd);
	log_msg(vpn, LOG_NOTICE, "%s route %s: %s",
	    VPN_ROLE_STR(vpn->role), ROUTE_ACTION_STR(action), cmd);
}

void
get_cur_monotonic(struct timespec *tp)
{
	clock_gettime(CLOCK_MONOTONIC, tp);
}

void
add_timer(struct vpn_state *vpn, timer_type ttype, intptr_t timeout_interval)
{
}

bool
run(struct vpn_state *vpn)
{
	bool		ok = true;

	return ok;
}
