#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysctl.h>

#include <net/if.h>
#ifdef __DragonFly__
#include <net/tun/if_tun.h>
#else
#include <net/if_tun.h>
#endif

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
open_tun_sock(struct vpn_state *vpn, char *tun_name_str)
{
	bool		ok = true;
	char		tun_dev_str[MAXPATHLEN];
	int		ioctl_data;


	snprintf(tun_dev_str, sizeof(tun_dev_str), "/dev/%s", tun_name_str);
	vpn->ctrl_sock = open(tun_dev_str, O_RDWR);
	if (vpn->ctrl_sock < 0) {
		ok = false;
		log_msg(vpn, LOG_ERR, "couldn't open tunnel: %s", strerror(errno));
	}

	if (ok) {
		ioctl_data = IFF_POINTOPOINT;
		if (ioctl(vpn->ctrl_sock, TUNSIFMODE, &ioctl_data) < 0) {
			ok = false;
			log_msg(vpn, LOG_ERR, "couldn't set tunnel in p-t-p mode: %s",
			    strerror(errno));
		}
	}

	if (ok) {
		ioctl_data = 0;
		if (ioctl(vpn->ctrl_sock, TUNSIFHEAD, &ioctl_data) < 0) {
			ok = false;
			log_msg(vpn, LOG_ERR, "couldn't set tunnel in link-layer mode: %s",
			    strerror(errno));
		}
	}

	if (ok)
		strlcpy(vpn->tun_name, tun_name_str, sizeof(vpn->tun_name));

	return ok;
}

bool
init_event_processing(struct vpn_state *vpn, bool stdin_events)
{
	EV_SET(&vpn->kev_changes[0], vpn->ext_sock,
	    EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	vpn->kev_change_count = 1;
	EV_SET(&vpn->kev_changes[1], vpn->ctrl_sock,
	    EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	vpn->kev_change_count++;
	EV_SET(&vpn->kev_changes[2], vpn->stats_sock,
	    EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
	vpn->kev_change_count++;
	EV_SET(&vpn->kev_changes[3], SIGUSR1,
	    EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, 0);
	vpn->kev_change_count++;
	signal(SIGUSR1, SIG_IGN);
	EV_SET(&vpn->kev_changes[4], SIGINT,
	    EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, 0);
	vpn->kev_change_count++;
	signal(SIGINT, SIG_IGN);
	EV_SET(&vpn->kev_changes[5], SIGTERM,
	    EVFILT_SIGNAL, EV_ADD | EV_ENABLE, 0, 0, 0);
	vpn->kev_change_count++;
	signal(SIGTERM, SIG_IGN);

	if (stdin_events) {
		EV_SET(&vpn->kev_changes[6], STDIN_FILENO,
		    EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
		vpn->kev_change_count++;
	}

	return true;
}

bool
get_forwarding(struct vpn_state *vpn, sa_family_t addr_family)
{
	bool		flag_bool = false;
	char		*name;
	uint32_t	flag;
	size_t		flag_sz = sizeof(flag);

	switch (addr_family) {
	case AF_INET:
		name = "net.inet.ip.forwarding";
		break;
	case AF_INET6:
		name = "net.inet6.ip6.forwarding";
		break;
	default:
		name = "net.inet.ip.forwarding";
		log_msg(vpn, LOG_WARNING, "unknown forwarding address family %d, "
		    "defaulting to IPv4", addr_family);
	}

	if (sysctlbyname(name, &flag, &flag_sz, NULL, 0) == -1)
		log_msg(vpn, LOG_ERR, "sysctl get %s: %s", name, strerror(errno));
	else
		flag_bool = (flag == 0) ? false : true;

	return flag_bool;
}

void
set_forwarding(struct vpn_state *vpn, sa_family_t addr_family, bool value)
{
	uint32_t	flag;
	char		*name;

	switch (addr_family) {
	case AF_INET:
		name = "net.inet.ip.forwarding";
		break;
	case AF_INET6:
		name = "net.inet6.ip6.forwarding";
		break;
	default:
		log_msg(vpn, LOG_ERR, "unknown forwarding address family %d, "
		    "ignoring request", addr_family);
		return;
	}

	flag = (value == true) ? 1 : 0;

	if (sysctlbyname(name, NULL, 0, &flag, sizeof(flag)) == -1)
		log_msg(vpn, LOG_ERR, "sysctl set %s: %s", name, strerror(errno));
	else
		log_msg(vpn, LOG_NOTICE, "sysctl %s=%d", name, flag);
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
#ifdef __MacOSX__
#else
	clock_gettime(CLOCK_MONOTONIC, tp);
#endif
}

void
add_timer(struct vpn_state *vpn, timer_type ttype, intptr_t timeout_interval)
{
	if (vpn->kev_change_count < COUNT_OF(vpn->kev_changes)) {
		EV_SET(&vpn->kev_changes[vpn->kev_change_count], ttype,
		       EVFILT_TIMER, EV_ADD | EV_ENABLE | EV_ONESHOT, 0,
		       timeout_interval, 0);
		vpn->kev_change_count++;

	} else {
		log_msg(vpn, LOG_ERR, "%s: No space for timer event (%s)",
			VPN_STATE_STR(vpn->state), TIMER_TYPE_STR(ttype));
	}
}

bool
run(struct vpn_state *vpn)
{
	bool		ok;
	struct kevent	event;
	int		kq        , nev;
	ok = true;

	if ((kq = kqueue()) == -1) {
		ok = false;
		log_msg(vpn, LOG_ERR, "kqueue(): %s", strerror(errno));
	}
	while (ok) {
		nev = kevent(kq, vpn->kev_changes, vpn->kev_change_count,
			     &event, 1, NULL);
		vpn->kev_change_count = 0;
		if (nev < 0) {
			ok = false;
			log_msg(vpn, LOG_ERR, "kevent: %s", strerror(errno));
		} else {
			if (event.flags & EV_ERROR) {
				ok = false;
				log_msg(vpn, LOG_ERR, "EV_ERROR: %s for %" PRIuPTR,
					strerror(event.data), event.ident);
			} else {
				switch (event.filter) {
				case EVFILT_READ:
					if (event.ident == vpn->ext_sock)
						ext_sock_input(vpn);
					else if (event.ident == vpn->ctrl_sock)
						ctrl_sock_input(vpn);
					else if (event.ident == vpn->stats_sock)
						stats_sock_input(vpn);
					else if (event.ident == STDIN_FILENO)
						stdin_input(vpn);
					break;
				case EVFILT_TIMER:
					process_timeout(vpn, event.ident);
					break;
				case EVFILT_SIGNAL:
					switch (event.ident) {
					case SIGUSR1:
						log_stats(vpn);
						break;
					case SIGINT:
					case SIGTERM:
						ok = false;
						log_msg(vpn, LOG_NOTICE, "shutting down (signal %u)",
							event.ident);
						write_nonce(vpn, REMOTE);
						return_to_init_state(vpn);
						break;
					default:
						break;
					}

					break;
				default:
					log_msg(vpn, LOG_WARNING, "unhandled event type: %d",
						event.filter);
				}
			}
		}
	}

	return ok;
}
