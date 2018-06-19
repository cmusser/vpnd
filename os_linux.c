#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/sysctl.h>
#include <sys/timerfd.h>

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

bool
open_tun_sock(struct vpn_state *vpn, char *tun_name_str)
{
	bool		ok = true;
	struct ifreq	ifr;

	vpn->ctrl_sock = open("/dev/net/tun", O_RDWR);

	if (vpn->ctrl_sock < 0) {
		ok = false;
		log_msg(vpn, LOG_ERR, "couldn't open tunnel: %s", strerror(errno));
	}
	if (ok) {
		bzero(&ifr, sizeof(ifr));
		ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
		strlcpy(ifr.ifr_name, tun_name_str, IFNAMSIZ);
		if (ioctl(vpn->ctrl_sock, TUNSETIFF, (void *)&ifr) < 0) {
			ok = false;
			close(vpn->ctrl_sock);
			log_msg(vpn, LOG_ERR, "couldn't configure tunnel: %s",
				strerror(errno));
		}
	}
	if (ok) {
		strlcpy(vpn->tun_name, ifr.ifr_name, sizeof(vpn->tun_name));
		set_tun_state(vpn, INTF_UP);
	}
	return ok;
}

bool
init_event_processing(struct vpn_state *vpn, bool stdin_events)
{
	bool		ok = true;
	struct epoll_event ev;
	sigset_t	sigmask;
	int		i;
	int		stdin_fd;

	vpn->event_fd = epoll_create1(0);
	if (vpn->event_fd == -1) {
		ok = false;
		log_msg(vpn, LOG_ERR, "Can't create event socket: %s",
			strerror(errno));
	}
	if (ok) {
		sigemptyset(&sigmask);
		sigaddset(&sigmask, SIGUSR1);
		sigaddset(&sigmask, SIGINT);
		sigaddset(&sigmask, SIGTERM);

		if (sigprocmask(SIG_BLOCK, &sigmask, NULL) == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "Can't block default signal handling: %s",
				strerror(errno));
		}
	}
	if (ok) {
		vpn->signal_fd = signalfd(-1, &sigmask, 0);
		if (vpn->signal_fd == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "Can't create signal file descriptor: %s",
				strerror(errno));
		}
	}
	if (ok) {
		ev.events = EPOLLIN;
		ev.data.fd = vpn->signal_fd;
		if (epoll_ctl(vpn->event_fd, EPOLL_CTL_ADD, vpn->signal_fd, &ev) == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "Can't add add signals file descriptor "
				"to event set: %s", strerror(errno));
		}
	}
	if (ok) {
		int            *timers[5] = {&vpn->retransmit_peer_init_timer_fd,
			&vpn->retransmit_key_switch_start_timer_fd,
			&vpn->retransmit_key_switch_ack_timer_fd,
			&vpn->retransmit_key_ready_timer_fd,
		&vpn->active_heartbeat_timer_fd};

		for (i = 0; ok && i < 5; i++) {
			*timers[i] = timerfd_create(CLOCK_MONOTONIC, 0);
			bzero(&ev, sizeof(ev));
			ev.events = EPOLLIN;
			ev.data.fd = *timers[i];
			if (epoll_ctl(vpn->event_fd, EPOLL_CTL_ADD, *timers[i], &ev) == -1) {
				ok = false;
				log_msg(vpn, LOG_ERR, "Can't add timer file descriptor "
					"to event set: %s", strerror(errno));
			}
		}
	}
	if (ok) {
		bzero(&ev, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = vpn->ctrl_sock;
		if (epoll_ctl(vpn->event_fd, EPOLL_CTL_ADD, vpn->ctrl_sock, &ev) == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "Can't add control socket file descriptor "
				"to event set: %s", strerror(errno));
		}
	}
	if (ok) {
		bzero(&ev, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = vpn->ext_sock;
		if (epoll_ctl(vpn->event_fd, EPOLL_CTL_ADD, vpn->ext_sock, &ev) == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "Can't add external socket file descriptor "
				"to event set: %s", strerror(errno));
		}
	}
	if (ok && stdin_events) {
		stdin_fd = fileno(stdin);
		bzero(&ev, sizeof(ev));
		ev.events = EPOLLIN;
		ev.data.fd = stdin_fd;
		if (epoll_ctl(vpn->event_fd, EPOLL_CTL_ADD, stdin_fd, &ev) == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "Can't add stdin file descriptor "
				"to event set: %s", strerror(errno));
		}
	}
	return ok;
}

bool
get_forwarding(struct vpn_state *vpn, sa_family_t addr_family)
{
	bool		flag_bool = false;
	char           *name;
	FILE           *forwarding;
	char		forwarding_str;

	switch (addr_family) {
	case AF_INET:
		name = "/proc/sys/net/ipv4/conf/all/forwarding";
		break;
	case AF_INET6:
		name = "/proc/sys/net/ipv6/conf/all/forwarding";
		break;
	default:
		name = "/proc/sys/net/ipv4/conf/all/forwarding";
		log_msg(vpn, LOG_WARNING, "unknown forwarding address family %d, "
			"defaulting to IPv4", addr_family);
	}

	forwarding = fopen(name, "r");
	if (forwarding == NULL) {
		log_msg(vpn, LOG_ERR, "failed to open forwarding data at %s: %s\n",
			name, strerror(errno));
	} else {
		if (fread(&forwarding_str, sizeof(forwarding_str), 1, forwarding) < 1)
			log_msg(vpn, LOG_ERR, "Can't read forwarding data from %s: %s\n",
				name, strerror(errno));
		else
			flag_bool = (strncmp(&forwarding_str, "0",
			       sizeof(forwarding_str)) == 0) ? false : true;
	}
	fclose(forwarding);

	return flag_bool;
}

void
set_forwarding(struct vpn_state *vpn, sa_family_t addr_family, bool value)
{
	char		flag;
	char           *name;
	FILE           *forwarding;

	switch (addr_family) {
	case AF_INET:
		name = "/proc/sys/net/ipv4/conf/all/forwarding";
		break;
	case AF_INET6:
		name = "/proc/sys/net/ipv6/conf/all/forwarding";
		break;
	default:
		log_msg(vpn, LOG_ERR, "unknown forwarding address family %d, "
			"ignoring request", addr_family);
		return;
	}

	flag = (value == true) ? '1' : '0';

	forwarding = fopen(name, "w");
	if (forwarding == NULL) {
		log_msg(vpn, LOG_ERR, "failed to open forwarding data at %s: %s\n",
			name, strerror(errno));

	} else {
		if (fwrite(&flag, sizeof(flag), 1, forwarding) < 1)
			log_msg(vpn, LOG_ERR, "Can't write forwarding data to %s: %s\n",
				name, strerror(errno));
		else
			log_msg(vpn, LOG_NOTICE, "sysctl %s=%c", name, flag);
		fclose(forwarding);
	}
}

void
set_tun_addrs(struct vpn_state *vpn, char *host_addr_str, tun_addr_mode mode)
{
	char		cmd       [256] = {'\0'};

	switch (mode) {
	case HOST_LOCAL:
		snprintf(cmd, sizeof(cmd), "/usr/sbin/ip addr add %s dev %s",
			 host_addr_str, vpn->tun_name);
		spawn_subprocess(vpn, cmd);
		break;
	case HOST_REMOTE:
		snprintf(cmd, sizeof(cmd), "/usr/sbin/ip addr add 127.0.0.1 dev %s",
			 vpn->tun_name);
		spawn_subprocess(vpn, cmd);

		snprintf(cmd, sizeof(cmd), "/usr/sbin/ip route add %s dev %s",
			 host_addr_str, vpn->tun_name);
		spawn_subprocess(vpn, cmd);
		break;
	default:
		log_msg(vpn, LOG_WARNING, "%s: %s tunnel addr mode (%d)",
		    VPN_ROLE_STR(vpn->role), TUN_ADDR_MODE_STR(mode), mode);
		return;
	}

	log_msg(vpn, LOG_NOTICE, "%s configured tunnel with host on %s end: %s",
		VPN_ROLE_STR(vpn->role), TUN_ADDR_MODE_STR(mode), cmd);
}

void
set_tun_state(struct vpn_state *vpn, intf_action action)
{
	char		cmd       [256] = {'\0'};

	switch (action) {
	case INTF_UP:
		snprintf(cmd, sizeof(cmd), "/usr/bin/ip link set %s  up",
			 vpn->tun_name);
		break;
	case INTF_DOWN:
		snprintf(cmd, sizeof(cmd), "/usr/bin/ip link set %s down",
			 vpn->tun_name);
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
	case ROUTE_ADD:
		snprintf(cmd, sizeof(cmd), "/usr/bin/ip route add %s/%u dev %s",
			 net_addr_str, vpn->rx_peer_info.host_prefix_len, vpn->tun_name);
		break;
	case ROUTE_DELETE:
		snprintf(cmd, sizeof(cmd), "/usr/bin/ip route delete %s/%u dev %s",
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
configure_route_on_net_gw(struct vpn_state *vpn, route_action action)
{
	char		route_dst_str[INET6_ADDRSTRLEN + 4] = {'\0'};
	char		cmd       [256] = {'\0'};

	switch (action) {
	case ROUTE_ADD:
	case ROUTE_DELETE:
		if (validate_route_dst(vpn, vpn->remote_network_family,
			&vpn->remote_network, vpn->remote_network_prefix_len,
				    route_dst_str, sizeof(route_dst_str))) {
			snprintf(cmd, sizeof(cmd), "/usr/bin/ip route %s %s dev %s",
				 ROUTE_ACTION_STR(action), route_dst_str, vpn->tun_name);
			spawn_subprocess(vpn, cmd);
			log_msg(vpn, LOG_NOTICE, "%s route %s: %s",
				VPN_ROLE_STR(vpn->role), ROUTE_ACTION_STR(action), cmd);
		}
		break;
	default:
		log_msg(vpn, LOG_WARNING, "unknown route action (%d)", action);
	}
}

void
get_cur_monotonic(struct timespec *tp)
{
	clock_gettime(CLOCK_MONOTONIC, tp);
}

void
add_timer(struct vpn_state *vpn, timer_type ttype)
{
	struct itimerspec new_timeout;

	bzero(&new_timeout, sizeof(new_timeout));
	new_timeout.it_value = get_timeout_interval(vpn, ttype);

	switch (ttype) {
	case RETRANSMIT_PEER_INIT:
		timerfd_settime(vpn->retransmit_peer_init_timer_fd, 0, &new_timeout, NULL);
		break;
	case RETRANSMIT_KEY_SWITCH_START:
		timerfd_settime(vpn->retransmit_key_switch_start_timer_fd, 0, &new_timeout, NULL);
		break;
	case RETRANSMIT_KEY_SWITCH_ACK:
		timerfd_settime(vpn->retransmit_key_switch_ack_timer_fd, 0, &new_timeout, NULL);
		break;
	case RETRANSMIT_KEY_READY:
		timerfd_settime(vpn->retransmit_key_ready_timer_fd, 0, &new_timeout, NULL);
		break;
	case ACTIVE_HEARTBEAT:
		timerfd_settime(vpn->active_heartbeat_timer_fd, 0, &new_timeout, NULL);
		break;
	default:
		log_msg(vpn, LOG_ERR, "unknown timer time %d\n", ttype);
	}
}

bool
run(struct vpn_state *vpn)
{
	bool		ok = true;
	struct epoll_event events[1];
	int		nev       , i, fd;
	uint64_t	expire;
	ssize_t		siginfo_len;
	struct signalfd_siginfo siginfo;

	while (ok) {
		bzero(&events, sizeof(events));
		nev = epoll_wait(vpn->event_fd, events, 1, -1);
		if (nev == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "epoll_wait: %s", strerror(errno));
		}
		for (i = 0; i < nev; i++) {
			fd = events[i].data.fd;
			if (fd == vpn->ext_sock)
				ext_sock_input(vpn);
			else if (fd == vpn->ctrl_sock)
				ctrl_sock_input(vpn);
			else if (fd == vpn->stats_sock)
				stats_sock_input(vpn);
			else if (fd == STDIN_FILENO) {
				stdin_input(vpn);
			} else if (fd == vpn->retransmit_peer_init_timer_fd) {
				read(fd, &expire, sizeof(expire));
				process_timeout(vpn, RETRANSMIT_PEER_INIT);
			} else if (fd == vpn->retransmit_key_switch_start_timer_fd) {
				read(fd, &expire, sizeof(expire));
				process_timeout(vpn, RETRANSMIT_KEY_SWITCH_START);
			} else if (fd == vpn->retransmit_key_switch_ack_timer_fd) {
				read(fd, &expire, sizeof(expire));
				process_timeout(vpn, RETRANSMIT_KEY_SWITCH_ACK);
			} else if (fd == vpn->retransmit_key_ready_timer_fd) {
				read(fd, &expire, sizeof(expire));
				process_timeout(vpn, RETRANSMIT_KEY_READY);
			} else if (fd == vpn->active_heartbeat_timer_fd) {
				read(fd, &expire, sizeof(expire));
				process_timeout(vpn, ACTIVE_HEARTBEAT);
			} else if (fd == vpn->signal_fd) {
				siginfo_len = read(vpn->signal_fd, &siginfo, sizeof(siginfo));
				if (siginfo_len == sizeof(siginfo)) {
					switch (siginfo.ssi_signo) {
					case SIGUSR1:
						log_stats(vpn);
						break;
					case SIGINT:
					case SIGTERM:
						ok = false;
						log_msg(vpn, LOG_NOTICE, "shutting down (signal %u)",
							siginfo.ssi_signo);
						write_nonce(vpn, REMOTE);
						return_to_init_state(vpn);
						break;
					default:
						break;
					}
				} else {
					log_msg(vpn, LOG_WARNING, "can't read info for caught signal: %s",
						strerror(errno));
				}
			} else {
				log_msg(vpn, LOG_WARNING, "event on unhandled file descriptor %d\n", fd);
			}
		}
	}

	return ok;
}
