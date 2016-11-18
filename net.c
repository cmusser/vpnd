#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "net.h"
#include "os.h"

#ifndef ETHER_ADDRSTRLEN
#define ETHER_ADDRSTRLEN 17
#endif

char           *
format_ethaddr(struct ether_addr *addr, char *str)
{
#if defined(__DragonFly__) || defined(__FreeBSD__)
	return ether_ntoa_r(addr, str);
#else
	strlcpy(str, ether_ntoa(addr), ETHER_ADDRSTRLEN);
	return str;
#endif
}

char           *
format_sockaddr(struct sockaddr *sa, char *str, size_t str_sz)
{
	char		addr_str  [INET6_ADDRSTRLEN];

	switch (sa->sa_family) {
	case AF_UNSPEC:
		strlcpy(str, "NULL address", str_sz);
		break;
	case AF_INET:
		inet_ntop(sa->sa_family, &((struct sockaddr_in *)sa)->sin_addr,
			  addr_str, sizeof(addr_str));
		snprintf(str, str_sz, "%s:%u", addr_str,
			 ntohs(((struct sockaddr_in *)sa)->sin_port));
		break;
	case AF_INET6:
		inet_ntop(sa->sa_family, &((struct sockaddr_in6 *)sa)->sin6_addr,
			  addr_str, sizeof(addr_str));
		snprintf(str, str_sz, "%s:%u", addr_str,
			 ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
		break;
	default:
		snprintf(str, str_sz, "invalid address (family: %d)", sa->sa_family);
	}

	return str;
}

bool
get_sockaddr(struct vpn_state *vpn, struct addrinfo **addrinfo_p, char *host, char *port_str, bool passive)
{
	bool		ok;
	struct addrinfo	hints = {'\0'};

	ok = true;
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	if (passive)
		hints.ai_flags |= AI_PASSIVE;

	if (getaddrinfo(host, port_str, &hints, addrinfo_p)) {
		ok = false;
		log_msg(vpn, LOG_ERR, "invalid socket address info: \"%s:%s\"",
			host, port_str);
	}
	return ok;
}

sa_family_t
inet_pton_any(struct vpn_state *vpn, const char *src, void *dst)
{
	sa_family_t	af , rv;

	af = AF_INET;
	rv = inet_pton(af, src, dst);
	if (rv == 0)
		af = AF_INET6;
	rv = inet_pton(af, src, dst);

	switch (rv) {
	case 0:
		af = AF_UNSPEC;
		log_msg(vpn, LOG_ERR, "unparseable address: %s\n", src);
		break;
	case 1:
		break;

	default:
		af = AF_UNSPEC;
		log_msg(vpn, LOG_ERR, "error: %s\n", strerror(errno));
	}

	return af;
}

void
manage_resolver(struct vpn_state *vpn)
{
	bool		ok = true;
	char		resolv_data_filename[512] = {'\0'};
	int		resolv_data_fd;
	char		resolv_data_str[256];
	char		resolv_addr_str[INET6_ADDRSTRLEN];
	char		resolvconf_cmd[512];
	FILE           *cmd_fd;
	char		cmd_out   [256];
	char           *newline;


	switch (vpn->state) {
	case INIT:
		snprintf(resolvconf_cmd, sizeof(resolvconf_cmd), "%s -d %s 2>&1",
			 vpn->resolvconf_path, vpn->tun_name);
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		snprintf(resolv_data_filename, sizeof(resolv_data_filename),
			 "/tmp/vpnd_resolv_%s.XXXXXX", vpn->tun_name);
		resolv_data_fd = mkstemp(resolv_data_filename);
		if (resolv_data_fd == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "creating of resolvconf temp data failed -- %s",
				strerror(errno));
		}
		if (ok) {
			snprintf(resolv_data_str, sizeof(resolv_data_str), "nameserver %s\n",
			     inet_ntop(vpn->rx_peer_info.resolv_addr_family,
			    &vpn->rx_peer_info.resolv_addr, resolv_addr_str,
				       sizeof(resolv_addr_str)));
			write(resolv_data_fd, resolv_data_str, strlen(resolv_data_str));

			if (strlen(vpn->rx_peer_info.resolv_domain) > 0) {
				snprintf(resolv_data_str, sizeof(resolv_data_str), "domain %s\n",
					 vpn->rx_peer_info.resolv_domain);
				write(resolv_data_fd, resolv_data_str, strlen(resolv_data_str));
			}
			close(resolv_data_fd);
			snprintf(resolvconf_cmd, sizeof(resolvconf_cmd), "%s -a %s < %s 2>&1",
				 vpn->resolvconf_path, vpn->tun_name, resolv_data_filename);
		}
		break;
	default:
		ok = false;
		log_msg(vpn, LOG_ERR, "cannot manage resolver in %s state",
			VPN_STATE_STR(vpn->state));
	}

	if (ok) {

		log_msg(vpn, LOG_NOTICE, "%s: %s", VPN_STATE_STR(vpn->state), resolvconf_cmd);
		if ((cmd_fd = popen(resolvconf_cmd, "r")) == NULL) {
			log_msg(vpn, LOG_ERR, "spawn of \"%s\" failed: %s", resolvconf_cmd,
				strerror(errno));
		} else {
			while (fgets(cmd_out, sizeof(cmd_out), cmd_fd) != NULL) {
				newline = strrchr(cmd_out, '\n');
				if (newline)
					*newline = '\0';
				log_msg(vpn, LOG_NOTICE, "==> %s", cmd_out);
			}

			if (ferror(cmd_fd))
				log_msg(vpn, LOG_ERR, "reading subprocess output: %s", strerror(errno));

			pclose(cmd_fd);
		}
	}
	unlink(resolv_data_filename);
}

void
manage_host_ptp_addrs(struct vpn_state *vpn)
{
	char		host_addr_str[INET6_ADDRSTRLEN];
	char		cmd       [256] = {'\0'};

	if (inet_ntop(vpn->rx_peer_info.host_addr_family, &vpn->rx_peer_info.host_addr,
		      host_addr_str, sizeof(host_addr_str)) == NULL) {
		log_msg(vpn, LOG_WARNING, "%s: host address on remote network unconfigured "
			"or invalid", VPN_ROLE_STR(vpn->role));
	} else {
		switch (vpn->state) {
		case INIT:
			/*
			 * I think it's OK to just leave the HOST tunnel
			 * interface configured if the session ends. This
			 * placeholder is here in case that turns out to not
			 * be be case.
			 */
			break;
		case ACTIVE_MASTER:
		case ACTIVE_SLAVE:
			snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s %s 10.0.0.1",
				 vpn->tun_name, host_addr_str);
			log_msg(vpn, LOG_NOTICE, "%s: %s",
				VPN_ROLE_STR(vpn->role), cmd);
			spawn_subprocess(vpn, cmd);
			break;
		default:
			log_msg(vpn, LOG_ERR, "cannot manage %s P-T-P addrs in %s state",
			VPN_ROLE_STR(vpn->role), VPN_STATE_STR(vpn->state));
		}
	}
}

void
manage_host_gw_ptp_addrs(struct vpn_state *vpn)
{
	char		host_addr_str[INET6_ADDRSTRLEN];
	char		cmd       [256] = {'\0'};

	if (inet_ntop(vpn->tx_peer_info.host_addr_family, &vpn->tx_peer_info.host_addr,
		      host_addr_str, sizeof(host_addr_str)) == NULL) {
		log_msg(vpn, LOG_WARNING, "%s: client host address unconfigured or invalid",
			VPN_ROLE_STR(vpn->role));
	} else {
		switch (vpn->state) {
		case INIT:
			/*
			 * I think it's OK to just leave the HOST-GW tunnel
			 * interface configured if the session ends.
			 * Placeholder is here in case that turns out to not
			 * be be case.
			 */
			break;
		case ACTIVE_MASTER:
		case ACTIVE_SLAVE:
			snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s 10.0.0.1 %s",
				 vpn->tun_name, host_addr_str);
			log_msg(vpn, LOG_NOTICE, "%s: %s", VPN_ROLE_STR(vpn->role), cmd);
			spawn_subprocess(vpn, cmd);
			break;
		default:
			log_msg(vpn, LOG_ERR, "cannot manage %s P-T-P addrs in %s state",
			VPN_ROLE_STR(vpn->role), VPN_STATE_STR(vpn->state));
		}
	}
}

void
manage_host_route_to_remote_net(struct vpn_state *vpn)
{
	char		net_addr_str[INET6_ADDRSTRLEN];
	char		cmd       [256] = {'\0'};
	char           *action_str = "\0";

	if (inet_ntop(vpn->rx_peer_info.remote_net_addr_family, vpn->rx_peer_info.remote_net,
		      net_addr_str, sizeof(net_addr_str)) == NULL) {
		log_msg(vpn, LOG_WARNING, "%s: remote network address unconfigured or invalid",
			VPN_ROLE_STR(vpn->role));
	} else {
		switch (vpn->state) {
		case INIT:
			action_str = "delete";
			break;
		case ACTIVE_MASTER:
		case ACTIVE_SLAVE:
			action_str = "add";
			break;
		default:
			log_msg(vpn, LOG_ERR, "cannot manage %s HOST route to HOST-GW "
			     "network in %s state", VPN_ROLE_STR(vpn->role),
				VPN_STATE_STR(vpn->state));
		}
		if (strlen(action_str) > 0) {
			snprintf(cmd, sizeof(cmd), "/sbin/route %s %s/%u -interface %s",
				 action_str, net_addr_str, vpn->rx_peer_info.host_prefix_len,
				 vpn->tun_name);
			log_msg(vpn, LOG_NOTICE, "%s: %s", VPN_ROLE_STR(vpn->role), cmd);
			spawn_subprocess(vpn, cmd);
		}
	}
}

void
manage_net_gw_tun_intf(struct vpn_state *vpn)
{
	char           *action_str = "\0";
	char		cmd       [256] = {'\0'};

#ifdef __NetBSD__
	const char	*ifconfig_addr = "10.0.0.1 ";
#else
	const char	*ifconfig_addr = "";
#endif
	switch (vpn->state) {
	case INIT:
		action_str = "down";
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		action_str = "up";
		break;
	default:
		log_msg(vpn, LOG_ERR, "cannot manage %s tunnel interface "
			"in %s state", VPN_ROLE_STR(vpn->role),
			VPN_STATE_STR(vpn->state));
	}
	if (strlen(action_str) > 0) {
		snprintf(cmd, sizeof(cmd), "/sbin/ifconfig %s %s%s", vpn->tun_name,
		    ifconfig_addr, action_str);
		log_msg(vpn, LOG_NOTICE, "%s: %s", VPN_ROLE_STR(vpn->role), cmd);
		spawn_subprocess(vpn, cmd);
	}
}

void
manage_net_gw_remote_route(struct vpn_state *vpn)
{
	char		remote_network_str[INET6_ADDRSTRLEN];
	char           *action_str = "\0";
	char		cmd       [256] = {'\0'};
#ifdef __NetBSD__
	const char	*route_param = "-link ";
#else
	const char	*route_param = "";
#endif

	if (inet_ntop(vpn->remote_network_family, vpn->remote_network, remote_network_str,
		      sizeof(remote_network_str)) == NULL) {
		log_msg(vpn, LOG_WARNING, "%s: remote network address unconfigured or invalid",
			VPN_ROLE_STR(vpn->role));
	} else {
		switch (vpn->state) {
		case INIT:
			action_str = "delete";
			break;
		case ACTIVE_MASTER:
		case ACTIVE_SLAVE:
			action_str = "add";
			break;
		default:
			log_msg(vpn, LOG_ERR, "cannot manage %s remote network route "
				"in %s state", VPN_ROLE_STR(vpn->role),
				VPN_STATE_STR(vpn->state));
		}
		if (strlen(action_str) > 0) {
			snprintf(cmd, sizeof(cmd), "/sbin/route %s %s/%u %s-interface %s",
				 action_str, remote_network_str, vpn->remote_network_prefix_len,
			    route_param, vpn->tun_name);
			log_msg(vpn, LOG_NOTICE, "%s: %s", VPN_ROLE_STR(vpn->role), cmd);
			spawn_subprocess(vpn, cmd);
		}
	}
}

void
manage_forwarding(struct vpn_state *vpn)
{
	switch (vpn->state) {
	case INIT:
		if (!vpn->already_ip_forwarding)
			set_sysctl_bool(vpn, SYS_IP_FORWARDING, false);
		if (!vpn->already_ip6_forwarding)
			set_sysctl_bool(vpn, SYS_IP6_FORWARDING, false);
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		set_sysctl_bool(vpn, SYS_IP_FORWARDING, true);
		set_sysctl_bool(vpn, SYS_IP6_FORWARDING, true);
		break;
	default:
		log_msg(vpn, LOG_ERR, "%s: cannot manage forwarding in %s state",
			VPN_ROLE_STR(vpn->role), VPN_STATE_STR(vpn->state));
	}
}

void
manage_network_config(struct vpn_state *vpn)
{
	switch (vpn->role) {
	case HOST:
		manage_host_ptp_addrs(vpn);
		manage_host_route_to_remote_net(vpn);
		if (vpn->rx_peer_info.resolv_addr_family == AF_INET ||
		    vpn->rx_peer_info.resolv_addr_family == AF_INET6)
			manage_resolver(vpn);
		break;
	case HOST_GW:
		manage_forwarding(vpn);
		manage_host_gw_ptp_addrs(vpn);
		break;
	case NET_GW:
		manage_forwarding(vpn);
		manage_net_gw_tun_intf(vpn);
		manage_net_gw_remote_route(vpn);

	default:
		break;
	}
}

bool
manage_ext_sock_connection(struct vpn_state *vpn, struct sockaddr *remote_addr, socklen_t remote_addr_len)
{
	bool		ok = true;
	int		rv;
	char		remote_addr_str[INET6_ADDRSTRLEN] = "<ADDR>";

	format_sockaddr(remote_addr, remote_addr_str, sizeof(remote_addr_str));

	rv = connect(vpn->ext_sock, remote_addr, remote_addr_len);
	if (rv == 0 || (rv == -1 &&
	     ((struct sockaddr_in *)remote_addr)->sin_family == AF_UNSPEC &&
			errno == EAFNOSUPPORT)) {
		log_msg(vpn, LOG_NOTICE, "%s: setting peer to %s",
			VPN_ROLE_STR(vpn->role), remote_addr_str);
	} else {
		ok = false;
		log_msg(vpn, LOG_ERR, "couldn't connect to %s: %s",
			remote_addr_str, strerror(errno));
	}

	return ok;
}
