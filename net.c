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

void
addr2net_with_netmask(sa_family_t af, void *host_addr, unsigned char *netmask)
{
	char           *addr_bytes;
	uint8_t		i;

	addr_bytes = (char *)host_addr;
	for (i = 0; i < ((af == AF_INET)
			 ? sizeof(struct in_addr)
			 : sizeof(struct in6_addr)); i++)
		addr_bytes[i] &= netmask[i];
}

void
addr2net_with_prefix(sa_family_t af, void *host_addr, uint8_t prefix_len)
{
	int		transition_idx, bits_in_transition;
	unsigned char	netmask[sizeof(struct in6_addr)] = {'\0'};

	transition_idx = prefix_len / 8;
	bits_in_transition = prefix_len % 8;
	memset(netmask, 0xff, transition_idx);
	netmask[transition_idx] = ~((1 << (8 - bits_in_transition)) - 1);
	addr2net_with_netmask(af, host_addr, netmask);
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

bool
addr_in_intf_network(struct vpn_state *vpn, sa_family_t af, unsigned char *host_addr, struct ifaddrs *intf_addrs)
{
	bool		in_network = true;
	uint8_t		i     , addr_len;
	unsigned char  *intf_addr, *intf_mask;

	switch (af) {
	case AF_INET:
		addr_len = sizeof(struct in_addr);
		intf_addr = (unsigned char *)&((struct sockaddr_in *)intf_addrs->ifa_addr)->sin_addr;
		intf_mask = (unsigned char *)&((struct sockaddr_in *)intf_addrs->ifa_netmask)->sin_addr;
		break;
	case AF_INET6:
		addr_len = sizeof(struct in6_addr);
		intf_addr = (unsigned char *)&((struct sockaddr_in6 *)intf_addrs->ifa_addr)->sin6_addr;
		intf_mask = (unsigned char *)&((struct sockaddr_in6 *)intf_addrs->ifa_netmask)->sin6_addr;
		break;
	default:
		printf("unsupported address family: %u\n", af);
		return false;
	}

	for (i = 0; i < addr_len; i++) {
		if (intf_mask[i] == 0xff) {
			if (host_addr[i] != intf_addr[i])
				in_network = false;
		} else {
			if ((host_addr[i] & intf_mask[i]) != (intf_addr[i] & intf_mask[i]))
				in_network = false;
			break;
		}
	}
	return in_network;
}

bool
intf_mac_for_host_net(struct vpn_state *vpn, sa_family_t af, unsigned char *host_addr, struct ether_addr *ether_addr)
{
	/*
	 * This replicates the function of the arp(8) command's "auto"
	 * keyword. It exists because "auto" is not universally supported,
	 * and is not provided by ndp(8), the equivalent command for
	 * configuring the IPv6 neighbor table.
	 */
	bool		ok = false;
	struct ifaddrs *ifa, *cur;
	char		addr_str  [INET6_ADDRSTRLEN] = {'\0'};
	char		if_name_str[IF_NAMESIZE] = {'\0'};

	if (getifaddrs(&ifa) != 0) {
		log_msg(vpn, LOG_ERR, "getifaddrs: %s", strerror(errno));
	} else {
		/*
		 * Scan the address list for the first "suitable" address
		 * (up, not point-to-point or loopback, has ARP) and get the
		 * associated interface name.
		 */
		for (cur = ifa; cur != NULL; cur = cur->ifa_next) {
			if ((cur->ifa_flags &
			     (IFF_UP | IFF_BROADCAST | IFF_POINTOPOINT | IFF_LOOPBACK | IFF_NOARP))
			    == (IFF_UP | IFF_BROADCAST)) {
				if (cur->ifa_addr->sa_family == af) {
					if (addr_in_intf_network(vpn, af, host_addr, cur)) {
						strlcpy(if_name_str, cur->ifa_name, sizeof(if_name_str));
						break;
					}
				}
			}
		}

		if (strlen(if_name_str) == 0) {
			log_msg(vpn, LOG_ERR, "no network for %s found\n", inet_ntop(af, host_addr, addr_str,
							 sizeof(addr_str)));
		} else {
			/*
			 * Scan the address list again, looking for a a link
			 * address for the candidate interface name and copy
			 * its link-layer address to the caller.
			 */
			for (cur = ifa; cur != NULL; cur = cur->ifa_next) {
				if (cur->ifa_addr->sa_family == AF_LINK &&
				  strcmp(cur->ifa_name, if_name_str) == 0) {
					memcpy(ether_addr, LLADDR((struct sockaddr_dl *)cur->ifa_addr),
					       sizeof(struct ether_addr));
					ok = true;
				}
			}
			if (!ok)
				log_msg(vpn, LOG_ERR, "couldn't find a link-layer address for %s", if_name_str);
		}
	}
	freeifaddrs(ifa);

	return ok;
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
manage_proxy_arp_for_host(struct vpn_state *vpn)
{
	bool		ok = true;
	char		host_addr_str[INET6_ADDRSTRLEN];
	struct ether_addr ether_addr;
	char		lladdr_str[ETHER_ADDRSTRLEN] = {'\0'};
	char		cmd       [256] = {'\0'};

	if (inet_ntop(vpn->tx_peer_info.host_addr_family, &vpn->tx_peer_info.host_addr,
		      host_addr_str, sizeof(host_addr_str)) == NULL) {
		ok = false;
		log_msg(vpn, LOG_WARNING, "%s: client host address (for proxy ARP) "
			"unconfigured or invalid", VPN_ROLE_STR(vpn->role));
	}
	if (ok) {
		switch (vpn->state) {
		case INIT:
			switch (vpn->tx_peer_info.host_addr_family) {
			case AF_INET:
				snprintf(cmd, sizeof(cmd), "arp -d %s", host_addr_str);
				break;
			case AF_INET6:
				snprintf(cmd, sizeof(cmd), "ndp -d %s", host_addr_str);
			default:
				ok = false;
				log_msg(vpn, LOG_ERR, "unknown address type (%u) to remove ARP/NDP",
					vpn->tx_peer_info.host_addr_family);
			}
			break;
		case ACTIVE_MASTER:
		case ACTIVE_SLAVE:
			if (intf_mac_for_host_net(vpn, vpn->tx_peer_info.host_addr_family,
				vpn->tx_peer_info.host_addr, &ether_addr)) {
				format_ethaddr(&ether_addr, lladdr_str);
				switch (vpn->tx_peer_info.host_addr_family) {
				case AF_INET:
					snprintf(cmd, sizeof(cmd), "arp -s %s %s pub",
						 host_addr_str, lladdr_str);
					break;
				case AF_INET6:
					snprintf(cmd, sizeof(cmd), "ndp -s %s %s proxy",
						 host_addr_str, lladdr_str);
				default:
					ok = false;
					log_msg(vpn, LOG_ERR, "unknown address type (%u) to add ARP/NDP",
					vpn->tx_peer_info.host_addr_family);
				}
			}
			break;
		default:
			ok = false;
			log_msg(vpn, LOG_ERR, "cannot manage ARP/NDP in %s state",
				VPN_STATE_STR(vpn->state));
		}
	}
	if (ok) {
		log_msg(vpn, LOG_NOTICE, "%s: %s", VPN_ROLE_STR(vpn->role), cmd);
		spawn_subprocess(vpn, cmd);
	}
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
			snprintf(cmd, sizeof(cmd), "ifconfig %s %s 10.0.0.1",
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
			snprintf(cmd, sizeof(cmd), "ifconfig %s 10.0.0.1 %s",
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
manage_route_to_host_gw_net(struct vpn_state *vpn)
{
	unsigned char	net_addr[sizeof(struct in6_addr)];
	char		net_addr_str[INET6_ADDRSTRLEN];
	char		cmd       [256] = {'\0'};
	char           *action_str = "\0";

	memcpy(net_addr, &vpn->rx_peer_info.host_addr,
	       (vpn->rx_peer_info.host_addr_family == AF_INET)
	       ? sizeof(struct in_addr) : sizeof(struct in6_addr));
	addr2net_with_prefix(vpn->rx_peer_info.host_addr_family, net_addr,
			     vpn->rx_peer_info.host_prefix_len);

	if (inet_ntop(vpn->rx_peer_info.host_addr_family, net_addr, net_addr_str,
		      sizeof(net_addr_str)) == NULL) {
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
			snprintf(cmd, sizeof(cmd), "route %s %s/%u -interface %s",
				 action_str, net_addr_str, vpn->rx_peer_info.host_prefix_len,
				 vpn->tun_name);
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
		manage_route_to_host_gw_net(vpn);
		if (vpn->rx_peer_info.resolv_addr_family == AF_INET ||
		    vpn->rx_peer_info.resolv_addr_family == AF_INET6)
			manage_resolver(vpn);
		break;
	case HOST_GW:
		manage_forwarding(vpn);
		manage_host_gw_ptp_addrs(vpn);
		manage_proxy_arp_for_host(vpn);
		break;
	case NET_GW:
		manage_forwarding(vpn);
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
