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

#include "diag.h"
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
	int		gai_error;

	ok = true;
	hints.ai_family = PF_INET;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG | AI_NUMERICSERV;
	if (passive)
		hints.ai_flags |= AI_PASSIVE;

	if ((gai_error = getaddrinfo(host, port_str, &hints, addrinfo_p))) {
		ok = false;
		log_msg(vpn, LOG_ERR, "invalid socket address info: \"%s:%s\" (%s)",
			host, port_str, gai_strerror(gai_error));
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
