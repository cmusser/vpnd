#ifndef _VPND_NET_H_
#define _VPND_NET_H_

#include <sys/socket.h>

#include <ifaddrs.h>
#include <netdb.h>

#include "vpnd.h"

char           *format_sockaddr(struct sockaddr *sa, char *str, size_t str_sz);
bool		get_sockaddr(struct vpn_state *vpn, struct addrinfo **addrinfo_p, char *host, char *port_str, bool passive);
sa_family_t	inet_pton_any(struct vpn_state *vpn, const char *src, void *dst);
bool		manage_ext_sock_connection(struct vpn_state *vpn, struct sockaddr *remote_addr, socklen_t remote_addr_len);

#endif				/* !_VPND_NET_H_ */
