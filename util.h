#ifndef _VPND_NET_H_
#define _VPND_NET_H_

#include <sys/socket.h>

#include <ifaddrs.h>
#include <netdb.h>

#include "vpnd.h"

char           *format_sockaddr(struct sockaddr *sa, char *str, size_t str_sz);
bool		get_sockaddr(struct vpn_state *vpn, struct addrinfo **addrinfo_p, char *host, char *port_str, bool passive);
sa_family_t	inet_pton_any(struct vpn_state *vpn, const char *src, void *dst);
bool		validate_route_dst(struct vpn_state *vpn, sa_family_t family, void *addr, uint8_t prefix_len, char *route_dst_str, size_t route_dst_str_len);
bool		manage_ext_sock_connection(struct vpn_state *vpn, struct sockaddr *remote_addr, socklen_t remote_addr_len);
void		spawn_subprocess(struct vpn_state *vpn, char *cmd);
#if defined(__NetBSD__) || defined(__MacOSX__) || defined(__linux__)
long long	strtonum(const char *nptr, long long minval, long long maxval, const char **errstr);
#endif

#ifdef __linux__
size_t		strlcpy(char *dst, const char *src, size_t siz);
#endif

#endif				/* !_VPND_NET_H_ */
