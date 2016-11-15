#ifndef _VPND_NET_H_
#define _VPND_NET_H_

#include <sys/socket.h>

#include <ifaddrs.h>
#if defined(__NetBSD__) || defined(__OpenBSD__)
#include <net/if_ether.h>
#else
#include <net/ethernet.h>
#endif
#include <netdb.h>

#include "vpnd.h"

char           *format_ethaddr(struct ether_addr *addr, char *str);
char           *format_sockaddr(struct sockaddr *sa, char *str, size_t str_sz);
bool		get_sockaddr(struct vpn_state *vpn, struct addrinfo **addrinfo_p, char *host, char *port_str, bool passive);
void		addr2net_with_netmask(sa_family_t af, void *host_addr, unsigned char *netmask);
void		addr2net_with_prefix(sa_family_t af, void *host_addr, uint8_t prefix_len);
sa_family_t	inet_pton_any(struct vpn_state *vpn, const char *src, void *dst);
bool		addr_in_intf_network(struct vpn_state *vpn, sa_family_t af, unsigned char *host_addr, struct ifaddrs *intf_addrs);
bool		intf_mac_for_host_net(struct vpn_state *vpn, sa_family_t af, unsigned char *host_addr, struct ether_addr *ether_addr);
void		manage_resolver(struct vpn_state *vpn);
void		manage_proxy_arp_for_host(struct vpn_state *vpn);
void		manage_host_ptp_addrs(struct vpn_state *vpn);
void		manage_host_gw_ptp_addrs(struct vpn_state *vpn);
void		manage_route_to_host_gw_net(struct vpn_state *vpn);
void		manage_net_gw_tun_intf(struct vpn_state *vpn);
void		manage_net_gw_remote_route(struct vpn_state *vpn);
void		manage_forwarding(struct vpn_state *vpn);
void		manage_network_config(struct vpn_state *vpn);
bool		manage_ext_sock_connection(struct vpn_state *vpn, struct sockaddr *remote_addr, socklen_t remote_addr_len);

#endif				/* !_VPND_NET_H_ */
