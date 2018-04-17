#ifdef __linux__
#include <endian.h>
#else
#include <sys/endian.h>
#endif
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include "diag.h"
#include "nonce.h"
#include "os.h"
#include "proto.h"
#include "setup.h"
#include "util.h"

#define DEFAULT_VPND_PORT "4706"

struct config_param {
	char           *desc;
	char           *name;
	size_t		name_sz;
	char           *value;
	size_t		value_sz;
	char           *default_value;
};

char           *get_value(char *line, size_t len);
bool		set_nonblocking(struct vpn_state *vpn, int fd, char *desc);

char           *
get_value(char *line, size_t len)
{
	char           *value, *end, *cur;

	end = line + len;

	value = line;
	while (*value != ':' && value < end)
		value++;

	value++;
	while (isspace(*value) && value < end)
		value++;

	cur = value;
	while (*cur != '\0') {
		if (*cur == '\n') {
			*cur = '\0';
			break;
		}
		cur++;
	}

	return value;
}

bool
set_nonblocking(struct vpn_state *vpn, int fd, char *desc) {
	bool	ok = true;
	int	fd_flags;

	if ((fd_flags = fcntl(fd, F_GETFL, 0)) == -1) {
		ok = false;
		log_msg(vpn, LOG_ERR, "can't get flags for %s: %s\n",
		    desc, strerror(errno));
	}

	if (ok) {
		if (fcntl(fd, F_SETFL, fd_flags | O_NONBLOCK) == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "setting nonblocking failed for %s: %s\n",
			    desc, strerror(errno));
		}
	}

	return ok;
}

bool
init(struct vpn_state *vpn, int vflag, bool fflag, char *prog_name, char *config_fname)
{
	bool		ok = true;
	FILE           *config_file;
	char		line      [256] = {'\0'};
	char		role      [32] = {'\0'};
	char		tunnel_device[32] = {'\0'};
	uint32_t	nonce_reset_incr_le;
	char		local_sk_hex[(crypto_box_SECRETKEYBYTES * 2) + 1] = {'\0'};
	char		local_port[6] = {'\0'};
	char		remote_pk_hex[(crypto_box_PUBLICKEYBYTES * 2) + 1] = {'\0'};
	char		remote_host[INET6_ADDRSTRLEN] = {'\0'};
	char		remote_port[6] = {'\0'};
	char		host_addr [INET6_ADDRSTRLEN + 4] = {'\0'};
	char		remote_network[INET6_ADDRSTRLEN + 4] = {'\0'};
	char		local_network[INET6_ADDRSTRLEN + 4] = {'\0'};
	char		resolv_addr[INET6_ADDRSTRLEN] = {'\0'};
	char		resolv_domain[32] = {'\0'};
	char		max_key_age_secs[16] = {'\0'};
	char		max_key_sent_packet_count[16] = {'\0'};
	char		max_read_per_event[16] = {'\0'};
	char		nonce_reset_incr[16] = {'\0'};
	const char     *num_err;
	struct config_param c[] = {
		{"role", "role:", sizeof("role:"),
		role, sizeof(role), "net-gw"},
		{"tunnel device", "device:", sizeof("device:"),
		tunnel_device, sizeof(tunnel_device), "tun0"},
		{"stats prefix", "stats_prefix:", sizeof("stats_prefix:"),
		vpn->stats_prefix, sizeof(vpn->stats_prefix), "<hostname>"},
		{"local secret key", "local_sk:", sizeof("local_sk:"),
		local_sk_hex, sizeof(local_sk_hex), NULL},
		{"local port", "local_port:", sizeof("local_port:"),
		local_port, sizeof(local_port), DEFAULT_VPND_PORT},
		{"remote public key", "remote_pk:", sizeof("remote_pk:"),
		remote_pk_hex, sizeof(remote_pk_hex), NULL},
		{"remote host", "remote_host:", sizeof("remote_host:"),
		remote_host, sizeof(remote_host), NULL},
		{"remote port", "remote_port:", sizeof("remote_port:"),
		remote_port, sizeof(remote_port), DEFAULT_VPND_PORT},
		{"host address", "host_addr:", sizeof("host_addr:"),
		host_addr, sizeof(host_addr), NULL},
		{"remote network", "remote_network:", sizeof("remote_network:"),
		remote_network, sizeof(remote_network), NULL},
		{"local network", "local_network:", sizeof("local_network:"),
		local_network, sizeof(local_network), NULL},
		{"resolver address", "resolv_addr:", sizeof("resolv_addr:"),
		resolv_addr, sizeof(resolv_addr), NULL},
		{"resolver domain", "resolv_domain:", sizeof("resolv_domain:"),
		resolv_domain, sizeof(resolv_domain), NULL},
		{"resolvconf path", "resolvconf_path:", sizeof("resolvconf_path:"),
		vpn->resolvconf_path, sizeof(vpn->resolvconf_path), "/sbin/resolvconf"},
		{"max key age (secs.)", "max_key_age:", sizeof("max_key_age:"),
		max_key_age_secs, sizeof(max_key_age_secs), "60"},
		{"max key packets", "max_key_packets:", sizeof("max_key_packets:"),
		max_key_sent_packet_count, sizeof(max_key_sent_packet_count), "100000"},
		{"max reads per event", "max_read_per_event:", sizeof("max_read_per_event:"),
		max_read_per_event, sizeof(max_read_per_event), "100"},
		{"nonce reset increment", "nonce_reset_incr:", sizeof("nonce_reset_incr:"),
		nonce_reset_incr, sizeof(nonce_reset_incr), "10000"},
		{"local nonce file", "local_nonce_file:", sizeof("local_nonce_file:"),
		vpn->local_nonce_filename, sizeof(vpn->local_nonce_filename), "/var/db/local_vpnd.nonce"},
		{"remote nonce file", "remote_nonce_file:", sizeof("remote_nonce_file:"),
		vpn->remote_nonce_filename, sizeof(vpn->remote_nonce_filename), "/var/db/remote_vpnd.nonce"},
	};

	size_t		bin_len;
	unsigned char	local_sk_bin[crypto_box_SECRETKEYBYTES];
	unsigned char	remote_pk_bin[crypto_box_PUBLICKEYBYTES];
	unsigned int	i , j;
	char           *prefix_start;
	long long	max_prefix_len;
	const char     *errstr;
	struct addrinfo *local_addrinfo = NULL;
	char		local_info[INET6_ADDRSTRLEN + 7];
	struct addrinfo *remote_addrinfo = NULL;
	struct sockaddr_un stats_addr;
	char           *stats_path = "/var/run/vpnd_stats.sock";

	bzero(vpn, sizeof(struct vpn_state));

	switch (vflag) {
	case 0:
		vpn->log_upto = LOG_NOTICE;
		break;
	case 1:
		vpn->log_upto = LOG_INFO;
		break;
	default:
		vpn->log_upto = LOG_DEBUG;
	}

	if (fflag) {
		vpn->foreground = true;
	} else {
		char           *ident;
		vpn->foreground = false;
		ident = strrchr(prog_name, '/');
		if (!ident)
			ident = prog_name;
		else
			ident++;
		openlog(ident, LOG_NDELAY | LOG_PID, LOG_DAEMON);
		if (vpn->log_upto >= 0)
			setlogmask(LOG_UPTO(vpn->log_upto));
	}

	vpn->already_ip_forwarding = get_forwarding(vpn, AF_INET);
	vpn->already_ip6_forwarding = get_forwarding(vpn, AF_INET6);

	config_file = fopen(config_fname, "r");
	if (config_file != NULL) {

		/* Read config file */
		while (fgets(line, sizeof(line), config_file)) {
			for (i = 0; i < COUNT_OF(c); i++) {
				if (strncasecmp(line, c[i].name, strlen(c[i].name)) == 0) {
					strlcpy(c[i].value, get_value(line, sizeof(line)),
						c[i].value_sz);
				}
			}
		}

		/*
		 * Ensure that all required parameters are present and, if
		 * possible, set defaults for parameters that have them.
		 * There is special treatment for:
		 *
		 * role: ensure the role is one of the legal values.
		 *
		 * remote_host: require in host and net gateway role
		 *
		 * host_addr: require in host gateway role.
		 *
		 * local_network: require in host gateway role.
		 *
		 * remote_network: require in net gateway role.
		 *
		 * stats_prefix: let the default be the hostname, which must be
		 * computed and hence cannot be hardcoded into the array of
		 * config parameters
		 */
		for (i = 0; i < COUNT_OF(c); i++) {
			log_msg(vpn, LOG_DEBUG, "%s: %s", c[i].name, c[i].value);
			if (strlen(c[i].value) == 0) {
				if (c[i].default_value == NULL) {
					if (!(strcmp(c[i].name, "remote_host:") == 0 ||
					      strcmp(c[i].name, "host_addr:") == 0 ||
					      strcmp(c[i].name, "remote_network:") == 0 ||
					      strcmp(c[i].name, "local_network:") == 0 ||
					      strcmp(c[i].name, "resolv_addr:") == 0 ||
					      strcmp(c[i].name, "resolv_domain:") == 0)) {
						ok = false;
						log_msg(vpn, LOG_ERR, "%s not specified", c[i].desc);
					}
				} else {
					if (strcmp(c[i].name, "stats_prefix:") == 0) {
						gethostname(c[i].value, c[i].value_sz);
						for (j = 0; j < c[i].value_sz; j++) {
							if (c[i].value[j] == '.')
								c[i].value[j] = '_';
						}
					} else {
						log_msg(vpn, LOG_DEBUG, "setting %s to %s",
							c[i].name, c[i].default_value);
						strlcpy(c[i].value, c[i].default_value,
							c[i].value_sz);
					}
				}
			}
		}

		if (strcmp(role, "net-gw") == 0) {
			vpn->role = NET_GW;
			if (strlen(remote_network) == 0) {
				ok = false;
				log_msg(vpn, LOG_ERR, "remote network must be "
					"specified when in \"%s\" role", VPN_ROLE_STR(vpn->role));
			}
			if (ok) {
				if ((prefix_start = strchr(remote_network, '/')) != NULL) {
					*prefix_start = '\0';
					prefix_start++;
				} else {
					ok = false;
					log_msg(vpn, LOG_ERR, "can't find prefix in "
						"remote network");
				}
			}
			if (ok) {
				printf("remote_network: %s\n", remote_network);
				vpn->remote_network_family = inet_pton_any(vpn, remote_network,
						      &vpn->remote_network);
				if (vpn->remote_network_family == AF_UNSPEC)
					ok = false;
			}
			if (ok) {
				max_prefix_len = (vpn->remote_network_family == AF_INET)
					? 32 : 128;
				vpn->remote_network_prefix_len = strtonum(prefix_start,
						0, max_prefix_len, &errstr);
				if (errstr) {
					ok = false;
					log_msg(vpn, LOG_ERR, "remote network prefix length too %s", errstr);
				}
			}
		} else if (strcmp(role, "host-gw") == 0) {
			vpn->role = HOST_GW;
			if (strlen(host_addr) == 0) {
				ok = false;
				log_msg(vpn, LOG_ERR, "host address must be "
					"specified when in \"%s\" role", VPN_ROLE_STR(vpn->role));
			}
			if (ok) {
				if ((prefix_start = strchr(host_addr, '/')) != NULL) {
					*prefix_start = '\0';
					prefix_start++;
				} else {
					ok = false;
					log_msg(vpn, LOG_ERR, "can't find prefix in "
						"host address");
				}
			}
			if (ok) {
				vpn->tx_peer_info.host_addr_family = inet_pton_any(vpn, host_addr,
					      &vpn->tx_peer_info.host_addr);
				if (vpn->tx_peer_info.host_addr_family == AF_UNSPEC)
					ok = false;
			}
			if (ok) {
				max_prefix_len = (vpn->tx_peer_info.host_addr_family == AF_INET)
					? 32 : 128;
				vpn->tx_peer_info.host_prefix_len = strtonum(prefix_start,
						0, max_prefix_len, &errstr);
				if (errstr) {
					ok = false;
					log_msg(vpn, LOG_ERR, "host address prefix length too %s", errstr);
				}
			}
			if (strlen(local_network) == 0) {
				ok = false;
				log_msg(vpn, LOG_ERR, "local network must be "
					"specified when in \"%s\" role", VPN_ROLE_STR(vpn->role));
			}
			if (ok) {
				if ((prefix_start = strchr(local_network, '/')) != NULL) {
					*prefix_start = '\0';
					prefix_start++;
				} else {
					ok = false;
					log_msg(vpn, LOG_ERR, "can't find prefix in "
						"local network");
				}
			}
			if (ok) {
				vpn->tx_peer_info.remote_net_addr_family = inet_pton_any(vpn,
											 local_network, &vpn->tx_peer_info.remote_net);
				if (vpn->tx_peer_info.host_addr_family == AF_UNSPEC)
					ok = false;
			}
			if (ok) {
				max_prefix_len = (vpn->tx_peer_info.remote_net_addr_family == AF_INET)
					? 32 : 128;
				vpn->tx_peer_info.remote_net_prefix_len = strtonum(prefix_start,
						0, max_prefix_len, &errstr);
				if (errstr) {
					ok = false;
					log_msg(vpn, LOG_ERR, "remote network prefix length too %s", errstr);
				}
			}
			if (ok) {
				if (strlen(resolv_addr) > 0) {
					vpn->tx_peer_info.resolv_addr_family = inet_pton_any(vpn, resolv_addr,
					    &vpn->tx_peer_info.resolv_addr);
					if (vpn->tx_peer_info.resolv_addr_family == AF_UNSPEC)
						ok = false;
				} else {
					vpn->tx_peer_info.resolv_addr_family = AF_UNSPEC;
				}
			}
			if (ok) {
				if (strlen(resolv_domain) > 0) {
					strlcpy(vpn->tx_peer_info.resolv_domain, resolv_domain,
						sizeof(vpn->tx_peer_info.resolv_domain));
				}
			}
		} else if (strcmp(role, "host") == 0) {
			vpn->role = HOST;
		} else {
			ok = false;
			log_msg(vpn, LOG_ERR, "invalid role specified (must be "
				"\"net-gw\", \"host-gw\" or \"host\")\n");
		}

		if (ok) {
			if (vpn->role != HOST_GW && strlen(remote_host) == 0) {
				ok = false;
				log_msg(vpn, LOG_ERR, "remote host must be specified "
				    "for %s or %s role", VPN_ROLE_STR(HOST),
					VPN_ROLE_STR(NET_GW));
			}
		}
		if (ok) {
			vpn->max_key_age_secs = strtonum(max_key_age_secs, 30, 3600,
							 &num_err);
			if (num_err) {
				ok = false;
				log_msg(vpn, LOG_ERR, "invalid maximum key age: %s", &num_err);
			}
		}
		if (ok) {
			vpn->max_key_sent_packet_count = strtonum(
			max_key_sent_packet_count, 5000, 10000000, &num_err);
			if (num_err) {
				ok = false;
				log_msg(vpn, LOG_ERR, "invalid maximum key packet count: %s",
					num_err);
			}
		}
		if (ok) {
			vpn->max_reads_per_event = strtonum(
			max_read_per_event, 1, 10000, &num_err);
			if (num_err) {
				ok = false;
				log_msg(vpn, LOG_ERR, "invalid max reads per event: %s",
					num_err);
			}
		}
		if (ok) {
			vpn->nonce_incr_count = 0;
			vpn->nonce_reset_incr = strtonum(
				     nonce_reset_incr, 16, 20000, &num_err);
			if (num_err) {
				ok = false;
				log_msg(vpn, LOG_ERR, "invalid nonce reset increment: %s",
					num_err);
			} else {
				nonce_reset_incr_le = htole32(vpn->nonce_reset_incr);
				memcpy(vpn->nonce_reset_incr_bin, &nonce_reset_incr_le,
				       sizeof(nonce_reset_incr_le));
			}
		}
		if (ok) {
			if (sodium_init() == -1) {
				ok = false;
				log_msg(vpn, LOG_ERR, "Failed to initialize crypto library");
			}
		}
		/* Setup initial crypto box */
		if (ok) {
			if (sodium_hex2bin(local_sk_bin, sizeof(local_sk_bin),
				    local_sk_hex, strlen(local_sk_hex), ":",
					   &bin_len, NULL) != 0) {
				ok = false;
				log_msg(vpn, LOG_ERR, "invalid local secret key");
			}
		}
		if (ok) {
			if (sodium_hex2bin(remote_pk_bin, sizeof(remote_pk_bin),
				  remote_pk_hex, strlen(remote_pk_hex), ":",
					   &bin_len, NULL) != 0) {
				ok = false;
				log_msg(vpn, LOG_ERR, "invalid remote public key");
			}
		}
		if (ok) {
			if (crypto_box_beforenm(vpn->cur_shared_key, remote_pk_bin,
						local_sk_bin) != 0) {
				ok = false;
				log_msg(vpn, LOG_ERR, "couldn't create shared key");
			} else {
				memcpy(vpn->orig_shared_key, vpn->cur_shared_key,
				       sizeof(vpn->orig_shared_key));
			}
		}
		/* Set up control socket */
		if (ok) {
			ok = open_tun_sock(vpn, tunnel_device);
		}

		if (ok)
			ok = set_nonblocking(vpn, vpn->ctrl_sock, "tunnel control socket");

		/* open stats socket */
		if (ok) {
			if ((vpn->stats_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
				ok = false;
				log_msg(vpn, LOG_ERR, "couldn't create stats socket -- %s",
					strerror(errno));
			}
		}
		if (ok) {
			memset(&stats_addr, 0, sizeof(stats_addr));
			stats_addr.sun_family = AF_UNIX;
			strlcpy(stats_addr.sun_path, stats_path, sizeof(stats_addr.sun_path));
			unlink(stats_path);
			if (bind(vpn->stats_sock, (struct sockaddr *)&stats_addr,
				 sizeof(stats_addr)) == -1) {
				ok = false;
				log_msg(vpn, LOG_ERR, "couldn't bind stats socket -- %s",
					strerror(errno));
			}
		}
		if (ok) {
			if (listen(vpn->stats_sock, 5) == -1) {
				ok = false;
				log_msg(vpn, LOG_ERR, "couldn't listen stats socket -- %s",
					strerror(errno));
			}
		}
		/* Set up communication socket */
		if (ok) {
			ok = get_sockaddr(vpn, &local_addrinfo, NULL, local_port, true);
		}
		if (ok) {
			if ((vpn->ext_sock = socket(local_addrinfo->ai_family,
					  SOCK_DGRAM, IPPROTO_UDP)) == -1) {
				ok = false;
				log_msg(vpn, LOG_ERR, "couldn't create socket: %s",
					strerror(errno));
			}
		}
		if (ok) {
			if (bind(vpn->ext_sock, local_addrinfo->ai_addr,
				 local_addrinfo->ai_addrlen) == -1) {
				ok = false;
				close(vpn->ext_sock);
				log_msg(vpn, LOG_ERR, "couldn't bind to %s: %s",
				    format_sockaddr(local_addrinfo->ai_addr,
					    local_info, sizeof(local_info)),
					strerror(errno));
			}
		}
		if (ok)
			ok = set_nonblocking(vpn, vpn->ext_sock, "external socket");

		if (ok)
			ok = init_event_processing(vpn, fflag);

		if (ok) {
			generate_peer_id(vpn);
			if (read_nonce(vpn, LOCAL)) {
				log_nonce(vpn, "read nonce reset point", vpn->nonce);
			} else {
				randombytes_buf(vpn->nonce, sizeof(vpn->nonce));
				log_nonce(vpn, "generating initial nonce", vpn->nonce);
			}
			write_nonce(vpn, LOCAL);

			if (read_nonce(vpn, REMOTE)) {
				log_nonce(vpn, "read remote nonce reset point",
					  vpn->remote_nonce);
			} else {
				bzero(vpn->remote_nonce, sizeof(vpn->remote_nonce));
				log_nonce(vpn, "initializing remote nonce",
					  vpn->remote_nonce);
			}

			vpn->rx_data_bytes = vpn->rx_packets = vpn->rx_late_packets =
				vpn->tx_data_bytes = vpn->tx_packets =
				vpn->bad_nonces =
				vpn->peer_init_retransmits =
				vpn->key_switch_start_retransmits =
				vpn->key_switch_ack_retransmits =
				vpn->key_ready_retransmits =
				vpn->keys_used = vpn->sess_starts =
				vpn->sess_active_secs = vpn->inactive_secs =
				vpn->decrypt_failures =
				vpn->ctrl_sock_rx_per_event_hi_water =
				vpn->ctrl_sock_rx_per_event_max_reached =
				vpn->ext_sock_rx_per_event_hi_water =
				vpn->ext_sock_rx_per_event_max_reached = 0;

			vpn->shared_key_is_ephemeral = vpn->peer_died = false;
			vpn->late_nonces = NULL;
			get_cur_monotonic(&vpn->sess_end_ts);

			if (vpn->role == HOST_GW) {
				change_state(vpn, HOST_WAIT);
			} else {
				ok = get_sockaddr(vpn, &remote_addrinfo, remote_host, remote_port, false);
				if (ok) {
					ok = manage_ext_sock_connection(vpn, remote_addrinfo->ai_addr,
					       remote_addrinfo->ai_addrlen);
					if (ok)
						change_state(vpn, INIT);
				}
			}
		}
	} else {
		ok = false;
		log_msg(vpn, LOG_ERR, "couldn't open config file %s: %s",
			config_fname, strerror(errno));
	}

	if (local_addrinfo != NULL)
		freeaddrinfo(local_addrinfo);

	if (remote_addrinfo != NULL)
		freeaddrinfo(remote_addrinfo);

	return ok;
}
