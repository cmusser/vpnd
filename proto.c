#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <net/if.h>
#ifdef __DragonFly__
#include <net/tun/if_tun.h>
#else
#include <net/if_tun.h>
#endif
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include "sodium.h"
#include "log.h"
#include "net.h"
#include "os.h"
#include "proto.h"

#define PEER_MAX_HEARTBEAT_INTERVAL_SECS 20
#define MAX_HOST_GW_INIT_SECS 120
#define PEER_INIT_RETRANS_INTERVAL (5 * 1000)
#define HEARTBEAT_INTERVAL (10 * 1000)
#define KEY_SWITCH_RETRANS_INTERVAL (500)
#define KEY_READY_RETRANS_INTERVAL (500)

struct config_param {
	char           *desc;
	char           *name;
	size_t		name_sz;
	char           *value;
	size_t		value_sz;
	char           *default_value;
};

char           *get_value(char *line, size_t len);
void		generate_peer_id(struct vpn_state *vpn);

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

void
generate_peer_id(struct vpn_state *vpn)
{
	randombytes_buf(&vpn->peer_id, sizeof(vpn->peer_id));
	vpn->tx_peer_info.peer_id = htonl(vpn->peer_id);
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
	char		nonce_reset_incr[16] = {'\0'};
	const char     *num_err;
	struct config_param c[] = {
		{"role", "role:", sizeof("role:"),
		role, sizeof(role), "net-gw"},
		{"tunnel device", "device:", sizeof("device:"),
		tunnel_device, sizeof(tunnel_device), "/dev/tun0"},
		{"stats prefix", "stats_prefix:", sizeof("stats_prefix:"),
		vpn->stats_prefix, sizeof(vpn->stats_prefix), "<hostname>"},
		{"local secret key", "local_sk:", sizeof("local_sk:"),
		local_sk_hex, sizeof(local_sk_hex), NULL},
		{"local port", "local_port:", sizeof("local_port:"),
		local_port, sizeof(local_port), "1337"},
		{"remote public key", "remote_pk:", sizeof("remote_pk:"),
		remote_pk_hex, sizeof(remote_pk_hex), NULL},
		{"remote host", "remote_host:", sizeof("remote_host:"),
		remote_host, sizeof(remote_host), NULL},
		{"remote port", "remote_port:", sizeof("remote_port:"),
		remote_port, sizeof(remote_port), "1337"},
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
		{"nonce reset increment", "nonce_reset_incr:", sizeof("nonce_reset_incr:"),
		nonce_reset_incr, sizeof(nonce_reset_incr), "10000"},
		{"nonce file", "nonce_file:", sizeof("nonce_file:"),
		vpn->nonce_filename, sizeof(vpn->nonce_filename), "vpnd.nonce"},
	};

	size_t		bin_len;
	unsigned char	local_sk_bin[crypto_box_SECRETKEYBYTES];
	unsigned char	remote_pk_bin[crypto_box_PUBLICKEYBYTES];
	unsigned int	i , j;
	char           *prefix_start, *tun_name_start;
	long long	max_prefix_len;
	const char     *errstr;
	struct addrinfo *local_addrinfo = NULL;
	char		local_info[INET6_ADDRSTRLEN + 7];
	struct addrinfo *remote_addrinfo = NULL;
	int		ioctl_data;
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

	vpn->already_ip_forwarding = get_sysctl_bool(vpn, SYS_IP_FORWARDING);
	vpn->already_ip6_forwarding = get_sysctl_bool(vpn, SYS_IP6_FORWARDING);

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
				if (resolv_addr != NULL && strlen(resolv_addr) > 0) {
					vpn->tx_peer_info.resolv_addr_family = inet_pton_any(vpn, resolv_addr,
					    &vpn->tx_peer_info.resolv_addr);
					if (vpn->tx_peer_info.resolv_addr_family == AF_UNSPEC)
						ok = false;
				} else {
					vpn->tx_peer_info.resolv_addr_family = AF_UNSPEC;
				}
			}
			if (ok) {
				if (resolv_domain != NULL && strlen(resolv_domain) > 0) {
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
			tun_name_start = strrchr(tunnel_device, '/');
			if (tun_name_start == NULL) {
				ok = false;
				log_msg(vpn, LOG_ERR, "Couldn't locate tunnel device name");
			} else {
				tun_name_start++;
				strlcpy(vpn->tun_name, tun_name_start, sizeof(vpn->tun_name));
			}
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
			vpn->ctrl_sock = open(tunnel_device, O_RDWR);
			if (vpn->ctrl_sock < 0) {
				ok = false;
				log_msg(vpn, LOG_ERR, "couldn't open tunnel: %s", strerror(errno));
			}
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
		if (ok) {
			generate_peer_id(vpn);
			if (read_nonce_reset_point(vpn, vpn->nonce)) {
				log_nonce(vpn, "read nonce reset point", vpn->nonce);
			} else {
				randombytes_buf(vpn->nonce, sizeof(vpn->nonce));
				log_nonce(vpn, "generating initial nonce", vpn->nonce);
			}
			write_nonce_reset_point(vpn);
			bzero(vpn->remote_nonce, sizeof(vpn->remote_nonce));

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

			if (fflag) {
				EV_SET(&vpn->kev_changes[6], STDIN_FILENO,
				  EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
				vpn->kev_change_count++;
			}
			vpn->rx_bytes = vpn->tx_bytes =
				vpn->peer_init_retransmits =
				vpn->key_switch_start_retransmits =
				vpn->key_switch_ack_retransmits =
				vpn->key_ready_retransmits =
				vpn->keys_used = vpn->sess_starts =
				vpn->sess_active_secs = vpn->inactive_secs =
				vpn->decrypt_failures = 0;

			vpn->peer_died = false;
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

void
return_to_init_state(struct vpn_state *vpn)
{
	memcpy(vpn->cur_shared_key, vpn->orig_shared_key,
	       sizeof(vpn->cur_shared_key));
	change_state(vpn, INIT);
	manage_network_config(vpn);

}

void
change_state(struct vpn_state *vpn, vpn_state new_state)
{
	time_t		inactive_secs;
	char		inactive_str[32];

	log_msg(vpn, LOG_INFO, "%s --> %s", VPN_STATE_STR(vpn->state),
		VPN_STATE_STR(new_state));
	vpn->state = new_state;

	switch (vpn->state) {
	case HOST_WAIT:
		log_msg(vpn, LOG_NOTICE, "%s: waiting for host", VPN_ROLE_STR(vpn->role));
		break;
	case INIT:
		tx_peer_info(vpn);
		break;
	case MASTER_KEY_STALE:
		crypto_box_keypair(vpn->new_public_key, vpn->new_secret_key);
		tx_new_public_key(vpn);
		break;
	case SLAVE_KEY_SWITCHING:
		tx_new_public_key(vpn);
		break;
	case MASTER_KEY_READY:
		/* Nothing to do here */
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		get_cur_monotonic(&vpn->key_start_ts);
		vpn->key_sent_packet_count = 0;
		vpn->keys_used++;
		if (vpn->peer_died || vpn->sess_starts == 0) {
			vpn->sess_start_ts = vpn->key_start_ts;
			inactive_secs = vpn->sess_start_ts.tv_sec -
				vpn->sess_end_ts.tv_sec;
			vpn->inactive_secs += inactive_secs;
			vpn->peer_died = false;
			vpn->sess_starts++;
			manage_network_config(vpn);
			log_msg(vpn, LOG_NOTICE, "%s: session #%" PRIu32 " started "
				"in %s",
				VPN_STATE_STR(vpn->state),
				vpn->sess_starts,
				time_str(inactive_secs, inactive_str, sizeof(inactive_str)));
		}
		tx_peer_info(vpn);
		break;
	default:
		log_msg(vpn, LOG_WARNING, "unhandled state transition: %s",
			VPN_STATE_STR(vpn->state));
	}
}

bool
tx_encrypted(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len)
{
	bool		ok;
	unsigned char  *key;
	unsigned char	ciphertext[crypto_box_MACBYTES + sizeof(struct vpn_msg)];
	size_t		payload_len, ciphertext_len;
	struct iovec	tx_iovec[2];
	ssize_t		tx_len;

	ok = true;
	payload_len = sizeof(unsigned char) + data_len;
	ciphertext_len = payload_len + crypto_box_MACBYTES;

	key = (vpn->state == MASTER_KEY_READY && msg->type == KEY_READY)
		? vpn->ready_retrans_key : vpn->cur_shared_key;
	if (crypto_box_easy_afternm(ciphertext, (unsigned char *)msg,
				    payload_len, vpn->nonce, key) != 0) {
		ok = false;
		log_msg(vpn, LOG_ERR, "%s: encryption failed", VPN_STATE_STR(vpn->state));
	}
	if (ok) {
		tx_iovec[0].iov_base = vpn->nonce;
		tx_iovec[0].iov_len = sizeof(vpn->nonce);
		tx_iovec[1].iov_base = ciphertext;
		tx_iovec[1].iov_len = ciphertext_len;

		if ((tx_len = writev(vpn->ext_sock, tx_iovec, COUNT_OF(tx_iovec))) == -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "%s: writev failed for %s message -- %s (%d)",
			 VPN_STATE_STR(vpn->state), MSG_TYPE_STR(msg->type),
				strerror(errno), errno);
		} else {
			vpn->key_sent_packet_count++;
		}

	}
	sodium_increment(vpn->nonce, sizeof(vpn->nonce));
	vpn->nonce_incr_count++;

	if (vpn->nonce_incr_count == vpn->nonce_reset_incr)
		write_nonce_reset_point(vpn);

	return ok;
}

void
tx_peer_info(struct vpn_state *vpn)
{
	bool		ok;
	struct vpn_msg	msg;
	timer_type	ttype;
	intptr_t	timeout_interval;

	ok = true;
	msg.type = PEER_INFO;

	switch (vpn->state) {
	case INIT:
		ttype = RETRANSMIT_PEER_INIT;
		timeout_interval = PEER_INIT_RETRANS_INTERVAL;
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		ttype = ACTIVE_HEARTBEAT;
		timeout_interval = HEARTBEAT_INTERVAL;
		break;
	default:
		ok = false;
		log_msg(vpn, LOG_ERR, "%s: may not transmit %s in %s state",
			VPN_ROLE_STR(vpn->role), MSG_TYPE_STR(msg.type),
			VPN_STATE_STR(vpn->state));
	}

	if (ok) {
		memcpy(&msg.data, &vpn->tx_peer_info,
		       sizeof(vpn->tx_peer_info));
		if (tx_encrypted(vpn, &msg, sizeof(vpn->tx_peer_info)))
			add_timer(vpn, ttype, timeout_interval);
	}
}

void
tx_new_public_key(struct vpn_state *vpn)
{
	bool		ok;
	struct vpn_msg	msg;
	message_type	type;
	timer_type	ttype;

	ok = true;

	switch (vpn->state) {
	case MASTER_KEY_STALE:
		type = KEY_SWITCH_START;
		ttype = RETRANSMIT_KEY_SWITCH_START;
		break;
	case SLAVE_KEY_SWITCHING:
		type = KEY_SWITCH_ACK;
		ttype = RETRANSMIT_KEY_SWITCH_ACK;
		break;
	default:
		ok = false;
		log_msg(vpn, LOG_ERR, "%s: may not transmit %s or %s in %s state",
		    VPN_ROLE_STR(vpn->role), MSG_TYPE_STR(KEY_SWITCH_START),
		   MSG_TYPE_STR(KEY_SWITCH_ACK), VPN_STATE_STR(vpn->state));
	}

	if (ok) {
		msg.type = type;
		memcpy(msg.data, vpn->new_public_key, sizeof(vpn->new_public_key));
		if (tx_encrypted(vpn, &msg, sizeof(vpn->new_public_key)))
			add_timer(vpn, ttype, KEY_SWITCH_RETRANS_INTERVAL);
	}
}

void
tx_key_ready(struct vpn_state *vpn)
{
	bool		ok;
	struct vpn_msg	msg;

	ok = true;
	msg.type = KEY_READY;

	switch (vpn->state) {
	case MASTER_KEY_STALE:
	case MASTER_KEY_READY:
		break;
	default:
		ok = false;
		log_msg(vpn, LOG_ERR, "%s: may not transmit %s in %s state",
			VPN_ROLE_STR(vpn->role), MSG_TYPE_STR(msg.type),
			VPN_STATE_STR(vpn->state));
	}

	if (ok) {
		memcpy(&msg.data, &vpn->tx_peer_info,
		       sizeof(vpn->tx_peer_info));
		if (tx_encrypted(vpn, &msg, sizeof(vpn->tx_peer_info)))
			add_timer(vpn, RETRANSMIT_KEY_READY, KEY_READY_RETRANS_INTERVAL);
	}
}

void
process_peer_info(struct vpn_state *vpn, struct vpn_msg *msg, struct sockaddr *peer_addr, socklen_t peer_addr_len)
{
	uint32_t	hostorder_remote_peer_id;

	memcpy(&vpn->rx_peer_info, msg->data, sizeof(vpn->rx_peer_info));

	switch (vpn->state) {
	case HOST_WAIT:
		manage_ext_sock_connection(vpn, peer_addr, peer_addr_len);
		change_state(vpn, INIT);
		break;
	case INIT:
		hostorder_remote_peer_id = ntohl(vpn->rx_peer_info.peer_id);
		if (hostorder_remote_peer_id > vpn->peer_id) {
			log_msg(vpn, LOG_DEBUG, "will be key master");
			change_state(vpn, MASTER_KEY_STALE);
		} else if (hostorder_remote_peer_id < vpn->peer_id) {
			/* Stay in INIT state */
			log_msg(vpn, LOG_DEBUG, "will be key slave");
		} else {
			log_msg(vpn, LOG_NOTICE, "got same peer ID from remote, trying again.");
			generate_peer_id(vpn);
			tx_peer_info(vpn);
		}
		break;
	case MASTER_KEY_READY:
		change_state(vpn, ACTIVE_MASTER);
		/* fallthrough */
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		get_cur_monotonic(&vpn->peer_last_heartbeat_ts);
		break;

	default:
		log_invalid_msg_for_state(vpn, msg->type);
	}
}

void
process_key_switch_start(struct vpn_state *vpn, struct vpn_msg *msg)
{
	switch (vpn->state) {
	case INIT:
	case ACTIVE_SLAVE:
		crypto_box_keypair(vpn->new_public_key, vpn->new_secret_key);
		if (crypto_box_beforenm(vpn->new_shared_key, msg->data,
					vpn->new_secret_key) != 0) {
			log_msg(vpn, LOG_ERR, "%s: couldn't create shared key",
				VPN_STATE_STR(vpn->state));
		} else {
			change_state(vpn, SLAVE_KEY_SWITCHING);
		}
		break;
	default:
		log_invalid_msg_for_state(vpn, msg->type);
	}
}

void
process_key_switch_ack(struct vpn_state *vpn, struct vpn_msg *msg)
{
	switch (vpn->state) {
	case MASTER_KEY_STALE:
		memcpy(vpn->ready_retrans_key, vpn->cur_shared_key,
		       sizeof(vpn->ready_retrans_key));
		tx_key_ready(vpn);
		if (crypto_box_beforenm(vpn->cur_shared_key, msg->data,
					vpn->new_secret_key) != 0) {
			log_msg(vpn, LOG_ERR, "%s couldn't create shared key",
				VPN_STATE_STR(vpn->state));
		} else {
			change_state(vpn, MASTER_KEY_READY);
		}
		break;
	default:
		log_invalid_msg_for_state(vpn, msg->type);
	}
}

void
process_key_ready(struct vpn_state *vpn, struct vpn_msg *msg)
{
	switch (vpn->state) {
	case SLAVE_KEY_SWITCHING:
		memcpy(&vpn->rx_peer_info, msg->data,
		       sizeof(vpn->rx_peer_info));
		memcpy(vpn->cur_shared_key, vpn->new_shared_key,
		       sizeof(vpn->cur_shared_key));
		change_state(vpn, ACTIVE_SLAVE);
		break;
	default:
		log_invalid_msg_for_state(vpn, msg->type);
	}
}

void
process_debug_string(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len)
{
	vpn->rx_bytes += data_len;

	log_msg(vpn, LOG_NOTICE, "%3zu bytes: (%s) \"%s\"", data_len,
		MSG_TYPE_STR(msg->type), msg->data);

}

void
process_rx_data(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len)
{
	switch (vpn->state) {
	case MASTER_KEY_READY:
		change_state(vpn, ACTIVE_MASTER);
		/* fallthrough */
	case MASTER_KEY_STALE:
	case SLAVE_KEY_SWITCHING:
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		if (write(vpn->ctrl_sock, msg->data, data_len) < 0)
			log_msg(vpn, LOG_ERR, "%s: couldn't write to tunnel -- %s",
				VPN_STATE_STR(vpn->state), strerror(errno));
		else
			vpn->rx_bytes += data_len;
		break;
	default:
		log_invalid_msg_for_state(vpn, msg->type);
	}
}

void
ctrl_sock_input(struct vpn_state *vpn)
{
	struct vpn_msg	msg;
	ssize_t		data_len;

	msg.type = DATA;
	data_len = read(vpn->ctrl_sock, msg.data, sizeof(msg.data));
	if (data_len >= 0) {
		if (tx_encrypted(vpn, &msg, data_len))
			vpn->tx_bytes += data_len;
	} else {
		log_msg(vpn, LOG_ERR, "%s: error reading from tunnel interface -- %s",
			VPN_STATE_STR(vpn->state), strerror(errno));
	}

}

void
ext_sock_input(struct vpn_state *vpn)
{
	bool		ok;
	unsigned char	ciphertext[crypto_box_MACBYTES + sizeof(struct vpn_msg)];
	struct vpn_msg	msg;
	size_t		rx_len , ciphertext_len;
	unsigned char	rx_nonce[crypto_box_NONCEBYTES];
	char		rx_nonce_str[(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};
	char		remote_nonce_str[(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};
	struct msghdr	msghdr = {0};
	struct sockaddr_storage peer_addr;
	struct iovec	rx_iovec[2];
	size_t		data_len;

	ok = true;

	if (vpn->role == HOST_GW && vpn->state == HOST_WAIT) {
		/* Unconnected socket, peer address will be available. */
		msghdr.msg_name = &peer_addr;
		msghdr.msg_namelen = sizeof(peer_addr);
	} else {
		/* Connected, peer address unavailable and not needed. */
		msghdr.msg_name = NULL;
		msghdr.msg_namelen = 0;
	}
	msghdr.msg_iov = rx_iovec;
	msghdr.msg_iovlen = COUNT_OF(rx_iovec);

	rx_iovec[0].iov_base = rx_nonce;
	rx_iovec[0].iov_len = sizeof(rx_nonce);
	rx_iovec[1].iov_base = ciphertext;
	rx_iovec[1].iov_len = sizeof(ciphertext);

	if ((rx_len = recvmsg(vpn->ext_sock, &msghdr, 0)) == -1) {
		ok = false;
		/*
		 * Ignore ECONNREFUSED because it's expected when sending on
		 * a connected socket and the peer is not available. The
		 * other host responds with an ICMP "port unreachable" that
		 * doesn't warrant an error message.
		 */
		if (errno != ECONNREFUSED)
			log_msg(vpn, LOG_ERR, "%s: recvmsg failed from tunnel socket -- %s (%d)",
			 VPN_STATE_STR(vpn->state), strerror(errno), errno);
	}
	if (ok) {
		if (sodium_compare(vpn->remote_nonce, rx_nonce, crypto_box_NONCEBYTES) > -1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "%s: received nonce (%s) <= previous (%s)",
				VPN_STATE_STR(vpn->state),
			  sodium_bin2hex(rx_nonce_str, sizeof(rx_nonce_str),
					 rx_nonce, sizeof(rx_nonce)),
				sodium_bin2hex(remote_nonce_str, sizeof(remote_nonce_str),
			     vpn->remote_nonce, sizeof(vpn->remote_nonce)));
		}
	}
	if (ok) {
		ciphertext_len = rx_len - sizeof(rx_nonce);
		if (crypto_box_open_easy_afternm((unsigned char *)&msg, ciphertext,
		      ciphertext_len, rx_nonce, vpn->cur_shared_key) != 0) {
			ok = false;
			vpn->decrypt_failures++;
		} else {
			memcpy(vpn->remote_nonce, rx_nonce, sizeof(vpn->remote_nonce));
		}
	}
	if (ok) {
		data_len = ciphertext_len - crypto_box_MACBYTES - sizeof(msg.type);

		if (msg.type != DATA)
			log_msg(vpn, LOG_DEBUG, "%s: received %s", VPN_STATE_STR(vpn->state),
				MSG_TYPE_STR(msg.type));

		switch (msg.type) {
		case PEER_INFO:
			process_peer_info(vpn, &msg, (struct sockaddr *)&peer_addr, msghdr.msg_namelen);
			break;
		case KEY_SWITCH_START:
			process_key_switch_start(vpn, &msg);
			break;
		case KEY_SWITCH_ACK:
			process_key_switch_ack(vpn, &msg);
			break;
		case KEY_READY:
			process_key_ready(vpn, &msg);
			break;
		case DEBUG_STRING:
			process_debug_string(vpn, &msg, data_len);
			break;
		case DATA:
			process_rx_data(vpn, &msg, data_len);
			break;
		default:
			log_msg(vpn, LOG_ERR, "%s: unknown message type %d",
				VPN_STATE_STR(vpn->state), msg.type);
		}
	}
}

void
stats_sock_input(struct vpn_state *vpn)
{
	int		client_fd;
	time_t		n;
	long long	now;
	char		stats_buf [1024];

	client_fd = accept(vpn->stats_sock, NULL, NULL);
	if (client_fd > 0) {
		time(&n);
		now = (long long)n;
		snprintf(stats_buf, sizeof(stats_buf),
			 "%s.keys %" PRIu32 " %lld\n"
			 "%s.keys %" PRIu32 " %lld\n"
			 "%s.sessions %" PRIu32 " %lld\n"
			 "%s.rx %" PRIu32 " %lld\n"
			 "%s.tx %" PRIu32 " %lld\n"
			 "%s.peer_info_retransmits %" PRIu32 " %lld\n"
			 "%s.key_switch_start_retransmits %" PRIu32 " %lld\n"
			 "%s.key_ack_retransmits %" PRIu32 " %lld\n"
			 "%s.key_ready_retransmits %" PRIu32 " %lld\n",
			 vpn->stats_prefix, vpn->keys_used, now,
			 vpn->stats_prefix, vpn->keys_used, now,
			 vpn->stats_prefix, vpn->sess_starts, now,
			 vpn->stats_prefix, vpn->rx_bytes, now,
			 vpn->stats_prefix, vpn->tx_bytes, now,
			 vpn->stats_prefix, vpn->peer_init_retransmits, now,
		  vpn->stats_prefix, vpn->key_switch_start_retransmits, now,
		    vpn->stats_prefix, vpn->key_switch_ack_retransmits, now,
			 vpn->stats_prefix, vpn->key_ready_retransmits, now);
		write(client_fd, stats_buf, strlen(stats_buf));
		close(client_fd);
	} else {
		log_msg(vpn, LOG_ERR, "couldn't accept connection on stats socket -- %s",
			strerror(errno));
	}

}

void
stdin_input(struct vpn_state *vpn)
{
	struct vpn_msg	msg;
	char           *tx_data;
	size_t		data_len;
	char           *last_char;

	msg.type = DEBUG_STRING;
	tx_data = (char *)msg.data;
	fgets(tx_data, sizeof(msg.data) - 1, stdin);

	if (strcmp(tx_data, "\n") == 0) {
		/* Do nothing. No sense in sending a blank line. */
	} else if (strcmp(tx_data, "stats\n") == 0) {
		log_stats(vpn);
	} else {
		last_char = &tx_data[strlen(tx_data) - 1];
		if (*last_char == '\n')
			*last_char = '\0';
		data_len = strlen(tx_data) + sizeof(char);
		if (tx_encrypted(vpn, &msg, data_len))
			vpn->tx_bytes += data_len;
	}

}

bool
check_peer_alive(struct vpn_state *vpn, struct timespec now)
{
	time_t		cur_sess_active_secs;
	char		cur_sess_active_str[32];

	if ((now.tv_sec - vpn->peer_last_heartbeat_ts.tv_sec)
	    <= PEER_MAX_HEARTBEAT_INTERVAL_SECS) {
		vpn->peer_died = false;
	} else {
		if (vpn->peer_died == false) {
			vpn->peer_died = true;
			get_cur_monotonic(&vpn->sess_end_ts);
			cur_sess_active_secs = vpn->sess_end_ts.tv_sec -
				vpn->sess_start_ts.tv_sec;
			vpn->sess_active_secs += cur_sess_active_secs;
			log_msg(vpn, LOG_ERR, "%s: peer died after %s.",
				VPN_STATE_STR(vpn->state),
			 time_str(cur_sess_active_secs, cur_sess_active_str,
				  sizeof(cur_sess_active_str)));
		}
		/* Always return to init if dead */
		return_to_init_state(vpn);
	}
	return !vpn->peer_died;
}

void
process_timeout(struct vpn_state *vpn, struct kevent *kev)
{
	struct timespec	now;
	time_t		inactive_secs, cur_key_age;
	bool		peer_init_retransmit = false;
	char		inactive_secs_str[32];
	struct sockaddr_in null_addr = {0};

	get_cur_monotonic(&now);

	switch (kev->ident) {
	case RETRANSMIT_PEER_INIT:
		if (vpn->state == INIT) {
			switch (vpn->role) {
			case HOST_GW:
				inactive_secs = now.tv_sec - vpn->sess_end_ts.tv_sec;
				if (inactive_secs >= MAX_HOST_GW_INIT_SECS) {
					log_msg(vpn, LOG_NOTICE, "%s: returning to %s "
						"after %s in %s",
						VPN_ROLE_STR(vpn->role),
						VPN_STATE_STR(HOST_WAIT),
						time_str(inactive_secs, inactive_secs_str,
						 sizeof(inactive_secs_str)),
						VPN_STATE_STR(vpn->state));
					null_addr.sin_family = AF_UNSPEC;
					manage_ext_sock_connection(vpn,
					      (struct sockaddr *)&null_addr,
							 sizeof(null_addr));
					change_state(vpn, HOST_WAIT);
				} else {
					peer_init_retransmit = true;
				}
				break;
			default:
				peer_init_retransmit = true;
				break;
			}
		}
		if (peer_init_retransmit) {
			vpn->peer_init_retransmits++;
			log_retransmit(vpn, PEER_INFO);
			tx_peer_info(vpn);
		}
		break;
	case RETRANSMIT_KEY_SWITCH_START:
		if (check_peer_alive(vpn, now) && vpn->state == MASTER_KEY_STALE) {
			vpn->key_switch_start_retransmits++;
			log_retransmit(vpn, KEY_SWITCH_START);
			tx_new_public_key(vpn);
		}
		break;
	case RETRANSMIT_KEY_SWITCH_ACK:
		if (check_peer_alive(vpn, now) && vpn->state == SLAVE_KEY_SWITCHING) {
			vpn->key_switch_ack_retransmits++;
			log_retransmit(vpn, KEY_SWITCH_ACK);
			tx_new_public_key(vpn);
		}
		break;
	case RETRANSMIT_KEY_READY:
		if (check_peer_alive(vpn, now) && vpn->state == MASTER_KEY_READY) {
			vpn->key_ready_retransmits++;
			log_retransmit(vpn, KEY_READY);
			tx_key_ready(vpn);
		}
		break;
	case ACTIVE_HEARTBEAT:
		if (check_peer_alive(vpn, now)) {
			switch (vpn->state) {
			case ACTIVE_MASTER:
				tx_peer_info(vpn);
				cur_key_age = now.tv_sec - vpn->key_start_ts.tv_sec;
				if ((cur_key_age >= vpn->max_key_age_secs) ||
				    (vpn->key_sent_packet_count
				     >= vpn->max_key_sent_packet_count)) {
					change_state(vpn, MASTER_KEY_STALE);
				}
				break;
			case ACTIVE_SLAVE:
				tx_peer_info(vpn);
				break;
			default:
				break;
			}
		}
		break;
	default:
		log_msg(vpn, LOG_ERR, "%s: unknown timer id: %u",
			VPN_STATE_STR(vpn->state), kev->ident);
	}

}
