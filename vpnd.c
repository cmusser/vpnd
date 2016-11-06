#include <sys/endian.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/event.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#ifdef __FreeBSD__
#include <net/if_tun.h>
#elif __DragonFly__
#include <net/tun/if_tun.h>
#endif
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <syslog.h>
#include <unistd.h>

#include <sodium.h>

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))
#define PEER_MAX_HEARTBEAT_INTERVAL_SECS 20
#define MAX_HOST_GW_INIT_SECS 120
#define PEER_INIT_RETRANS_INTERVAL (5 * 1000)
#define HEARTBEAT_INTERVAL (10 * 1000)
#define KEY_SWITCH_RETRANS_INTERVAL (500)
#define KEY_READY_RETRANS_INTERVAL (500)

#define SYS_IP_FORWARDING "net.inet.ip.forwarding"
#define SYS_IP6_FORWARDING "net.inet6.ip6.forwarding"

/* VPN process role */
typedef enum {
	NET_GW,
	HOST_GW,
	HOST,
	VPN_ROLE_LAST_PLUS_ONE,
}		vpn_role;

const char     *vpn_role_string_array[VPN_ROLE_LAST_PLUS_ONE] =
{
	"NET GW",
	"HOST GW",
	"HOST",
};

#define VPN_ROLE_STR(role) \
	(((role) >= VPN_ROLE_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : vpn_role_string_array[(role)])


/* VPN states */
typedef enum {
	HOST_WAIT,
	INIT,
	MASTER_KEY_STALE,
	SLAVE_KEY_SWITCHING,
	MASTER_KEY_READY,
	ACTIVE_MASTER,
	ACTIVE_SLAVE,
	VPN_STATE_LAST_PLUS_ONE,
}		vpn_state;

const char     *vpn_state_string_array[VPN_STATE_LAST_PLUS_ONE] =
{
	"HOST WAIT",
	"INIT",
	"MASTER KEY STALE",
	"SLAVE KEY SWITCHING",
	"MASTER KEY READY",
	"ACTIVE (MASTER)",
	"ACTIVE (SLAVE)",
};

#define VPN_STATE_STR(state) \
	(((state) >= VPN_STATE_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : vpn_state_string_array[(state)])

/* message types exchanged between peers */
typedef enum {
	PEER_INFO,
	KEY_SWITCH_START,
	KEY_SWITCH_ACK,
	KEY_READY,
	DEBUG_STRING,
	DATA,
	MSG_TYPE_LAST_PLUS_ONE,
}		message_type;

const char     *message_type_string_array[MSG_TYPE_LAST_PLUS_ONE] =
{
	"PEER_INFO",
	"KEY_SWITCH_START",
	"KEY_SWITCH_ACK",
	"KEY_READY",
	"DEBUG_STRING",
	"DATA",
};

#define MSG_TYPE_STR(type) \
	(((type) >= MSG_TYPE_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : message_type_string_array[(type)])

/* Timers used for retransmits and expiry */
typedef enum {
	RETRANSMIT_PEER_INIT,
	RETRANSMIT_KEY_SWITCH_START,
	RETRANSMIT_KEY_SWITCH_ACK,
	RETRANSMIT_KEY_READY,
	ACTIVE_HEARTBEAT,
	TIMER_TYPE_LAST_PLUS_ONE,
}		timer_type;

const char     *timer_type_string_array[TIMER_TYPE_LAST_PLUS_ONE] =
{
	"RETRANSMIT_PEER_INIT",
	"RETRANSMIT_KEY_SWITCH_START",
	"RETRANSMIT_KEY_SWITCH_ACK",
	"RETRANSMIT_KEY_READY",
	"ACTIVE_HEARTBEAT",
};

#define TIMER_TYPE_STR(type) \
	(((type) >= TIMER_TYPE_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : timer_type_string_array[(type)])

struct config_param {
	char           *desc;
	char           *name;
	size_t		name_sz;
	char           *value;
	size_t		value_sz;
	char           *default_value;
};

#define DATA_SZ 1500
/* Message data structure definitions */
struct vpn_msg {
	unsigned char	type;
	unsigned char	data[DATA_SZ];
};

struct vpn_peer_info {
	uint32_t	peer_id;
	sa_family_t	host_addr_family;
	uint8_t		host_prefix_len;
	sa_family_t	resolv_addr_family;
	unsigned char	host_addr[sizeof(struct in6_addr)];
	unsigned char	resolv_addr[sizeof(struct in6_addr)];
	char		resolv_domain[32];
};

/* Finite state machine state data. */
struct vpn_state {
	vpn_role	role;
	vpn_state	state;
	char		tun_name  [8];
	char		nonce_filename[256];
	char		resolvconf_path[256];
	bool		already_ip_forwarding;
	bool		already_ip6_forwarding;
	uint32_t	peer_id;
	struct vpn_peer_info tx_peer_info;
	struct vpn_peer_info rx_peer_info;
	char		stats_prefix[64];
	unsigned char	orig_shared_key[crypto_box_BEFORENMBYTES];
	unsigned char	cur_shared_key[crypto_box_BEFORENMBYTES];
	struct timespec	key_start_ts;
	struct timespec	sess_start_ts;
	struct timespec	sess_end_ts;
	time_t		sess_active_secs;
	time_t		inactive_secs;
	struct timespec	peer_last_heartbeat_ts;
	uint32_t	key_sent_packet_count;
	uint32_t	max_key_sent_packet_count;
	uint32_t	max_key_age_secs;
	unsigned char	new_secret_key[crypto_box_SECRETKEYBYTES];
	unsigned char	new_public_key[crypto_box_PUBLICKEYBYTES];
	unsigned char	new_shared_key[crypto_box_BEFORENMBYTES];
	unsigned char	ready_retrans_key[crypto_box_BEFORENMBYTES];
	unsigned char	nonce[crypto_box_NONCEBYTES];
	uint32_t	nonce_reset_incr;
	uint32_t	nonce_incr_count;
	unsigned char	nonce_reset_incr_bin[crypto_box_NONCEBYTES];
	unsigned char	remote_nonce[crypto_box_NONCEBYTES];
	int		ext_sock;
	int		ctrl_sock;
	int		stats_sock;
	struct kevent	kev_changes[8];
	uint32_t	kev_change_count;
	uint32_t	rx_bytes;
	uint32_t	tx_bytes;
	uint32_t	peer_init_retransmits;
	uint32_t	key_switch_start_retransmits;
	uint32_t	key_switch_ack_retransmits;
	uint32_t	key_ready_retransmits;
	uint32_t	keys_used;
	uint32_t	sess_starts;
	uint32_t	decrypt_failures;
	bool		peer_died;
};

int		log_upto;
bool		fflag = false;
int		vflag = 0;
void		log_msg   (int priority, const char *msg,...);
char           *time_str(time_t time, char *time_str, size_t len);
char           *get_value(char *line, size_t len);
bool		read_nonce_reset_point(struct vpn_state *vpn, unsigned char *nonce);
void		write_nonce_reset_point(struct vpn_state *vpn);
char           *format_sockaddr(sa_family_t af, struct sockaddr *sa, char *str, size_t str_sz);
bool		get_sockaddr(struct addrinfo **addrinfo_p, char *host, char *port_str, bool passive);
void		addr2net_with_netmask(sa_family_t af, void *host_addr, unsigned char *netmask);
void		addr2net_with_prefix(sa_family_t af, void *host_addr, uint8_t prefix_len);
sa_family_t	inet_pton_any(const char *restrict src, void *restrict dst);
bool		get_sysctl_bool(char *name);
void		set_sysctl_bool(char *name, bool value);
void		spawn_subprocess(char *cmd);
void		manage_resolver(struct vpn_state *vpn);
void		manage_proxy_arp_for_host(struct vpn_state *vpn);
void		manage_host_ptp_addrs(struct vpn_state *vpn);
void		manage_host_gw_ptp_addrs(struct vpn_state *vpn);
void		manage_route_to_host_gw_net(struct vpn_state *vpn);
void		manage_forwarding(struct vpn_state *vpn);
void		manage_network_config(struct vpn_state *vpn);
bool		manage_ext_sock_connection(struct vpn_state *vpn, struct sockaddr *remote_addr, socklen_t remote_addr_len);
void		generate_peer_id(struct vpn_state *vpn);
bool		init      (bool fflag, char *config_fname, struct vpn_state *vpn);
void		return_to_init_state(struct vpn_state *vpn);
void		change_state(struct vpn_state *vpn, vpn_state new_state);
void		log_invalid_msg_for_state(struct vpn_state *vpn, message_type msg_type);
void		log_nonce (struct vpn_state *vpn, char *prefix, unsigned char *nonce);
void		log_retransmit(struct vpn_state *vpn, message_type msg_type);
void		add_timer (struct vpn_state *vpn, timer_type ttype, intptr_t timeout_interval);
bool		tx_encrypted(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);
void		tx_peer_info(struct vpn_state *vpn);
void		tx_new_public_key(struct vpn_state *vpn);
void		tx_key_ready(struct vpn_state *vpn);
void		process_peer_info(struct vpn_state *vpn, struct vpn_msg *msg, struct sockaddr *peer_addr, socklen_t peer_addr_len);
void		process_key_switch_start(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_key_switch_ack(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_key_ready(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_debug_string(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);

void		process_rx_data(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);
void		ext_sock_input(struct vpn_state *vpn);
void		ctrl_sock_input(struct vpn_state *vpn);
void		stats_sock_input(struct vpn_state *vpn);
void		stdin_input(struct vpn_state *vpn);
bool		check_peer_alive(struct vpn_state *vpn, struct timespec now);
void		process_timeout(struct vpn_state *vpn, struct kevent *kev);
char           *string_for_addr(sa_family_t af, void *addr, char *addr_str, size_t addr_str_sz);
void		log_stats (struct vpn_state *vpn);
bool		run       (struct vpn_state *vpn);

void
log_msg(int priority, const char *msg,...)
{
	va_list		ap;
	time_t		now;
	struct tm	now_tm;
	char		timestamp_str[32];
	char		msg_str   [1024];

	va_start(ap, msg);
	if (fflag) {
		if (priority <= log_upto) {
			time(&now);
			localtime_r(&now, &now_tm);
			strftime(timestamp_str, sizeof(timestamp_str), "%c", &now_tm);
			vsnprintf(msg_str, sizeof(msg_str), msg, ap);
			fprintf(stderr, "%s %s", timestamp_str, msg_str);
			fprintf(stderr, "\n");
		}
	} else {
		vsyslog(priority, msg, ap);
	}
	va_end(ap);
}

char           *
time_str(time_t time, char *time_str, size_t len)
{
	time_t		h      , m, s;

	m = time / 60;
	s = time % 60;
	h = m / 60;
	m = m % 60;
	snprintf(time_str, len, "%ld:%02ld:%02ld", h, m, s);

	return time_str;
}

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
read_nonce_reset_point(struct vpn_state *vpn, unsigned char *nonce)
{
	bool		ok = true;
	FILE           *f;

	f = fopen(vpn->nonce_filename, "r");
	if (f == NULL) {
		ok = false;
		log_msg(LOG_ERR, "failed to open nonce file %s: %s\n",
			vpn->nonce_filename, strerror(errno));
	}
	if (ok) {
		if (fread(nonce, crypto_box_NONCEBYTES, 1, f) < 1) {
			ok = false;
			log_msg(LOG_ERR, "Can't read nonce from %s: %s\n",
				vpn->nonce_filename, strerror(errno));
		}
	}
	if (f != NULL)
		fclose(f);

	return ok;
}

void
write_nonce_reset_point(struct vpn_state *vpn)
{
	bool		ok = true;
	unsigned char	nonce_reset_point[crypto_box_NONCEBYTES];
	FILE           *f;

	vpn->nonce_incr_count = 0;

	f = fopen(vpn->nonce_filename, "w");
	if (f == NULL) {
		ok = false;
		log_msg(LOG_ERR, "failed to open nonce file %s: %s\n",
			vpn->nonce_filename, strerror(errno));
	}
	if (ok) {
		memcpy(nonce_reset_point, vpn->nonce, sizeof(nonce_reset_point));
		sodium_add(nonce_reset_point, vpn->nonce_reset_incr_bin,
			   sizeof(nonce_reset_point));
		log_nonce(vpn, "create nonce reset point", nonce_reset_point);
		if (fwrite(nonce_reset_point, sizeof(nonce_reset_point), 1, f) < 1) {
			ok = false;
			log_msg(LOG_ERR, "failed to write nonce to %s: %s\n",
				vpn->nonce_filename, strerror(errno));
		}
	}
	if (f != NULL)
		fclose(f);
}

char           *
format_sockaddr(sa_family_t af, struct sockaddr *sa, char *str, size_t str_sz)
{
	char		addr_str  [INET6_ADDRSTRLEN];

	switch (af) {
	case AF_UNSPEC:
		strlcpy(str, "NULL address", str_sz);
		break;
	case AF_INET:
		inet_ntop(af, &((struct sockaddr_in *)sa)->sin_addr,
			  addr_str, sizeof(addr_str));
		snprintf(str, str_sz, "%s:%u", addr_str,
			 ntohs(((struct sockaddr_in *)sa)->sin_port));
		break;
	case AF_INET6:
		inet_ntop(af, &((struct sockaddr_in6 *)sa)->sin6_addr,
			  addr_str, sizeof(addr_str));
		snprintf(str, str_sz, "%s:%u", addr_str,
			 ntohs(((struct sockaddr_in6 *)sa)->sin6_port));
		break;
	default:
		snprintf(str, str_sz, "invalid address (family: %d)", af);
	}

	return str;
}

bool
get_sockaddr(struct addrinfo **addrinfo_p, char *host, char *port_str, bool passive)
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
		log_msg(LOG_ERR, "invalid socket address info: \"%s:%s\"",
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
inet_pton_any(const char *restrict src, void *restrict dst)
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
		log_msg(LOG_ERR, "unparseable address: %s\n", src);
		break;
	case 1:
		break;

	default:
		af = AF_UNSPEC;
		log_msg(LOG_ERR, "error: %s\n", strerror(errno));
	}

	return af;
}

bool
get_sysctl_bool(char *name)
{
	bool		flag_bool = false;
	uint32_t	flag;
	size_t		flag_sz = sizeof(flag);

	if (sysctlbyname(name, &flag, &flag_sz, NULL, 0) == -1)
		log_msg(LOG_ERR, "sysctl get %s: %s", name, strerror(errno));
	else
		flag_bool = (flag == 0) ? false : true;

	return flag_bool;
}

void
set_sysctl_bool(char *name, bool value)
{
	uint32_t	flag;

	flag = (value == true) ? 1 : 0;

	if (sysctlbyname(name, NULL, 0, &flag, sizeof(flag)) == -1)
		log_msg(LOG_ERR, "sysctl set %s: %s", name, strerror(errno));
	else
		log_msg(LOG_NOTICE, "sysctl %s=%d", name, flag);
}

void
spawn_subprocess(char *cmd)
{
	char		cmd_with_stderr_redirect[512];
	FILE           *cmd_fd;
	char		cmd_out   [256];
	char           *newline;

	snprintf(cmd_with_stderr_redirect, sizeof(cmd_with_stderr_redirect),
		 "%s 2>&1", cmd);
	if ((cmd_fd = popen(cmd_with_stderr_redirect, "r")) == NULL) {
		log_msg(LOG_ERR, "spawn of \"%s\" failed: %s", cmd_with_stderr_redirect,
			strerror(errno));
	} else {

		while (fgets(cmd_out, sizeof(cmd_out), cmd_fd) != NULL) {
			newline = strrchr(cmd_out, '\n');
			if (newline)
				*newline = '\0';
			log_msg(LOG_NOTICE, "==> %s", cmd_out);
		}

		if (ferror(cmd_fd))
			log_msg(LOG_ERR, "reading subprocess output: %s", strerror(errno));

		pclose(cmd_fd);
	}
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
			log_msg(LOG_ERR, "creating of resolvconf temp data failed -- %s",
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
		log_msg(LOG_ERR, "cannot manage resolver in %s state",
			VPN_STATE_STR(vpn->state));
	}

	if (ok) {

		log_msg(LOG_NOTICE, "%s: %s", VPN_STATE_STR(vpn->state), resolvconf_cmd);
		if ((cmd_fd = popen(resolvconf_cmd, "r")) == NULL) {
			log_msg(LOG_ERR, "spawn of \"%s\" failed: %s", resolvconf_cmd,
				strerror(errno));
		} else {
			while (fgets(cmd_out, sizeof(cmd_out), cmd_fd) != NULL) {
				newline = strrchr(cmd_out, '\n');
				if (newline)
					*newline = '\0';
				log_msg(LOG_NOTICE, "==> %s", cmd_out);
			}

			if (ferror(cmd_fd))
				log_msg(LOG_ERR, "reading subprocess output: %s", strerror(errno));

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
	char		cmd       [256] = {'\0'};

	if (inet_ntop(vpn->tx_peer_info.host_addr_family, &vpn->tx_peer_info.host_addr,
		      host_addr_str, sizeof(host_addr_str)) == NULL) {
		ok = false;
		log_msg(LOG_WARNING, "%s: client host address (for proxy ARP) "
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
				log_msg(LOG_ERR, "unknown address type (%u) to remove ARP/NDP",
					vpn->tx_peer_info.host_addr_family);
			}
			break;
		case ACTIVE_MASTER:
		case ACTIVE_SLAVE:
			switch (vpn->tx_peer_info.host_addr_family) {
			case AF_INET:
				snprintf(cmd, sizeof(cmd), "arp -s %s auto pub", host_addr_str);
				break;
			case AF_INET6:
				snprintf(cmd, sizeof(cmd), "ndp -s %s proxy", host_addr_str);
			default:
				ok = false;
				log_msg(LOG_ERR, "unknown address type (%u) to add ARP/NDP",
					vpn->tx_peer_info.host_addr_family);

			}
			break;
		default:
			ok = false;
			log_msg(LOG_ERR, "cannot manage ARP/NDP in %s state",
				VPN_STATE_STR(vpn->state));
		}
	}
	if (ok) {
		log_msg(LOG_NOTICE, "%s: %s", VPN_ROLE_STR(vpn->role), cmd);
		spawn_subprocess(cmd);
	}
}

void
manage_host_ptp_addrs(struct vpn_state *vpn)
{
	char		host_addr_str[INET6_ADDRSTRLEN];
	char		cmd       [256] = {'\0'};

	if (inet_ntop(vpn->rx_peer_info.host_addr_family, &vpn->rx_peer_info.host_addr,
		      host_addr_str, sizeof(host_addr_str)) == NULL) {
		log_msg(LOG_WARNING, "%s: host address on remote network unconfigured "
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
			log_msg(LOG_NOTICE, "%s: %s",
				VPN_ROLE_STR(vpn->role), cmd);
			spawn_subprocess(cmd);
			break;
		default:
			log_msg(LOG_ERR, "cannot manage %s P-T-P addrs in %s state",
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
		log_msg(LOG_WARNING, "%s: client host address unconfigured or invalid",
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
			log_msg(LOG_NOTICE, "%s: %s", VPN_ROLE_STR(vpn->role), cmd);
			spawn_subprocess(cmd);
			break;
		default:
			log_msg(LOG_ERR, "cannot manage %s P-T-P addrs in %s state",
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
		log_msg(LOG_WARNING, "%s: remote network address unconfigured or invalid",
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
			log_msg(LOG_ERR, "cannot manage %s HOST route to HOST-GW "
			     "network in %s state", VPN_ROLE_STR(vpn->role),
				VPN_STATE_STR(vpn->state));
		}
		if (strlen(action_str) > 0) {
			snprintf(cmd, sizeof(cmd), "route %s %s/%u -interface %s",
				 action_str, net_addr_str, vpn->rx_peer_info.host_prefix_len,
				 vpn->tun_name);
			log_msg(LOG_NOTICE, "%s: %s", VPN_ROLE_STR(vpn->role), cmd);
			spawn_subprocess(cmd);
		}
	}
}

void
manage_forwarding(struct vpn_state *vpn)
{
	switch (vpn->state) {
	case INIT:
		if (!vpn->already_ip_forwarding)
			set_sysctl_bool(SYS_IP_FORWARDING, false);
		if (!vpn->already_ip6_forwarding)
			set_sysctl_bool(SYS_IP6_FORWARDING, false);
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		set_sysctl_bool(SYS_IP_FORWARDING, true);
		set_sysctl_bool(SYS_IP6_FORWARDING, true);
		break;
	default:
		log_msg(LOG_ERR, "%s: cannot manage forwarding in %s state",
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

	format_sockaddr(remote_addr->sa_family, remote_addr,
			remote_addr_str, sizeof(remote_addr_str));

	rv = connect(vpn->ext_sock, remote_addr, remote_addr_len);
	if (rv == 0 || (rv == -1 &&
	     ((struct sockaddr_in *)remote_addr)->sin_family == AF_UNSPEC &&
			errno == EAFNOSUPPORT)) {
		log_msg(LOG_NOTICE, "%s: setting peer to %s",
			VPN_ROLE_STR(vpn->role), remote_addr_str);
	} else {
		ok = false;
		log_msg(LOG_ERR, "couldn't connect to %s: %s",
			remote_addr_str, strerror(errno));
	}

	return ok;
}

void
generate_peer_id(struct vpn_state *vpn)
{
	randombytes_buf(&vpn->peer_id, sizeof(vpn->peer_id));
	vpn->tx_peer_info.peer_id = htonl(vpn->peer_id);
}

bool
init(bool fflag, char *config_fname, struct vpn_state *vpn)
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
	char		host_addr [INET6_ADDRSTRLEN] = {'\0'};
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

	vpn->already_ip_forwarding = get_sysctl_bool(SYS_IP_FORWARDING);
	vpn->already_ip6_forwarding = get_sysctl_bool(SYS_IP6_FORWARDING);

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
		 * stats_prefix: let the default be the hostname, which must be
		 * computed and hence cannot be hardcoded into the array of
		 * config parameters
		 */
		for (i = 0; i < COUNT_OF(c); i++) {
			log_msg(LOG_DEBUG, "%s: %s", c[i].name, c[i].value);
			if (strlen(c[i].value) == 0) {
				if (c[i].default_value == NULL) {
					if (!(strcmp(c[i].name, "remote_host:") == 0 ||
					      strcmp(c[i].name, "host_addr:") == 0 ||
					      strcmp(c[i].name, "resolv_addr:") == 0 ||
					      strcmp(c[i].name, "resolv_domain:") == 0)) {
						ok = false;
						log_msg(LOG_ERR, "%s not specified", c[i].desc);
					}
				} else {
					if (strcmp(c[i].name, "stats_prefix:") == 0) {
						gethostname(c[i].value, c[i].value_sz);
						for (j = 0; j < c[i].value_sz; j++) {
							if (c[i].value[j] == '.')
								c[i].value[j] = '_';
						}
					} else {
						log_msg(LOG_DEBUG, "setting %s to %s",
							c[i].name, c[i].default_value);
						strlcpy(c[i].value, c[i].default_value,
							c[i].value_sz);
					}
				}
			}
		}

		if (strcmp(role, "net-gw") == 0) {
			vpn->role = NET_GW;
		} else if (strcmp(role, "host-gw") == 0) {
			vpn->role = HOST_GW;
			if (strlen(host_addr) == 0) {
				ok = false;
				log_msg(LOG_ERR, "host address must be "
					"specified when in \"%s\" role", VPN_ROLE_STR(vpn->role));
			}
			if (ok) {
				if ((prefix_start = strchr(host_addr, '/')) != NULL) {
					*prefix_start = '\0';
					prefix_start++;
				} else {
					ok = false;
					log_msg(LOG_ERR, "can't find prefix in "
						"host address");
				}
			}
			if (ok) {
				vpn->tx_peer_info.host_addr_family = inet_pton_any(host_addr,
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
					log_msg(LOG_ERR, "prefix length too %s", errstr);
				}
			}
			if (ok) {
				if (resolv_addr != NULL && strlen(resolv_addr) > 0) {
					vpn->tx_peer_info.resolv_addr_family = inet_pton_any(resolv_addr,
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
			log_msg(LOG_ERR, "invalid role specified (must be "
				"\"net-gw\", \"host-gw\" or \"host\")\n");
		}

		if (ok) {
			tun_name_start = strrchr(tunnel_device, '/');
			if (tun_name_start == NULL) {
				ok = false;
				log_msg(LOG_ERR, "Couldn't locate tunnel device name");
			} else {
				tun_name_start++;
				strlcpy(vpn->tun_name, tun_name_start, sizeof(vpn->tun_name));
			}
		}
		if (ok) {
			if (vpn->role != HOST_GW && strlen(remote_host) == 0) {
				ok = false;
				log_msg(LOG_ERR, "remote host must be specified "
				    "for %s or %s role", VPN_ROLE_STR(HOST),
					VPN_ROLE_STR(NET_GW));
			}
		}
		if (ok) {
			vpn->max_key_age_secs = strtonum(max_key_age_secs, 30, 3600,
							 &num_err);
			if (num_err) {
				ok = false;
				log_msg(LOG_ERR, "invalid maximum key age: %s", &num_err);
			}
		}
		if (ok) {
			vpn->max_key_sent_packet_count = strtonum(
			max_key_sent_packet_count, 5000, 10000000, &num_err);
			if (num_err) {
				ok = false;
				log_msg(LOG_ERR, "invalid maximum key packet count: %s",
					num_err);
			}
		}
		if (ok) {
			vpn->nonce_incr_count = 0;
			vpn->nonce_reset_incr = strtonum(
				     nonce_reset_incr, 16, 20000, &num_err);
			if (num_err) {
				ok = false;
				log_msg(LOG_ERR, "invalid nonce reset increment: %s",
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
				log_msg(LOG_ERR, "Failed to initialize crypto library");
			}
		}
		/* Setup initial crypto box */
		if (ok) {
			if (sodium_hex2bin(local_sk_bin, sizeof(local_sk_bin),
				    local_sk_hex, strlen(local_sk_hex), ":",
					   &bin_len, NULL) != 0) {
				ok = false;
				log_msg(LOG_ERR, "invalid local secret key");
			}
		}
		if (ok) {
			if (sodium_hex2bin(remote_pk_bin, sizeof(remote_pk_bin),
				  remote_pk_hex, strlen(remote_pk_hex), ":",
					   &bin_len, NULL) != 0) {
				ok = false;
				log_msg(LOG_ERR, "invalid remote public key");
			}
		}
		if (ok) {
			if (crypto_box_beforenm(vpn->cur_shared_key, remote_pk_bin,
						local_sk_bin) != 0) {
				ok = false;
				log_msg(LOG_ERR, "couldn't create shared key");
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
				log_msg(LOG_ERR, "couldn't open tunnel: %s", strerror(errno));
			}
		}
		if (ok) {
			ioctl_data = IFF_POINTOPOINT;
			if (ioctl(vpn->ctrl_sock, TUNSIFMODE, &ioctl_data) < 0) {
				ok = false;
				log_msg(LOG_ERR, "couldn't set tunnel in p-t-p mode: %s",
					strerror(errno));
			}
		}
		if (ok) {
			ioctl_data = 0;
			if (ioctl(vpn->ctrl_sock, TUNSIFHEAD, &ioctl_data) < 0) {
				ok = false;
				log_msg(LOG_ERR, "couldn't set tunnel in link-layer mode: %s",
					strerror(errno));
			}
		}
		/* open stats socket */
		if (ok) {
			if ((vpn->stats_sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
				ok = false;
				log_msg(LOG_ERR, "couldn't create stats socket -- %s",
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
				log_msg(LOG_ERR, "couldn't bind stats socket -- %s",
					strerror(errno));
			}
		}
		if (ok) {
			if (listen(vpn->stats_sock, 5) == -1) {
				ok = false;
				log_msg(LOG_ERR, "couldn't listen stats socket -- %s",
					strerror(errno));
			}
		}
		/* Set up communication socket */
		if (ok) {
			ok = get_sockaddr(&local_addrinfo, NULL, local_port, true);
		}
		if (ok) {
			if ((vpn->ext_sock = socket(local_addrinfo->ai_family,
					  SOCK_DGRAM, IPPROTO_UDP)) == -1) {
				ok = false;
				log_msg(LOG_ERR, "couldn't create socket: %s",
					strerror(errno));
			}
		}
		if (ok) {
			if (bind(vpn->ext_sock, local_addrinfo->ai_addr,
				 local_addrinfo->ai_addrlen) == -1) {
				ok = false;
				close(vpn->ext_sock);
				log_msg(LOG_ERR, "couldn't bind to %s: %s",
				  format_sockaddr(local_addrinfo->ai_family,
						  local_addrinfo->ai_addr,
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
			clock_gettime(CLOCK_MONOTONIC, &vpn->sess_end_ts);

			if (vpn->role == HOST_GW) {
				change_state(vpn, HOST_WAIT);
			} else {
				ok = get_sockaddr(&remote_addrinfo, remote_host, remote_port, false);
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
		log_msg(LOG_ERR, "couldn't open config file %s: %s",
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

	log_msg(LOG_INFO, "%s --> %s", VPN_STATE_STR(vpn->state),
		VPN_STATE_STR(new_state));
	vpn->state = new_state;

	switch (vpn->state) {
	case HOST_WAIT:
		log_msg(LOG_NOTICE, "%s: waiting for host", VPN_ROLE_STR(vpn->role));
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
		clock_gettime(CLOCK_MONOTONIC, &vpn->key_start_ts);
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
			log_msg(LOG_NOTICE, "%s: session #%" PRIu32 " started "
				"in %s",
				VPN_STATE_STR(vpn->state),
				vpn->sess_starts,
				time_str(inactive_secs, inactive_str, sizeof(inactive_str)));
		}
		tx_peer_info(vpn);
		break;
	default:
		log_msg(LOG_WARNING, "unhandled state transition: %s",
			VPN_STATE_STR(vpn->state));
	}
}

void
log_invalid_msg_for_state(struct vpn_state *vpn, message_type msg_type)
{
	log_msg(LOG_ERR, "%s: received unexpected %s message",
		VPN_STATE_STR(vpn->state), MSG_TYPE_STR(msg_type));
}

void
log_nonce(struct vpn_state *vpn, char *prefix, unsigned char *nonce)
{
	char		nonce_str [(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};

	log_msg(LOG_NOTICE, "%s: %s %s)", VPN_ROLE_STR(vpn->role), prefix,
		sodium_bin2hex(nonce_str, sizeof(nonce_str), nonce, crypto_box_NONCEBYTES));
}

void
log_retransmit(struct vpn_state *vpn, message_type msg_type)
{
	log_msg(LOG_NOTICE, "%s: retransmitting %s", VPN_STATE_STR(vpn->state),
		MSG_TYPE_STR(msg_type));
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
		log_msg(LOG_ERR, "%s: No space for timer event (%s)",
			VPN_STATE_STR(vpn->state), TIMER_TYPE_STR(ttype));
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
		log_msg(LOG_ERR, "%s: encryption failed", VPN_STATE_STR(vpn->state));
	}
	if (ok) {
		tx_iovec[0].iov_base = vpn->nonce;
		tx_iovec[0].iov_len = sizeof(vpn->nonce);
		tx_iovec[1].iov_base = ciphertext;
		tx_iovec[1].iov_len = ciphertext_len;

		if ((tx_len = writev(vpn->ext_sock, tx_iovec, COUNT_OF(tx_iovec))) == -1) {
			ok = false;
			log_msg(LOG_ERR, "%s: writev failed for %s message -- %s (%d)",
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
		log_msg(LOG_ERR, "%s: may not transmit %s in %s state",
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
		log_msg(LOG_ERR, "%s: may not transmit %s or %s in %s state",
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
		log_msg(LOG_ERR, "%s: may not transmit %s in %s state",
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
			log_msg(LOG_DEBUG, "will be key master");
			change_state(vpn, MASTER_KEY_STALE);
		} else if (hostorder_remote_peer_id < vpn->peer_id) {
			/* Stay in INIT state */
			log_msg(LOG_DEBUG, "will be key slave");
		} else {
			log_msg(LOG_NOTICE, "got same peer ID from remote, trying again.");
			generate_peer_id(vpn);
			tx_peer_info(vpn);
		}
		break;
	case MASTER_KEY_READY:
		change_state(vpn, ACTIVE_MASTER);
		/* fallthrough */
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		clock_gettime(CLOCK_MONOTONIC, &vpn->peer_last_heartbeat_ts);
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
			log_msg(LOG_ERR, "%s: couldn't create shared key",
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
			log_msg(LOG_ERR, "%s couldn't create shared key",
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

	log_msg(LOG_NOTICE, "%3zu bytes: (%s) \"%s\"", data_len,
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
			log_msg(LOG_ERR, "%s: couldn't write to tunnel -- %s",
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
		log_msg(LOG_ERR, "%s: error reading from tunnel interface -- %s",
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
			log_msg(LOG_ERR, "%s: recvmsg failed from tunnel socket -- %s (%d)",
			 VPN_STATE_STR(vpn->state), strerror(errno), errno);
	}
	if (ok) {
		if (sodium_compare(vpn->remote_nonce, rx_nonce, crypto_box_NONCEBYTES) > -1) {
			ok = false;
			log_msg(LOG_ERR, "%s: received nonce (%s) <= previous (%s)",
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
			log_msg(LOG_DEBUG, "%s: received %s", VPN_STATE_STR(vpn->state),
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
			log_msg(LOG_ERR, "%s: unknown message type %d",
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
		log_msg(LOG_ERR, "couldn't accept connection on stats socket -- %s",
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
			clock_gettime(CLOCK_MONOTONIC, &vpn->sess_end_ts);
			cur_sess_active_secs = vpn->sess_end_ts.tv_sec -
				vpn->sess_start_ts.tv_sec;
			vpn->sess_active_secs += cur_sess_active_secs;
			log_msg(LOG_ERR, "%s: peer died after %s.",
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

	clock_gettime(CLOCK_MONOTONIC, &now);

	switch (kev->ident) {
	case RETRANSMIT_PEER_INIT:
		if (vpn->state == INIT) {
			switch (vpn->role) {
			case HOST_GW:
				inactive_secs = now.tv_sec - vpn->sess_end_ts.tv_sec;
				if (inactive_secs >= MAX_HOST_GW_INIT_SECS) {
					log_msg(LOG_NOTICE, "%s: returning to %s "
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
		log_msg(LOG_ERR, "%s: unknown timer id: %u",
			VPN_STATE_STR(vpn->state), kev->ident);
	}

}

char           *
string_for_addr(sa_family_t af, void *addr, char *addr_str, size_t addr_str_sz)
{
	switch (af) {
	case AF_UNSPEC:
		strlcpy(addr_str, "<none>", addr_str_sz);
		break;
	case AF_INET:
	case AF_INET6:
		inet_ntop(af, addr, addr_str, addr_str_sz);
		break;
	default:
		snprintf(addr_str, addr_str_sz, "<invalid, (af %u)>", af);

	}

	return addr_str;
}

void
log_stats(struct vpn_state *vpn)
{
	struct timespec	now;
	time_t		cur_inactive_secs, cur_sess_active_secs;
	char		cur_inactive_str[32], cur_sess_active_str[32];
	unsigned char	rp_nonce[crypto_box_NONCEBYTES];
	char		tx_nonce_str[(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};
	char		rp_nonce_str[(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};
	char		rx_nonce_str[(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};
	char		host_addr_str[INET6_ADDRSTRLEN];
	char		resolv_addr_str[INET6_ADDRSTRLEN];
	char		peer_info_str[256] = {'\0'};

	clock_gettime(CLOCK_MONOTONIC, &now);
	cur_inactive_secs = vpn->inactive_secs;
	cur_sess_active_secs = vpn->sess_active_secs;

	read_nonce_reset_point(vpn, rp_nonce);

	switch (vpn->role) {
	case HOST:
		snprintf(peer_info_str, sizeof(peer_info_str),
			 "\nRX peerinfo:\n"
			 "  host: %s/%d\n"
			 "  resolver: %s\n"
			 "  domain: %s",
			 string_for_addr(vpn->rx_peer_info.host_addr_family,
				&vpn->rx_peer_info.host_addr, host_addr_str,
		  sizeof(host_addr_str)), vpn->rx_peer_info.host_prefix_len,
		       string_for_addr(vpn->rx_peer_info.resolv_addr_family,
			    &vpn->rx_peer_info.resolv_addr, resolv_addr_str,
				       sizeof(resolv_addr_str)),
			 strlen(vpn->rx_peer_info.resolv_domain) > 0
			 ? vpn->rx_peer_info.resolv_domain : "<none>");
		break;
	case HOST_GW:
		snprintf(peer_info_str, sizeof(peer_info_str),
			 "\nTX peerinfo:\n"
			 "  host: %s/%d\n"
			 "  resolver: %s\n"
			 "  domain: %s",
			 string_for_addr(vpn->tx_peer_info.host_addr_family,
				&vpn->tx_peer_info.host_addr, host_addr_str,
		  sizeof(host_addr_str)), vpn->tx_peer_info.host_prefix_len,
		       string_for_addr(vpn->tx_peer_info.resolv_addr_family,
			    &vpn->tx_peer_info.resolv_addr, resolv_addr_str,
				       sizeof(resolv_addr_str)),
			 strlen(vpn->tx_peer_info.resolv_domain) > 0
			 ? vpn->tx_peer_info.resolv_domain : "<none>");
		break;
	default:
		break;
	}

	if (vpn->state == ACTIVE_MASTER || vpn->state == ACTIVE_SLAVE) {
		cur_sess_active_secs += (now.tv_sec - vpn->sess_start_ts.tv_sec);
	} else {
		cur_inactive_secs += (now.tv_sec - vpn->sess_end_ts.tv_sec);
	}

	log_msg(LOG_NOTICE, "--- vpnd statistics ---\n"
		"%s is %s:\n"
		"sessions: %" PRIu32 ", keys used: %" PRIu32 " (max age %" PRIu32 " sec.)\n"
		"time inactive/active: %s/%s\n"
		"data rx/tx: %" PRIu32 "/%" PRIu32 "\n"
		"decrypt failures: %" PRIu32 "\n"
		"retransmits (pi/kss/ksa/kr): %" PRIu32
		"/%" PRIu32 "/%" PRIu32 "/%" PRIu32 "\n"
		"last peer message: %" PRIu32 " sec. ago\n"
		"nonces since reset: %" PRIu32 "\n"
		"TX nonce: %s\n"
		"RP nonce: %s\n"
		"RX nonce: %s%s",
		VPN_ROLE_STR(vpn->role),
		VPN_STATE_STR(vpn->state),
		vpn->sess_starts, vpn->keys_used, vpn->max_key_age_secs,
		time_str(cur_inactive_secs, cur_inactive_str,
			 sizeof(cur_inactive_str)),
		time_str(cur_sess_active_secs, cur_sess_active_str,
			 sizeof(cur_sess_active_str)),
		vpn->rx_bytes, vpn->tx_bytes, vpn->decrypt_failures,
		vpn->peer_init_retransmits,
	 vpn->key_switch_start_retransmits, vpn->key_switch_ack_retransmits,
		vpn->key_ready_retransmits,
		(now.tv_sec - vpn->peer_last_heartbeat_ts.tv_sec),
		vpn->nonce_incr_count,
	      sodium_bin2hex(tx_nonce_str, sizeof(tx_nonce_str), vpn->nonce,
			     crypto_box_NONCEBYTES),
		sodium_bin2hex(rp_nonce_str, sizeof(rp_nonce_str), rp_nonce,
			       crypto_box_NONCEBYTES),
	sodium_bin2hex(rx_nonce_str, sizeof(rx_nonce_str), vpn->remote_nonce,
		       crypto_box_NONCEBYTES),
		peer_info_str);
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
		log_msg(LOG_ERR, "kqueue(): %s", strerror(errno));
	}
	while (ok) {
		nev = kevent(kq, vpn->kev_changes, vpn->kev_change_count,
			     &event, 1, NULL);
		vpn->kev_change_count = 0;
		if (nev < 0) {
			ok = false;
			log_msg(LOG_ERR, "kevent: %s", strerror(errno));
		} else {
			if (event.flags & EV_ERROR) {
				ok = false;
				log_msg(LOG_ERR, "EV_ERROR: %s for %" PRIuPTR,
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
					process_timeout(vpn, &event);
					break;
				case EVFILT_SIGNAL:
					switch (event.ident) {
					case SIGUSR1:
						log_stats(vpn);
						break;
					case SIGINT:
					case SIGTERM:
						ok = false;
						log_msg(LOG_NOTICE, "shutting down (signal %u)",
							event.ident);
						return_to_init_state(vpn);
						break;
					default:
						break;
					}

					break;
				default:
					log_msg(LOG_WARNING, "unhandled event type: %d",
						event.filter);
				}
			}
		}
	}

	return ok;
}

int
main(int argc, char *argv[])
{

	const char     *opts;
	int		ch;
	struct vpn_state vpn;
	char           *config_fname;

	opts = "vfc:";
	config_fname = "vpnd.conf";

	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'v':
			vflag++;
			break;
		case 'f':
			fflag = true;
			break;
		case 'c':
			config_fname = optarg;
			break;
		default:
			fprintf(stderr, "usage: vpnd [-vfc]\n");
			fprintf(stderr, "  -f: foreground mode (default: daemon)\n");
			fprintf(stderr, "  -v: verbosity (default: NOTICE; use once for\n");
			fprintf(stderr, "      INFO, multiple times for DEBUG)\n");
			fprintf(stderr, "  -c: config file (default: vpnd.conf)\n");
			exit(EXIT_FAILURE);
		}
	}

	switch (vflag) {
	case 0:
		log_upto = LOG_NOTICE;
		break;
	case 1:
		log_upto = LOG_INFO;
		break;
	default:
		log_upto = LOG_DEBUG;
	}

	if (!fflag) {
		char           *ident;
		ident = strrchr(argv[0], '/');
		if (!ident)
			ident = argv[0];
		else
			ident++;
		openlog(ident, LOG_NDELAY | LOG_PID, LOG_DAEMON);
		if (log_upto >= 0)
			setlogmask(LOG_UPTO(log_upto));
	}
	if (init(fflag, config_fname, &vpn)) {
		if (!fflag)
			daemon(0, 0);

		return run(&vpn) ? EXIT_SUCCESS : EXIT_FAILURE;
	} else {
		return EXIT_FAILURE;
	}
}
