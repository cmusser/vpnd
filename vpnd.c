#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

/* VPN states */
typedef enum {
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
	PEER_ID,
	KEY_SWITCH_START,
	KEY_SWITCH_ACK,
	KEY_READY,
	DEBUG_STRING,
	DATA,
	MSG_TYPE_LAST_PLUS_ONE,
}		message_type;

const char     *message_type_string_array[MSG_TYPE_LAST_PLUS_ONE] =
{
	"PEER_ID",
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

#define DATA_SZ 1400
/* Message data structure definitions */
struct vpn_msg {
	unsigned char	type;
	unsigned char	data[DATA_SZ];
};

/* Finite state machine state data. */
struct vpn_state {
	vpn_state	state;
	uint32_t	peer_id;
	uint32_t	remote_peer_id;
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
	unsigned char	remote_nonce[crypto_box_NONCEBYTES];
	int		ext_sock;
	int		ctrl_sock;
	int		stats_sock;
	struct kevent	kev_changes[6];
	uint32_t	kev_change_count;
	uint32_t	rx_bytes;
	uint32_t	tx_bytes;
	uint32_t	peer_init_retransmits;
	uint32_t	key_switch_start_retransmits;
	uint32_t	key_switch_ack_retransmits;
	uint32_t	key_ready_retransmits;
	uint32_t	keys_used;
	uint32_t	sess_starts;
	bool		peer_died;
};

int		log_upto;
bool		fflag = false;
int		dflag = 0;
void		log_msg   (int priority, const char *msg,...);
char           *time_str(time_t time, char *time_str, size_t len);
char           *get_value(char *line, size_t len);
bool		init      (bool fflag, char *config_fname, struct vpn_state *vpn);
void		start_protocol(struct vpn_state *vpn);
void		change_state(struct vpn_state *vpn, vpn_state new_state);
void		log_invalid_msg_for_state(struct vpn_state *vpn, message_type msg_type);
void		log_retransmit(struct vpn_state *vpn, message_type msg_type);
void		add_timer (struct vpn_state *vpn, timer_type ttype, intptr_t timeout_interval);
bool		tx_encrypted(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);
void		tx_peer_id(struct vpn_state *vpn);
void		tx_new_public_key(struct vpn_state *vpn);
void		tx_key_ready(struct vpn_state *vpn);
void		process_peer_id(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_key_switch_start(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_key_switch_ack(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_key_ready(struct vpn_state *vpn, struct vpn_msg *msg);
void		process_debug_string(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);

void		process_rx_data(struct vpn_state *vpn, struct vpn_msg *msg, size_t data_len);
void		ext_sock_input(struct vpn_state *vpn);
void		ctrl_sock_input(struct vpn_state *vpn);
void		stats_sock_input(struct vpn_state *vpn);
void		stdin_input(struct vpn_state *vpn);
bool		dead_peer_restart(struct vpn_state *vpn, struct timespec now);
void		process_timeout(struct vpn_state *vpn, struct kevent *kev);
void		log_state (struct vpn_state *vpn);
bool		run       (struct vpn_state *vpn);

void
log_msg(int priority, const char *msg,...)
{
	va_list		ap;
	time_t		now;
	struct tm	now_tm;
	char		timestamp_str[32];
	char		msg_str   [256];

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
get_addrinfo(struct addrinfo **addrinfo_p, char *host, char *port_str, char *info_str, size_t info_str_sz, bool passive)
{
	bool		ok;
	struct addrinfo	hints = {'\0'};
	struct addrinfo *addrinfo;
	void           *addr;
	uint16_t	port;
	char		addr_str  [INET6_ADDRSTRLEN];

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
	if (ok) {
		addrinfo = *addrinfo_p;
		switch (addrinfo->ai_family) {
		case AF_INET:
			addr = &((struct sockaddr_in *)addrinfo->ai_addr)->sin_addr;
			port = ntohs(((struct sockaddr_in *)addrinfo->ai_addr)->sin_port);
			break;
		case AF_INET6:
			addr = &((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_addr;
			port = ntohs(((struct sockaddr_in6 *)addrinfo->ai_addr)->sin6_port);
			break;
		default:
			ok = false;
			log_msg(LOG_ERR, "invalid address family: %d", addrinfo->ai_family);
		}
	}
	if (ok) {
		inet_ntop(addrinfo->ai_family, addr, addr_str, addrinfo->ai_addrlen);
		snprintf(info_str, info_str_sz, "%s:%u", addr_str, port);
	}
	return ok;
}

bool
init(bool fflag, char *config_fname, struct vpn_state *vpn)
{
	bool		ok = true;
	FILE           *config_file;
	char		line      [256] = {'\0'};
	char		tunnel_device[32] = {'\0'};
	char		local_sk_hex[(crypto_box_SECRETKEYBYTES * 2) + 1] = {'\0'};
	char		local_port[6] = {'\0'};
	char		remote_pk_hex[(crypto_box_PUBLICKEYBYTES * 2) + 1] = {'\0'};
	char		remote_host[INET6_ADDRSTRLEN] = {'\0'};
	char		remote_port[6] = {'\0'};
	char		max_key_age_secs[16] = {'\0'};
	char		max_key_sent_packet_count[16] = {'\0'};
	const char     *num_err;
	struct config_param c[] = {
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
		{"max key age (secs.)", "max_key_age:", sizeof("max_key_age:"),
		max_key_age_secs, sizeof(max_key_age_secs), "60"},
		{"max key packets", "max_key_packets:", sizeof("max_key_packets:"),
		max_key_sent_packet_count, sizeof(max_key_sent_packet_count), "100000"},
	};

	size_t		bin_len;
	unsigned char	local_sk_bin[crypto_box_SECRETKEYBYTES];
	unsigned char	remote_pk_bin[crypto_box_PUBLICKEYBYTES];
	unsigned int	i , j;
	struct addrinfo *local_addrinfo = NULL;
	char		local_info[INET6_ADDRSTRLEN + 7];
	struct addrinfo *remote_addrinfo = NULL;
	char		remote_info[INET6_ADDRSTRLEN + 7];
	int		ioctl_data;
	struct sockaddr_un stats_addr;
	char           *stats_path = "/var/run/vpnd_stats.sock";

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
		 */
		for (i = 0; i < COUNT_OF(c); i++) {

			if (strlen(c[i].value) == 0) {
				if (c[i].default_value == NULL) {
					ok = false;
					log_msg(LOG_ERR, "%s not specified", c[i].desc);
				} else {
					if (strcmp(c[i].name, "stats_prefix:") == 0) {
						gethostname(c[i].value, c[i].value_sz);
						for (j = 0; j < c[i].value_sz; j++) {
							if (c[i].value[j] == '.')
								c[i].value[j] = '_';
						}
					} else {
						strlcpy(c[i].value, c[i].default_value,
							c[i].value_sz);
					}
				}
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
			if (sodium_init() == -1) {
				ok = false;
				log_msg(LOG_ERR, "Failed to initialize crypto library");
			}
		}
		/* Setup initial crypto box */
		if (ok) {
			if (sodium_hex2bin(local_sk_bin, sizeof(local_sk_bin),
				    local_sk_hex, sizeof(local_sk_hex), ":",
					   &bin_len, NULL) != 0) {
				ok = false;
				log_msg(LOG_ERR, "invalid local secret key");
			}
		}
		if (ok) {
			if (sodium_hex2bin(remote_pk_bin, sizeof(remote_pk_bin),
				  remote_pk_hex, sizeof(remote_pk_hex), ":",
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
		/* Set up communication socket */
		if (ok) {
			ok = get_addrinfo(&local_addrinfo, NULL, local_port,
				      local_info, sizeof(local_info), true);
		}
		if (ok) {
			ok = get_addrinfo(&remote_addrinfo, remote_host, remote_port,
				   remote_info, sizeof(remote_info), false);
		}
		if (ok) {
			if ((vpn->ext_sock = socket(remote_addrinfo->ai_family,
					       remote_addrinfo->ai_socktype,
				     remote_addrinfo->ai_protocol)) == -1) {
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
					local_info, strerror(errno));
			}
		}
		if (ok) {
			if (connect(vpn->ext_sock, remote_addrinfo->ai_addr,
				    remote_addrinfo->ai_addrlen) < 0) {
				ok = false;
				close(vpn->ext_sock);
				log_msg(LOG_ERR, "couldn't connect to %s: %s",
					remote_info, strerror(errno));
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
		}
		if (bind(vpn->stats_sock, (struct sockaddr *)&stats_addr,
			 sizeof(stats_addr)) == -1) {
			ok = false;
			log_msg(LOG_ERR, "couldn't bind stats socket -- %s",
				strerror(errno));
		}
		if (ok) {
			if (listen(vpn->stats_sock, 5) == -1) {
				ok = false;
				log_msg(LOG_ERR, "couldn't listen stats socket -- %s",
					strerror(errno));
			}
		}
		if (ok) {
			log_msg(LOG_NOTICE, "connected: %s <--> %s", local_info, remote_info);
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
			if (fflag) {
				EV_SET(&vpn->kev_changes[4], STDIN_FILENO,
				  EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);
				vpn->kev_change_count++;
			}
			vpn->rx_bytes = vpn->tx_bytes =
				vpn->peer_init_retransmits =
				vpn->key_switch_start_retransmits =
				vpn->key_switch_ack_retransmits =
				vpn->key_ready_retransmits =
				vpn->keys_used = vpn->sess_starts =
				vpn->sess_active_secs = vpn->inactive_secs = 0;

			vpn->peer_died = false;
			clock_gettime(CLOCK_MONOTONIC, &vpn->sess_end_ts);
			start_protocol(vpn);
		}
	} else {
		ok = false;
		log_msg(LOG_ERR, "couldn't open config file %s: %s",
			config_fname, strerror(errno));
	}

	if (remote_addrinfo != NULL)
		freeaddrinfo(remote_addrinfo);

	return ok;
}

void
start_protocol(struct vpn_state *vpn)
{
	vpn->state = INIT;
	randombytes_buf(&vpn->peer_id, sizeof(vpn->peer_id));
	randombytes_buf(vpn->nonce, sizeof(vpn->nonce));
	bzero(vpn->remote_nonce, sizeof(vpn->remote_nonce));
	tx_peer_id(vpn);
}

void
change_state(struct vpn_state *vpn, vpn_state new_state)
{
	time_t		inactive_secs;
	char		inactive_str[32];

	log_msg(LOG_INFO, "%s --> %s", VPN_STATE_STR(vpn->state),
		VPN_STATE_STR(new_state));
	vpn->state = new_state;

	if (vpn->state == ACTIVE_MASTER || vpn->state == ACTIVE_SLAVE) {
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
			log_msg(LOG_NOTICE, "%s: session #%" PRIu32 " started "
				"in %s",
				VPN_STATE_STR(vpn->state),
				vpn->sess_starts,
				time_str(inactive_secs, inactive_str, sizeof(inactive_str)));
		}
	}
}

void
log_invalid_msg_for_state(struct vpn_state *vpn, message_type msg_type)
{
	log_msg(LOG_ERR, "%s: %s (%d) message invalid for state",
		VPN_STATE_STR(vpn->state), MSG_TYPE_STR(msg_type), msg_type);
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

		if (writev(vpn->ext_sock, tx_iovec, COUNT_OF(tx_iovec)) == -1) {
			ok = false;
			log_msg(LOG_ERR, "%sL write failed -- %s",
				VPN_STATE_STR(vpn->state), strerror(errno));
		} else {
			vpn->key_sent_packet_count++;
		}

	}
	sodium_increment(vpn->nonce, sizeof(vpn->nonce));

	return ok;
}

void
tx_peer_id(struct vpn_state *vpn)
{
	bool		ok;
	struct vpn_msg	msg;
	uint32_t	peer_id;
	timer_type	ttype;
	intptr_t	timeout_interval;

	ok = true;
	switch (vpn->state) {
	case INIT:
		ttype = RETRANSMIT_PEER_INIT;
		timeout_interval = 5000;
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		ttype = ACTIVE_HEARTBEAT;
		timeout_interval = 10000;
		break;
	default:
		ok = false;
		log_msg(LOG_ERR, "%s: may not transmit peer ID in state",
			VPN_STATE_STR(vpn->state));
	}

	if (ok) {
		msg.type = PEER_ID;
		peer_id = htonl(vpn->peer_id);
		memcpy(&msg.data, &peer_id, sizeof(peer_id));
		if (tx_encrypted(vpn, &msg, sizeof(vpn->peer_id)))
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
		log_msg(LOG_ERR, "%s: may not transmit public key in state",
			VPN_STATE_STR(vpn->state));
	}

	if (ok) {
		msg.type = type;
		memcpy(msg.data, vpn->new_public_key, sizeof(vpn->new_public_key));
		if (tx_encrypted(vpn, &msg, sizeof(vpn->new_public_key)))
			add_timer(vpn, ttype, 5000);
	}
}

void
tx_key_ready(struct vpn_state *vpn)
{
	bool		ok;
	struct vpn_msg	msg;
	message_type	type;

	ok = true;
	switch (vpn->state) {
	case MASTER_KEY_STALE:
		type = KEY_READY;
		break;
	default:
		ok = false;
		log_msg(LOG_ERR, "%s: may not transmit KEY_READY in state",
			VPN_STATE_STR(vpn->state));
	}

	if (ok) {
		msg.type = type;
		if (tx_encrypted(vpn, &msg, 0))
			add_timer(vpn, ACTIVE_HEARTBEAT, 10000);
	}
}

void
process_peer_id(struct vpn_state *vpn, struct vpn_msg *msg)
{
	uint32_t	tmp_remote_peer_id;

	switch (vpn->state) {
	case INIT:
		memcpy(&tmp_remote_peer_id, msg->data, sizeof(tmp_remote_peer_id));
		vpn->remote_peer_id = ntohl(tmp_remote_peer_id);
		if (vpn->remote_peer_id > vpn->peer_id) {
			log_msg(LOG_INFO, "will be key master");
			change_state(vpn, MASTER_KEY_STALE);
			crypto_box_keypair(vpn->new_public_key, vpn->new_secret_key);
			tx_new_public_key(vpn);
		} else if (vpn->remote_peer_id < vpn->peer_id) {
			/* Stay in INIT state */
			log_msg(LOG_INFO, "will be key slave");
		} else {
			log_msg(LOG_INFO, "got same peer ID from remote, trying again.");
			randombytes_buf(&vpn->peer_id, sizeof(vpn->peer_id));
			tx_peer_id(vpn);
		}
		break;
	case MASTER_KEY_READY:
		change_state(vpn, ACTIVE_MASTER);
		tx_peer_id(vpn);
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
			tx_new_public_key(vpn);
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
		memcpy(vpn->cur_shared_key, vpn->new_shared_key,
		       sizeof(vpn->cur_shared_key));
		change_state(vpn, ACTIVE_SLAVE);
		tx_peer_id(vpn);
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
		tx_peer_id(vpn);
		/* fallthrough */
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
	unsigned char	ciphertext[crypto_box_MACBYTES + 128];
	struct vpn_msg	msg;
	size_t		rx_len , ciphertext_len;
	unsigned char	rx_nonce[crypto_box_NONCEBYTES];
	char		rx_nonce_str[(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};
	char		remote_nonce_str[(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};
	struct iovec	rx_iovec[2];
	size_t		data_len;

	ok = true;

	rx_iovec[0].iov_base = rx_nonce;
	rx_iovec[0].iov_len = sizeof(rx_nonce);
	rx_iovec[1].iov_base = ciphertext;
	rx_iovec[1].iov_len = sizeof(ciphertext);

	/* TODO: don't assume data is read completely */
	if ((rx_len = readv(vpn->ext_sock, rx_iovec, COUNT_OF(rx_iovec))) == -1) {
		ok = false;
		if (errno != ECONNREFUSED)
			log_msg(LOG_ERR, "%s: error reading from tunnel socket: %s",
				VPN_STATE_STR(vpn->state), strerror(errno));
	}
	if (ok) {
		if (sodium_compare(vpn->remote_nonce, rx_nonce, crypto_box_NONCEBYTES) > -1) {
			ok = false;
			log_msg(LOG_ERR, "%s: received nonce (%s)<= previous (%s)",
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
			log_msg(LOG_ERR, "%s: decryption failed of %zu bytes",
				VPN_STATE_STR(vpn->state), ciphertext_len);
		} else {
			memcpy(vpn->remote_nonce, rx_nonce, sizeof(vpn->remote_nonce));
		}
	}
	if (ok) {
		data_len = ciphertext_len - crypto_box_MACBYTES - sizeof(msg.type);

		log_msg(LOG_INFO, "%s: received %s", VPN_STATE_STR(vpn->state),
			MSG_TYPE_STR(msg.type));

		switch (msg.type) {
		case PEER_ID:
			process_peer_id(vpn, &msg);
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
			 "%s.peer_id_retransmits %" PRIu32 " %lld\n"
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
		//Do nothing.No sense in sending a blank line.
	} else if (strcmp(tx_data, "stats\n") == 0) {
		log_state(vpn);
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
dead_peer_restart(struct vpn_state *vpn, struct timespec now)
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
		memcpy(vpn->cur_shared_key, vpn->orig_shared_key,
		       sizeof(vpn->cur_shared_key));
		start_protocol(vpn);
	}

	return vpn->peer_died;
}

void
process_timeout(struct vpn_state *vpn, struct kevent *kev)
{
	struct timespec	now;
	time_t		age;

	clock_gettime(CLOCK_MONOTONIC, &now);

	switch (kev->ident) {
	case RETRANSMIT_PEER_INIT:
		if (vpn->state == INIT) {
			vpn->peer_init_retransmits++;
			log_retransmit(vpn, PEER_ID);
			tx_peer_id(vpn);
		}
		break;
	case RETRANSMIT_KEY_SWITCH_START:
		if ((!dead_peer_restart(vpn, now)) && vpn->state == MASTER_KEY_STALE) {
			vpn->key_switch_start_retransmits++;
			log_retransmit(vpn, KEY_SWITCH_START);
			tx_new_public_key(vpn);
		}
		break;
	case RETRANSMIT_KEY_SWITCH_ACK:
		if ((!dead_peer_restart(vpn, now)) && vpn->state == SLAVE_KEY_SWITCHING) {
			vpn->key_switch_ack_retransmits++;
			log_retransmit(vpn, KEY_SWITCH_ACK);
			tx_new_public_key(vpn);
		}
		break;
	case RETRANSMIT_KEY_READY:
		if ((!dead_peer_restart(vpn, now)) && vpn->state == MASTER_KEY_READY) {
			vpn->key_ready_retransmits++;
			log_retransmit(vpn, KEY_READY);
			tx_key_ready(vpn);
		}
		break;
	case ACTIVE_HEARTBEAT:
		if (!dead_peer_restart(vpn, now)) {
			switch (vpn->state) {
			case ACTIVE_MASTER:
				tx_peer_id(vpn);
				age = now.tv_sec - vpn->key_start_ts.tv_sec;
				if ((age >= vpn->max_key_age_secs) ||
				    (vpn->key_sent_packet_count
				     >= vpn->max_key_sent_packet_count)) {
					change_state(vpn, MASTER_KEY_STALE);
					crypto_box_keypair(vpn->new_public_key,
						       vpn->new_secret_key);
					tx_new_public_key(vpn);
				}
				break;
			case ACTIVE_SLAVE:
				tx_peer_id(vpn);
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

void
log_state(struct vpn_state *vpn)
{
	struct timespec	now;
	time_t		cur_inactive_secs, cur_sess_active_secs;
	char		cur_inactive_str[32], cur_sess_active_str[32];

	clock_gettime(CLOCK_MONOTONIC, &now);
	cur_inactive_secs = vpn->inactive_secs;
	cur_sess_active_secs = vpn->sess_active_secs;

	if (vpn->state == ACTIVE_MASTER || vpn->state == ACTIVE_SLAVE) {
		cur_sess_active_secs += (now.tv_sec - vpn->sess_start_ts.tv_sec);
	} else {
		cur_inactive_secs += (now.tv_sec - vpn->sess_end_ts.tv_sec);
	}

	log_msg(LOG_NOTICE, "%s:\n"
		"keys used: %" PRIu32 " sessions: %" PRIu32 "\n"
		"time inactive/active: %s/%s\n"
		"data rx/tx: %" PRIu32 "/%" PRIu32 "\n"
		"retransmits (pi/kss/ksa/kr): %" PRIu32
		"/%" PRIu32 "/%" PRIu32 "/%" PRIu32 "\n"
		"last peer message: %" PRIu32 " sec. ago",
		VPN_STATE_STR(vpn->state),
		vpn->keys_used, vpn->sess_starts,
		time_str(cur_inactive_secs, cur_inactive_str,
			 sizeof(cur_inactive_str)),
		time_str(cur_sess_active_secs, cur_sess_active_str,
			 sizeof(cur_sess_active_str)),
		vpn->rx_bytes, vpn->tx_bytes,
		vpn->peer_init_retransmits,
	 vpn->key_switch_start_retransmits, vpn->key_switch_ack_retransmits,
		vpn->key_ready_retransmits,
		(now.tv_sec - vpn->peer_last_heartbeat_ts.tv_sec));
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
					log_state(vpn);
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

	opts = "dfc:";
	config_fname = "vpnd.conf";

	while ((ch = getopt(argc, argv, opts)) != -1) {
		switch (ch) {
		case 'd':
			dflag++;
			break;
		case 'f':
			fflag = true;
			break;
		case 'c':
			config_fname = optarg;
			break;
		default:
			fprintf(stderr, "usage: vpnd [-fdc]\n");
			exit(EXIT_FAILURE);
		}
	}

	switch (dflag) {
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
