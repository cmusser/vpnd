#include <sys/event.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
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

/* FSM states */
typedef enum {
	INIT,
	KEY_NONE,
	KEY_STARTING,
	KEY_OK,
	KEY_STALE,
	KEY_SWITCHING,
}		vpn_state;

/* message types exchanged between peers */
typedef enum {
	PEER_START,
	KEY_INIT_START,
	KEY_INIT_ACK,
	KEY_INIT_DONE,
	DEBUG_STRING,
	KEY_SWITCH_START,
	KEY_SWITCH_ACK,
	KEY_SWITCH_DONE,
	DATA,
}		message_type;

/* Timers used for retransmits and expiry */
typedef enum {
	RETRANSMIT_PEER_INIT,
	RETRANSMIT_KEY_INIT_START,
	RETRANSMIT_KEY_INIT_ACK,
	RETRANSMIT_KEY_SWITCH_START,
	RETRANSMIT_KEY_SWITCH_ACK,
	KEY_EXPIRY,
}		timer_type;

struct config_param {
	char           *desc;
	char           *name;
	size_t		name_sz;
	char           *value;
	size_t		value_sz;
	char           *default_value;
};

#define PAYLOAD_SZ 1400
/* Message data structure definitions */
struct message {
	message_type	type;
	union {
		uint32_t	init_random;
		unsigned char	dh_pk[crypto_box_PUBLICKEYBYTES];
		unsigned char	data[PAYLOAD_SZ];
	};
};

/* Finite state machine state data. */
struct vpn_fsm {
	vpn_state	state;
	uint32_t	r;
	unsigned char	dh_sk[crypto_box_SECRETKEYBYTES];
	unsigned char	dh_pk[crypto_box_PUBLICKEYBYTES];
	unsigned char	cur_key[crypto_box_BEFORENMBYTES];
	unsigned char	new_key[crypto_box_BEFORENMBYTES];
	unsigned char	nonce[crypto_box_NONCEBYTES];
	int		s;
};

int		log_upto;
bool		fflag = false;
int		dflag = 0;
void		log_msg   (int priority, const char *msg,...);
char           *get_value(char *line, size_t len);
bool		init      (char *config_fname, struct vpn_fsm *fsm);
void		sock_input(struct vpn_fsm *fsm);
void		expire_timer(struct vpn_fsm *fsm, struct kevent *kev);
void		dump_state(struct vpn_fsm *fsm);
bool		run       (struct vpn_fsm *fsm);

void
log_msg(int priority, const char *msg,...)
{
	va_list		ap;

	va_start(ap, msg);
	if (fflag) {
		if (priority <= log_upto) {
			vfprintf(stderr, msg, ap);
			fprintf(stderr, "\n");
		}
	} else {
		vsyslog(priority, msg, ap);
	}
	va_end(ap);
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
		}
		inet_ntop(addrinfo->ai_family, addr,
			  addr_str, addrinfo->ai_addrlen);

		snprintf(info_str, info_str_sz, "%s:%u", addr_str, port);
	}
	return ok;
}

bool
init(char *config_fname, struct vpn_fsm *fsm)
{
	bool		ok = true;
	FILE           *config_file;
	char		line      [256] = {'\0'};
	char		local_sk_hex[(crypto_box_SECRETKEYBYTES * 2) + 1] = {'\0'};
	char		local_port[6] = {'\0'};
	char		remote_pk_hex[(crypto_box_PUBLICKEYBYTES * 2) + 1] = {'\0'};
	char		remote_host[INET6_ADDRSTRLEN] = {'\0'};
	char		remote_port[6] = {'\0'};
	struct config_param c[] = {
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
	};

	size_t		bin_len;
	unsigned char	local_sk_bin[crypto_box_SECRETKEYBYTES];
	unsigned char	remote_pk_bin[crypto_box_PUBLICKEYBYTES];
	unsigned int	i;
	struct addrinfo *local_addrinfo = NULL;
	char		local_info[INET6_ADDRSTRLEN + 7];
	struct addrinfo *remote_addrinfo = NULL;
	char		remote_info[INET6_ADDRSTRLEN + 7];

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
					strlcpy(c[i].value, c[i].default_value,
						c[i].value_sz);
				}
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
			sodium_init();
			bzero(fsm->nonce, sizeof(fsm->nonce));
			if (crypto_box_beforenm(fsm->cur_key, remote_pk_bin,
						local_sk_bin) != 0) {
				ok = false;
				log_msg(LOG_ERR, "couldn't create shared key");
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
			if ((fsm->s = socket(remote_addrinfo->ai_family,
					     remote_addrinfo->ai_socktype,
				     remote_addrinfo->ai_protocol)) == -1) {
				ok = false;
				log_msg(LOG_ERR, "couldn't create socket: %s",
					strerror(errno));
			}
		}
		if (ok) {
			if (bind(fsm->s, local_addrinfo->ai_addr,
				 local_addrinfo->ai_addrlen) == -1) {
				ok = false;
				close(fsm->s);
				log_msg(LOG_ERR, "couldn't bind to %s: %s",
					local_info, strerror(errno));
			}
		}
		if (ok) {
			if (connect(fsm->s, remote_addrinfo->ai_addr,
				    remote_addrinfo->ai_addrlen) < 0) {
				ok = false;
				close(fsm->s);
				log_msg(LOG_ERR, "couldn't connect to %s: %s",
					remote_info, strerror(errno));
			}
		}
		if (ok)
			log_msg(LOG_NOTICE, "connected: %s <--> %s", local_info, remote_info);
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
sock_input(struct vpn_fsm *fsm)
{
	bool		ok;
	unsigned char	ciphertext[crypto_box_MACBYTES + 128];
	unsigned char	plaintext[128];
	size_t		ciphertext_len;

	ok = true;

	if ((ciphertext_len = read(fsm->s, ciphertext, sizeof(ciphertext))) == -1) {
		ok = false;
		log_msg(LOG_ERR, "read failed: %s", strerror(errno));
	}
	if (ok) {
		log_msg(LOG_NOTICE, "read: %d", ciphertext_len);
		if (crypto_box_open_easy_afternm(plaintext, ciphertext,
			   ciphertext_len, fsm->nonce, fsm->cur_key) != 0) {
			ok = false;
			log_msg(LOG_ERR, "decryption failed");
		}
	}
	if (ok)
		log_msg(LOG_NOTICE, "read %d bytes: %s", ciphertext_len, plaintext);

}

void
expire_timer(struct vpn_fsm *fsm, struct kevent *kev)
{
	bool		ok;
	const unsigned char plaintext[128];
	char		hostname  [64];
	unsigned char	ciphertext[crypto_box_MACBYTES + 128];
	size_t		plaintext_len, ciphertext_len;

	ok = true;
	gethostname(hostname, sizeof(hostname));
	snprintf((char *)plaintext, sizeof(plaintext), "from: %s", hostname);
	plaintext_len = strlen((char *)plaintext);
	ciphertext_len = plaintext_len + crypto_box_MACBYTES;

	if (crypto_box_easy_afternm(ciphertext, plaintext,
			    plaintext_len, fsm->nonce, fsm->cur_key) != 0) {
		ok = false;
		log_msg(LOG_ERR, "encryption failed");
	}
	if (ok) {
		log_msg(LOG_NOTICE, "sending: %d (from %d)", ciphertext_len,
			plaintext_len);
		if (write(fsm->s, ciphertext, ciphertext_len) == -1)
			log_msg(LOG_ERR, "write failed: %s", strerror(errno));
	}
}

void
dump_state(struct vpn_fsm *fsm)
{

}

bool
run(struct vpn_fsm *fsm)
{
	bool		ok;
	struct kevent	changes[2], event;
	int		kq        , nev;
	ok = true;

	EV_SET(&changes[0], 1, EVFILT_TIMER, EV_ADD | EV_ENABLE, 0, 2000, 0);
	EV_SET(&changes[1], fsm->s, EVFILT_READ, EV_ADD | EV_ENABLE, 0, 0, 0);

	if ((kq = kqueue()) == -1) {
		ok = false;
		log_msg(LOG_ERR, "kqueue(): %s", strerror(errno));
	}
	while (ok) {
		nev = kevent(kq, changes, 2, &event, 1, NULL);
		if (nev < 0) {
			ok = false;
			log_msg(LOG_ERR, "kevent: %s", strerror(errno));
		} else {
			if (event.flags & EV_ERROR) {
				ok = false;
				log_msg(LOG_ERR, "EV_ERROR: %s for %lu",
					strerror(event.data), event.ident);
			} else {
				switch (event.filter) {
				case EVFILT_READ:
					sock_input(fsm);
					break;
				case EVFILT_TIMER:
					expire_timer(fsm, &event);
					break;
				case EVFILT_SIGNAL:
					dump_state(fsm);
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
	struct vpn_fsm	fsm;
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
			fprintf(stderr, "usage: radnsd [-fdc]\n");
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
	if (init(config_fname, &fsm)) {
		if (!fflag)
			daemon(0, 0);

		return run(&fsm) ? EXIT_SUCCESS : EXIT_FAILURE;
	} else {
		return EXIT_FAILURE;
	}
}
