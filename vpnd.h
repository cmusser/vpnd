#ifndef _VPND_H_
#define _VPND_H_

#include <sys/socket.h>
#include <sys/types.h>
#ifndef __linux__
#include <sys/event.h>
#endif
#include <sys/un.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <inttypes.h>
#include <stdbool.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "uthash.h"

#define VPND_VERSION "1.1.7"

#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

/* VPN process role */
typedef enum {
	NET_GW,
	HOST_GW,
	HOST,
	VPN_ROLE_LAST_PLUS_ONE,
}		vpn_role;

#ifdef _DECL_STRINGS_
const char     *vpn_role_string_array[VPN_ROLE_LAST_PLUS_ONE] =
{
	"NET GW",
	"HOST GW",
	"HOST",
};
#else
extern const char *vpn_role_string_array[];
#endif

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

#ifdef _DECL_STRINGS_
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
#else
extern const char *vpn_state_string_array[];
#endif

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

#ifdef _DECL_STRINGS_
const char     *message_type_string_array[MSG_TYPE_LAST_PLUS_ONE] =
{
	"PEER_INFO",
	"KEY_SWITCH_START",
	"KEY_SWITCH_ACK",
	"KEY_READY",
	"DEBUG_STRING",
	"DATA",
};
#else
extern const char *message_type_string_array[];
#endif

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

#ifdef _DECL_STRINGS_
const char     *timer_type_string_array[TIMER_TYPE_LAST_PLUS_ONE] =
{
	"RETRANSMIT_PEER_INIT",
	"RETRANSMIT_KEY_SWITCH_START",
	"RETRANSMIT_KEY_SWITCH_ACK",
	"RETRANSMIT_KEY_READY",
	"ACTIVE_HEARTBEAT",
};
#else
extern const char *timer_type_string_array[];
#endif

#define TIMER_TYPE_STR(type) \
	(((type) >= TIMER_TYPE_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : timer_type_string_array[(type)])

/* Nonce types */
typedef enum {
	LOCAL,
	REMOTE,
	NONCE_TYPE_LAST_PLUS_ONE,
}		nonce_type;

#ifdef _DECL_STRINGS_
const char     *nonce_type_string_array[NONCE_TYPE_LAST_PLUS_ONE] =
{
	"local",
	"remote",
};
#else
extern const char *nonce_type_string_array[];
#endif

#define NONCE_TYPE_STR(type) \
	(((type) >= NONCE_TYPE_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : nonce_type_string_array[(type)])

/* Nonce validity status */
typedef enum {
	NONCE_LATE,
	NONCE_ALREADY_USED,
	NONCE_NEW,
	NONCE_STATUS_LAST_PLUS_ONE,
}		nonce_status;

#ifdef _DECL_STRINGS_
const char     *nonce_status_string_array[NONCE_STATUS_LAST_PLUS_ONE] =
{
	"late",
	"already used",
	"new",
};
#else
extern const char *nonce_status_string_array[];
#endif

#define NONCE_STATUS_STR(role) \
	(((role) >= NONCE_STATUS_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : nonce_status_string_array[(role)])

/* Tunnel host address mode */
typedef enum {
	HOST_LOCAL,
	HOST_REMOTE,
	TUN_ADDR_MODE_LAST_PLUS_ONE,
}		tun_addr_mode;

#ifdef _DECL_STRINGS_
const char     *tun_addr_mode_string_array[TUN_ADDR_MODE_LAST_PLUS_ONE] =
{
	"local",
	"remote",
};
#else
extern const char *tun_addr_mode_string_array[];
#endif

#define TUN_ADDR_MODE_STR(role) \
	(((mode) >= TUN_ADDR_MODE_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : tun_addr_mode_string_array[(mode)])

/* Interface actions. */
typedef enum {
	INTF_UP,
	INTF_DOWN,
	INTF_ACTION_LAST_PLUS_ONE,
}		intf_action;

#ifdef _DECL_STRINGS_
const char     *intf_action_string_array[INTF_ACTION_LAST_PLUS_ONE] =
{
	"up",
	"down",
};
#else
extern const char *intf_action_string_array[];
#endif

#define INTF_ACTION_STR(role)			 \
	(((action) >= INTF_ACTION_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : intf_action_string_array[(action)])

/* Route actions */
typedef enum {
	ROUTE_ADD,
	ROUTE_DELETE,
	ROUTE_ACTION_LAST_PLUS_ONE,
}		route_action;

#ifdef _DECL_STRINGS_
const char     *route_action_string_array[ROUTE_ACTION_LAST_PLUS_ONE] =
{
	"add",
	"delete",
};
#else
extern const char *route_action_string_array[];
#endif

#define ROUTE_ACTION_STR(role)			 \
	(((action) >= ROUTE_ACTION_LAST_PLUS_ONE) \
	    ? "UNKNOWN" : route_action_string_array[(action)])


struct vpn_peer_info {
	uint32_t	peer_id;
	uint8_t		host_addr_family;
	uint8_t		host_prefix_len;
	uint8_t		remote_net_addr_family;
	uint8_t		remote_net_prefix_len;
	uint8_t		resolv_addr_family;
	unsigned char	host_addr[sizeof(struct in6_addr)];
	unsigned char	remote_net[sizeof(struct in6_addr)];
	unsigned char	resolv_addr[sizeof(struct in6_addr)];
	char		resolv_domain[32];
};

struct late_nonce {
	unsigned char	nonce[crypto_box_NONCEBYTES];	/* key */
	uint32_t	use_count;	/* value (tracks how many times nonce
					 * was received) */
	UT_hash_handle	hh;	/* makes this structure hashable */
};

/* Finite state machine state data. */
struct vpn_state {
	int		log_upto;
	bool		foreground;
	vpn_role	role;
	vpn_state	state;
	char		tun_name  [8];
	char		local_nonce_filename[256];
	char		remote_nonce_filename[256];
	char		resolvconf_path[256];
	char		ip_path[32];
	bool		already_ip_forwarding;
	bool		already_ip6_forwarding;
	bool		shared_key_is_ephemeral;
	uint32_t	peer_id;
	sa_family_t	remote_network_family;
	uint8_t		remote_network_prefix_len;
	unsigned char	remote_network[sizeof(struct in6_addr)];
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
	struct late_nonce *late_nonces;
	int		ext_sock;
	int		ctrl_sock;
	int		stats_sock;
#ifdef __linux__
	int		event_fd;
	int		signal_fd;
	int		retransmit_peer_init_timer_fd;
	int		retransmit_key_switch_start_timer_fd;
	int		retransmit_key_switch_ack_timer_fd;
	int		retransmit_key_ready_timer_fd;
	int		active_heartbeat_timer_fd;
#else
	struct kevent	kev_changes[8];
	uint32_t	kev_change_count;
#endif
	uint32_t	rx_data_bytes;
	uint32_t	rx_packets;
	uint32_t	rx_late_packets;
	uint32_t	tx_data_bytes;
	uint32_t	tx_packets;
	uint32_t	bad_nonces;
	uint32_t	peer_init_retransmits;
	uint32_t	key_switch_start_retransmits;
	uint32_t	key_switch_ack_retransmits;
	uint32_t	key_ready_retransmits;
	uint32_t	keys_used;
	uint32_t	sess_starts;
	uint32_t	decrypt_failures;
	bool		peer_died;
};

#endif				/* !_VPND_H_ */
