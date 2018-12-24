#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include "sodium.h"
#include "diag.h"
#include "nonce.h"
#include "os.h"
#include "proto.h"
#include "util.h"

#define PEER_MAX_HEARTBEAT_INTERVAL_SECS 20
#define MAX_HOST_GW_INIT_SECS 120
#define PEER_INIT_RETRANS_INTERVAL_SECS 5
#define PEER_INIT_RETRANS_INTERVAL_NSECS 0
#define KEY_MGMT_RETRANS_INTERVAL_SECS 0
#define KEY_MGMT_RETRANS_INTERVAL_NSECS 500000000
#define HEARTBEAT_INTERVAL_SECS 10
#define HEARTBEAT_INTERVAL_NSECS 0

typedef enum {
	MASTER,
	SLAVE,
	TIE,
}		vpn_key_role;

vpn_key_role	peer_id_compare(struct vpn_state *vpn);
bool		check_peer_alive(struct vpn_state *vpn, uintptr_t timer_id, struct timespec now);
void		manage_host_networking(struct vpn_state *vpn);
void		manage_host_gw_networking(struct vpn_state *vpn);
void		manage_net_gw_networking(struct vpn_state *vpn);
void		manage_network_config(struct vpn_state *vpn);


void
generate_peer_id(struct vpn_state *vpn)
{
	randombytes_buf(&vpn->peer_id, sizeof(vpn->peer_id));
	vpn->tx_peer_info.peer_id = htonl(vpn->peer_id);
}

struct timespec
get_timeout_interval(struct vpn_state *vpn, timer_type ttype)
{
	struct timespec	interval;

	switch (ttype) {
	case RETRANSMIT_PEER_INIT:
		interval.tv_sec = PEER_INIT_RETRANS_INTERVAL_SECS;
		interval.tv_nsec = PEER_INIT_RETRANS_INTERVAL_NSECS;
		break;
	case RETRANSMIT_KEY_SWITCH_START:
	case RETRANSMIT_KEY_SWITCH_ACK:
	case RETRANSMIT_KEY_READY:
		interval.tv_sec = KEY_MGMT_RETRANS_INTERVAL_SECS;
		interval.tv_nsec = KEY_MGMT_RETRANS_INTERVAL_NSECS;
		break;
	case ACTIVE_HEARTBEAT:
		interval.tv_sec = HEARTBEAT_INTERVAL_SECS;
		interval.tv_nsec = HEARTBEAT_INTERVAL_NSECS;
		break;
	default:
		interval.tv_sec = 0;
		interval.tv_nsec = 0;
		log_msg(vpn, LOG_WARNING, "no interval for %s timer type",
			TIMER_TYPE_STR(ttype));
	}

	return interval;
}

vpn_key_role
peer_id_compare(struct vpn_state *vpn)
{
	uint32_t	hostorder_remote_peer_id;

	hostorder_remote_peer_id = ntohl(vpn->rx_peer_info.peer_id);
	if (hostorder_remote_peer_id > vpn->peer_id) {
		log_msg(vpn, LOG_NOTICE, "%s: will be key master", VPN_ROLE_STR(vpn->role));
		return MASTER;
		change_state(vpn, MASTER_KEY_STALE);
	} else if (hostorder_remote_peer_id < vpn->peer_id) {
		log_msg(vpn, LOG_NOTICE, "%s: will be key slave", VPN_ROLE_STR(vpn->role));
		return SLAVE;
	} else {
		log_msg(vpn, LOG_NOTICE, "%s: got same peer ID from remote, trying again.",
			VPN_ROLE_STR(vpn->role));
		return TIE;
	}

}

void
return_to_init_state(struct vpn_state *vpn)
{
	memcpy(vpn->cur_shared_key, vpn->orig_shared_key,
	       sizeof(vpn->cur_shared_key));
	vpn->shared_key_is_ephemeral = false;
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
		vpn->shared_key_is_ephemeral = true;
		purge_late(vpn);
		break;
	case ACTIVE_SLAVE:
		vpn->shared_key_is_ephemeral = true;
		purge_late(vpn);
		/* Fallthrough */
	case ACTIVE_MASTER:
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
			vpn->tx_packets++;
			vpn->key_sent_packet_count++;
		}

	}
	sodium_increment(vpn->nonce, sizeof(vpn->nonce));
	vpn->nonce_incr_count++;

	if (vpn->nonce_incr_count == vpn->nonce_reset_incr)
		write_nonce(vpn, LOCAL);

	return ok;
}

void
tx_peer_info(struct vpn_state *vpn)
{
	bool		ok;
	struct vpn_msg	msg;
	timer_type	ttype;

	ok = true;
	msg.type = PEER_INFO;

	switch (vpn->state) {
	case INIT:
		ttype = RETRANSMIT_PEER_INIT;
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		ttype = ACTIVE_HEARTBEAT;
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
			add_timer(vpn, ttype);
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
			add_timer(vpn, ttype);
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
			add_timer(vpn, RETRANSMIT_KEY_READY);
	}
}

void
process_peer_info(struct vpn_state *vpn, struct vpn_msg *msg, struct sockaddr *peer_addr, socklen_t peer_addr_len)
{
	memcpy(&vpn->rx_peer_info, msg->data, sizeof(vpn->rx_peer_info));

	switch (vpn->state) {
	case HOST_WAIT:
		manage_ext_sock_connection(vpn, peer_addr, peer_addr_len);
		switch (peer_id_compare(vpn)) {
		case MASTER:
			change_state(vpn, MASTER_KEY_STALE);
			break;
		case SLAVE:
			change_state(vpn, INIT);
			break;
		case TIE:
			generate_peer_id(vpn);
			change_state(vpn, INIT);
			break;
		}

		break;
	case INIT:
		switch (peer_id_compare(vpn)) {
		case MASTER:
			change_state(vpn, MASTER_KEY_STALE);
			break;
		case SLAVE:
			/* Stay in INIT; waiting for KEY_SWITCH_START */
			break;
		case TIE:
			generate_peer_id(vpn);
			tx_peer_info(vpn);
			break;
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
	vpn->rx_data_bytes += data_len;

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
			vpn->rx_data_bytes += data_len;
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
			vpn->tx_data_bytes += data_len;
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
		ok = check_nonce(vpn, rx_nonce);
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
		vpn->rx_packets++;
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

	client_fd = accept(vpn->stats_sock, NULL, NULL);
	if (client_fd > 0) {
		tx_graphite_stats(vpn, client_fd);
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
	if (fgets(tx_data, sizeof(msg.data) - 1, stdin) == NULL) {
		log_msg(vpn, LOG_NOTICE, "received EOF on stdin");
		fclose(stdin);
	} else {
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
				vpn->tx_data_bytes += data_len;
		}

	}
}

bool
check_peer_alive(struct vpn_state *vpn, uintptr_t timer_id, struct timespec now)
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
			log_msg(vpn, LOG_ERR, "%s: peer died after %s (checked before %s).",
				VPN_STATE_STR(vpn->state),
			 time_str(cur_sess_active_secs, cur_sess_active_str,
				  sizeof(cur_sess_active_str)),
				TIMER_TYPE_STR(timer_id));
		}
		/* Always return to init if dead */
		return_to_init_state(vpn);
	}
	return !vpn->peer_died;
}

void
process_timeout(struct vpn_state *vpn, uintptr_t timer_id)
{
	struct timespec	now;
	time_t		inactive_secs, cur_key_age;
	char		inactive_secs_str[32];
	struct sockaddr_in null_addr = {0};

	get_cur_monotonic(&now);

	if (timer_id == RETRANSMIT_PEER_INIT) {
		if (vpn->state == INIT) {
			if (vpn->role == HOST_GW) {
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
					vpn->peer_init_retransmits++;
					log_retransmit(vpn, PEER_INFO);
					tx_peer_info(vpn);
				}
			} else {
				vpn->peer_init_retransmits++;
				log_retransmit(vpn, PEER_INFO);
				tx_peer_info(vpn);
			}
		} else {
			log_skip_retransmit(vpn, timer_id);
		}
	} else if (check_peer_alive(vpn, timer_id, now)) {
		switch (timer_id) {
		case RETRANSMIT_KEY_SWITCH_START:
			if (vpn->state == MASTER_KEY_STALE) {
				vpn->key_switch_start_retransmits++;
				log_retransmit(vpn, KEY_SWITCH_START);
				tx_new_public_key(vpn);
			} else {
				log_skip_retransmit(vpn, timer_id);
			}
			break;
		case RETRANSMIT_KEY_SWITCH_ACK:
			if (vpn->state == SLAVE_KEY_SWITCHING) {
				vpn->key_switch_ack_retransmits++;
				log_retransmit(vpn, KEY_SWITCH_ACK);
				tx_new_public_key(vpn);
			} else {
				log_skip_retransmit(vpn, timer_id);
			}
			break;
		case RETRANSMIT_KEY_READY:
			if (vpn->state == MASTER_KEY_READY) {
				vpn->key_ready_retransmits++;
				log_retransmit(vpn, KEY_READY);
				tx_key_ready(vpn);
			} else {
				log_skip_retransmit(vpn, timer_id);
			}
			break;
		case ACTIVE_HEARTBEAT:
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
			break;
		default:
			log_msg(vpn, LOG_ERR, "%s: unhandled timer id: %s",
			VPN_STATE_STR(vpn->state), TIMER_TYPE_STR(timer_id));
		}
	}
}

void
manage_host_networking(struct vpn_state *vpn)
{
	char		host_addr_str[INET6_ADDRSTRLEN];
	char		net_addr_str[INET6_ADDRSTRLEN];
	bool		ok = true;
	bool		manage_resolver;
	char		resolv_data_filename[512] = {'\0'};
	int		resolv_data_fd;
	char		resolv_data_str[256];
	char		resolv_addr_str[INET6_ADDRSTRLEN];
	char		resolvconf_cmd[1024];
	FILE           *cmd_fd;
	char		cmd_out   [256];
	char           *newline;

	if (inet_ntop(vpn->rx_peer_info.host_addr_family, &vpn->rx_peer_info.host_addr,
		      host_addr_str, sizeof(host_addr_str)) == NULL) {
		log_msg(vpn, LOG_WARNING, "%s: host address on remote network unconfigured "
			"or invalid", VPN_ROLE_STR(vpn->role));
		return;
	}
	if (inet_ntop(vpn->rx_peer_info.remote_net_addr_family, vpn->rx_peer_info.remote_net,
		      net_addr_str, sizeof(net_addr_str)) == NULL) {
		log_msg(vpn, LOG_WARNING, "%s: remote network address unconfigured or invalid",
			VPN_ROLE_STR(vpn->role));
		return;
	}
	manage_resolver = (vpn->rx_peer_info.resolv_addr_family == AF_INET ||
			   vpn->rx_peer_info.resolv_addr_family == AF_INET6);

	switch (vpn->state) {
	case INIT:
		configure_route_on_host(vpn, net_addr_str, ROUTE_DELETE);
		if (manage_resolver)
			snprintf(resolvconf_cmd, sizeof(resolvconf_cmd), "%s -d %s 2>&1",
				 vpn->resolvconf_path, vpn->tun_name);
		break;

	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		set_tun_addrs(vpn, host_addr_str, HOST_LOCAL);
		configure_route_on_host(vpn, net_addr_str, ROUTE_ADD);
		if (manage_resolver) {
			snprintf(resolv_data_filename, sizeof(resolv_data_filename),
			       "/tmp/vpnd_resolv_%s.XXXXXX", vpn->tun_name);
			resolv_data_fd = mkstemp(resolv_data_filename);
			if (resolv_data_fd == -1) {
				ok = false;
				log_msg(vpn, LOG_ERR, "creating of resolvconf temp data failed -- %s",
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
		}
		break;

	default:
		ok = false;
		log_msg(vpn, LOG_ERR, "cannot manage %s networking in %s state",
			VPN_ROLE_STR(vpn->role), VPN_STATE_STR(vpn->state));
	}

	if (manage_resolver && ok) {
		log_msg(vpn, LOG_NOTICE, "%s: %s", VPN_STATE_STR(vpn->state), resolvconf_cmd);
		if ((cmd_fd = popen(resolvconf_cmd, "r")) == NULL) {
			log_msg(vpn, LOG_ERR, "spawn of \"%s\" failed: %s", resolvconf_cmd,
				strerror(errno));
		} else {
			while (fgets(cmd_out, sizeof(cmd_out), cmd_fd) != NULL) {
				newline = strrchr(cmd_out, '\n');
				if (newline)
					*newline = '\0';
				log_msg(vpn, LOG_NOTICE, "==> %s", cmd_out);
			}

			if (ferror(cmd_fd))
				log_msg(vpn, LOG_ERR, "reading subprocess output: %s", strerror(errno));

			pclose(cmd_fd);
		}
		unlink(resolv_data_filename);
	}
}

void
manage_host_gw_networking(struct vpn_state *vpn)
{
	char		host_addr_str[INET6_ADDRSTRLEN];

	if (inet_ntop(vpn->tx_peer_info.host_addr_family, &vpn->tx_peer_info.host_addr,
		      host_addr_str, sizeof(host_addr_str)) == NULL) {
		log_msg(vpn, LOG_WARNING, "%s: client host address unconfigured or invalid",
			VPN_ROLE_STR(vpn->role));
		return;
	}
	switch (vpn->state) {
	case INIT:
		if (!vpn->already_ip_forwarding)
			set_forwarding(vpn, AF_INET, false);
		if (!vpn->already_ip6_forwarding)
			set_forwarding(vpn, AF_INET6, false);
		break;
	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		set_forwarding(vpn, AF_INET, true);
		set_forwarding(vpn, AF_INET6, true);
		set_tun_addrs(vpn, host_addr_str, HOST_REMOTE);
		break;
	default:
		log_msg(vpn, LOG_ERR, "cannot manage %s networking in %s state",
			VPN_ROLE_STR(vpn->role), VPN_STATE_STR(vpn->state));
	}
}

void
manage_net_gw_networking(struct vpn_state *vpn)
{
	switch (vpn->state) {
	case INIT:
		if (!vpn->already_ip_forwarding)
			set_forwarding(vpn, AF_INET, false);
		if (!vpn->already_ip6_forwarding)
			set_forwarding(vpn, AF_INET6, false);

		set_tun_state(vpn, INTF_DOWN);
		configure_route_on_net_gw(vpn, ROUTE_DELETE);
		break;

	case ACTIVE_MASTER:
	case ACTIVE_SLAVE:
		set_forwarding(vpn, AF_INET, true);
		set_forwarding(vpn, AF_INET6, true);
		set_tun_state(vpn, INTF_UP);
		configure_route_on_net_gw(vpn, ROUTE_ADD);
		break;

	default:
		log_msg(vpn, LOG_ERR, "cannot manage %s networking in %s state",
			VPN_ROLE_STR(vpn->role), VPN_STATE_STR(vpn->state));
	}
}

void
manage_network_config(struct vpn_state *vpn)
{
	switch (vpn->role) {
	case HOST:
		manage_host_networking(vpn);
		break;
	case HOST_GW:
		manage_host_gw_networking(vpn);
		break;
	case NET_GW:
		manage_net_gw_networking(vpn);
	default:
		break;
	}
}
