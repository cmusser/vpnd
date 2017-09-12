#include "log.h"
#include "nonce.h"
#include "uthash.h"

bool
check_nonce(struct vpn_state *vpn, unsigned char *nonce)
{
	bool		ok = true;
	int		comparison;
	struct late_nonce *found, *late;
	char		nonce_str [(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};
	char		remote_nonce_str[(crypto_box_NONCEBYTES * 2) + 1] = {'\0'};

	comparison = sodium_compare(vpn->remote_nonce, nonce, crypto_box_NONCEBYTES);
	if (vpn->shared_key_is_ephemeral) {
		switch (comparison) {
		case -1:
			/* received nonce is greater: ok */
			ok = true;
			break;
		case 0:
			/* received nonce is equal: replay */
			ok = false;
			vpn->bad_nonces++;
			log_msg(vpn, LOG_ERR, "%s: received nonce (%s) equal to previous",
				VPN_STATE_STR(vpn->state),
				sodium_bin2hex(nonce_str, sizeof(nonce_str), nonce, sizeof(nonce)));
			break;
		case 1:
			/*
			 * received nonce is less: not found, late; found,
			 * replay
			 */
			HASH_FIND(hh, vpn->late_nonces, nonce, crypto_box_NONCEBYTES, found);
			if (found == NULL) {
				late = (struct late_nonce *)calloc(1, sizeof(struct late_nonce));
				if (late != NULL) {
					ok = true;
					vpn->rx_late_packets++;
					found->use_count = 1;
					HASH_ADD(hh, vpn->late_nonces, nonce, sizeof(struct late_nonce), late);
				} else {
					ok = false;
				}
			} else {
				ok = false;
				vpn->bad_nonces++;
				found->use_count++;
				log_msg(vpn, LOG_ERR, "%s: duplicate nonce (%s) seen %u times",
					VPN_STATE_STR(vpn->state),
					sodium_bin2hex(nonce_str, sizeof(nonce_str), nonce, sizeof(nonce)),
					found->use_count);
			}
			break;
		default:
			ok = false;
		}
	} else {
		if (comparison > -1) {
			ok = false;
			vpn->bad_nonces++;
			log_msg(vpn, LOG_ERR, "%s: received nonce (%s) <= previous (%s)",
				VPN_STATE_STR(vpn->state),
				sodium_bin2hex(nonce_str, sizeof(nonce_str), nonce, sizeof(nonce)),
				sodium_bin2hex(remote_nonce_str, sizeof(remote_nonce_str),
			     vpn->remote_nonce, sizeof(vpn->remote_nonce)));
		} else {
			ok = true;
		}
	}

	return ok;
}

void
purge_late(struct vpn_state *vpn)
{
	struct late_nonce *late, *tmp;

	HASH_ITER(hh, vpn->late_nonces, late, tmp) {
		HASH_DEL(vpn->late_nonces, late);
		free(late);
	}
}
