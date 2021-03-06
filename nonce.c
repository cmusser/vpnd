#include <errno.h>

#include "diag.h"
#include "nonce.h"
#include "uthash.h"

bool
read_nonce(struct vpn_state *vpn, nonce_type type)
{
	bool		ok = true;
	char           *nonce_filename;
	FILE           *f;
	unsigned char  *nonce;

	if (type == LOCAL) {
		nonce_filename = vpn->local_nonce_filename;
		nonce = vpn->nonce;
	} else {
		nonce_filename = vpn->remote_nonce_filename;
		nonce = vpn->remote_nonce;
	}

	f = fopen(nonce_filename, "r");
	if (f == NULL) {
		ok = false;
		log_msg(vpn, LOG_ERR, "failed to open nonce file %s: %s\n",
			nonce_filename, strerror(errno));
	}
	if (ok) {
		if (fread(nonce, crypto_box_NONCEBYTES, 1, f) < 1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "Can't read nonce from %s: %s\n",
				nonce_filename, strerror(errno));
		}
	}
	if (f != NULL)
		fclose(f);

	return ok;
}

void
write_nonce(struct vpn_state *vpn, nonce_type type)
{
	bool		ok = true;
	unsigned char	output_nonce[crypto_box_NONCEBYTES];
	char           *nonce_filename;
	FILE           *f;
	unsigned char  *input_nonce;

	if (type == LOCAL) {
		vpn->nonce_incr_count = 0;
		nonce_filename = vpn->local_nonce_filename;
		input_nonce = vpn->nonce;
	} else {
		nonce_filename = vpn->remote_nonce_filename;
		input_nonce = vpn->remote_nonce;
	}

	f = fopen(nonce_filename, "w");
	if (f == NULL) {
		ok = false;
		log_msg(vpn, LOG_ERR, "failed to open nonce file %s: %s\n",
			nonce_filename, strerror(errno));
	}
	if (ok) {
		memcpy(output_nonce, input_nonce, sizeof(output_nonce));
		if (type == LOCAL) {
			sodium_add(output_nonce, vpn->nonce_reset_incr_bin,
				   sizeof(output_nonce));
			log_nonce(vpn, "create nonce reset point", type, output_nonce);
		} else {
			log_nonce(vpn, "storing remote nonce", type, output_nonce);
		}
		if (fwrite(output_nonce, sizeof(output_nonce), 1, f) < 1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "failed to write nonce to %s: %s\n",
				nonce_filename, strerror(errno));
		}
	}
	if (f != NULL)
		fclose(f);
}

uint32_t
cur_key_late_packets(struct vpn_state *vpn)
{
	return HASH_COUNT(vpn->late_nonces);
}

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
					late->use_count = 1;
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
