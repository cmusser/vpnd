#include <sys/types.h>
#include <sys/sysctl.h>

#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "log.h"
#include "proto.h"

bool
read_nonce_reset_point(struct vpn_state *vpn, unsigned char *nonce)
{
	bool		ok = true;
	FILE           *f;

	f = fopen(vpn->nonce_filename, "r");
	if (f == NULL) {
		ok = false;
		log_msg(vpn, LOG_ERR, "failed to open nonce file %s: %s\n",
			vpn->nonce_filename, strerror(errno));
	}
	if (ok) {
		if (fread(nonce, crypto_box_NONCEBYTES, 1, f) < 1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "Can't read nonce from %s: %s\n",
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
		log_msg(vpn, LOG_ERR, "failed to open nonce file %s: %s\n",
			vpn->nonce_filename, strerror(errno));
	}
	if (ok) {
		memcpy(nonce_reset_point, vpn->nonce, sizeof(nonce_reset_point));
		sodium_add(nonce_reset_point, vpn->nonce_reset_incr_bin,
			   sizeof(nonce_reset_point));
		log_nonce(vpn, "create nonce reset point", nonce_reset_point);
		if (fwrite(nonce_reset_point, sizeof(nonce_reset_point), 1, f) < 1) {
			ok = false;
			log_msg(vpn, LOG_ERR, "failed to write nonce to %s: %s\n",
				vpn->nonce_filename, strerror(errno));
		}
	}
	if (f != NULL)
		fclose(f);
}

bool
get_sysctl_bool(struct vpn_state *vpn, char *name)
{
	bool		flag_bool = false;
	uint32_t	flag;
	size_t		flag_sz = sizeof(flag);

	if (sysctlbyname(name, &flag, &flag_sz, NULL, 0) == -1)
		log_msg(vpn, LOG_ERR, "sysctl get %s: %s", name, strerror(errno));
	else
		flag_bool = (flag == 0) ? false : true;

	return flag_bool;
}

void
set_sysctl_bool(struct vpn_state *vpn, char *name, bool value)
{
	uint32_t	flag;

	flag = (value == true) ? 1 : 0;

	if (sysctlbyname(name, NULL, 0, &flag, sizeof(flag)) == -1)
		log_msg(vpn, LOG_ERR, "sysctl set %s: %s", name, strerror(errno));
	else
		log_msg(vpn, LOG_NOTICE, "sysctl %s=%d", name, flag);
}

void
get_cur_monotonic(struct timespec *tp)
{
#ifdef __MacOSX__
#else
	clock_gettime(CLOCK_MONOTONIC, tp);
#endif
}

void
spawn_subprocess(struct vpn_state *vpn, char *cmd)
{
	char		cmd_with_stderr_redirect[512];
	FILE           *cmd_fd;
	char		cmd_out   [256];
	char           *newline;

	snprintf(cmd_with_stderr_redirect, sizeof(cmd_with_stderr_redirect),
		 "%s 2>&1", cmd);
	if ((cmd_fd = popen(cmd_with_stderr_redirect, "r")) == NULL) {
		log_msg(vpn, LOG_ERR, "spawn of \"%s\" failed: %s", cmd_with_stderr_redirect,
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
		log_msg(vpn, LOG_ERR, "%s: No space for timer event (%s)",
			VPN_STATE_STR(vpn->state), TIMER_TYPE_STR(ttype));
	}
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
		log_msg(vpn, LOG_ERR, "kqueue(): %s", strerror(errno));
	}
	while (ok) {
		nev = kevent(kq, vpn->kev_changes, vpn->kev_change_count,
			     &event, 1, NULL);
		vpn->kev_change_count = 0;
		if (nev < 0) {
			ok = false;
			log_msg(vpn, LOG_ERR, "kevent: %s", strerror(errno));
		} else {
			if (event.flags & EV_ERROR) {
				ok = false;
				log_msg(vpn, LOG_ERR, "EV_ERROR: %s for %" PRIuPTR,
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
						log_msg(vpn, LOG_NOTICE, "shutting down (signal %u)",
							event.ident);
						return_to_init_state(vpn);
						break;
					default:
						break;
					}

					break;
				default:
					log_msg(vpn, LOG_WARNING, "unhandled event type: %d",
						event.filter);
				}
			}
		}
	}

	return ok;
}

#if defined(__NetBSD__) || defined(__MacOSX__)
/* $DragonFly: src/lib/libc/stdlib/strtonum.c,v 1.2 2006/09/28 17:20:45 corecode Exp $ */
/*	$OpenBSD: strtonum.c,v 1.6 2004/08/03 19:38:01 millert Exp $	*/

/*
 * Copyright (c) 2004 Ted Unangst and Todd Miller
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <limits.h>

#define INVALID 	1
#define TOOSMALL 	2
#define TOOLARGE 	3

long long
strtonum(const char *numstr, long long minval, long long maxval,
    const char **errstrp)
{
	long long ll = 0;
	char *ep;
	int error = 0;
	struct errval {
		const char *errstr;
		int err;
	} ev[4] = {
		{ NULL,		0 },
		{ "invalid",	EINVAL },
		{ "too small",	ERANGE },
		{ "too large",	ERANGE },
	};

	ev[0].err = errno;
	errno = 0;
	if (minval > maxval)
		error = INVALID;
	else {
		ll = strtoll(numstr, &ep, 10);
		if (numstr == ep || *ep != '\0')
			error = INVALID;
		else if ((ll == LLONG_MIN && errno == ERANGE) || ll < minval)
			error = TOOSMALL;
		else if ((ll == LLONG_MAX && errno == ERANGE) || ll > maxval)
			error = TOOLARGE;
	}
	if (errstrp != NULL)
		*errstrp = ev[error].errstr;
	errno = ev[error].err;
	if (error)
		ll = 0;

	return (ll);
}

#endif
