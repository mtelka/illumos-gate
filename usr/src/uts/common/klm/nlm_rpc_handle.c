/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/queue.h>

#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <rpc/rpcb_prot.h>

#include <rpcsvc/nlm_prot.h>
#include <rpcsvc/sm_inter.h>

#include "nlm_impl.h"

static nlm_rpc_t *
get_nlm_rpc_fromcache(struct nlm_host *hostp, int vers)
{
	nlm_rpc_t *rpcp;
	bool_t found = FALSE;

	if (TAILQ_EMPTY(&hostp->nh_rpchc))
		return (NULL);

	TAILQ_FOREACH(rpcp, &hostp->nh_rpchc, nr_link) {
		if (rpcp->nr_vers == vers) {
			found = TRUE;
			break;
		}
	}

	if (!found)
		return (NULL);

	TAILQ_REMOVE(&hostp->nh_rpchc, rpcp, nr_link);
	return (rpcp);
}

static int
refresh_nlm_rpc(struct nlm_host *hostp, nlm_rpc_t *rpcp)
{
	int ret;

	if (rpcp->nr_handle != NULL) {
		/* TODO: call NULL to check if client is alright */
		ret = 0;
	} else {
		enum clnt_stat stat;

		stat = rpcbind_getaddr(&hostp->nh_knc, NLM_PROG,
		    rpcp->nr_vers, &hostp->nh_addr);

		if (stat != RPC_SUCCESS)
			return (EINVAL);

		ret = clnt_tli_kcreate(&hostp->nh_knc, &hostp->nh_addr,
		    NLM_PROG, rpcp->nr_vers, 0, 0, CRED(), &rpcp->nr_handle);
	}

	rpcp->nr_refresh_time = ddi_get_lbolt();
	return (ret);
}

/*
 * Get RPC handle that can be used to talk to the NLM
 * of given version running on given host.
 * Saves obtained RPC handle to rpcpp argument.
 *
 * If error occures, return nonzero error code.
 */
int
nlm_host_get_rpc(struct nlm_host *hostp, int vers, nlm_rpc_t **rpcpp)
{
	nlm_rpc_t *rpcp;
	clock_t time_uptime;
	int err;

	mutex_enter(&hostp->nh_lock);
	rpcp = get_nlm_rpc_fromcache(hostp, vers);

	if (rpcp == NULL) {
		mutex_exit(&hostp->nh_lock);

		rpcp = kmem_zalloc(sizeof (*rpcp), KM_SLEEP);
		rpcp->nr_vers = vers;

		mutex_enter(&hostp->nh_lock);
	}

	mutex_exit(&hostp->nh_lock);
	err = refresh_nlm_rpc(hostp, rpcp);
	if (err) {
		nlm_host_rele_rpc(hostp, rpcp);
		rpcp = NULL;
	}

	*rpcpp = rpcp;
	return (0);
}

void
nlm_host_rele_rpc(struct nlm_host *hostp, nlm_rpc_t *rpcp)
{
	rpcp->nr_ttl_timeout = ddi_get_lbolt() +
		SEC_TO_TICK(NLM_RPC_TTL_PERIOD);

	mutex_enter(&hostp->nh_lock);

	/* keep items in LRU fashion */
	TAILQ_INSERT_HEAD(&hostp->nh_rpchc, rpcp, nr_link);
	mutex_exit(&hostp->nh_lock);
}

