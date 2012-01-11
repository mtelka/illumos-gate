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
#include <sys/sdt.h>

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

/*
 * Update host's RPC binding (host->nh_addr).
 * The function is executed by only one thread at time.
 *
 * On success returns 0. If rpcb_getaddr() operation failed
 * returns -1.
 */
static int
update_host_rpcbinding(struct nlm_host *hostp, int vers)
{
	enum clnt_stat stat;
	int ret = 0;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	/*
	 * Mark RPC binding state as "update in progress" in order
	 * to say other threads that they need to wait until binding
	 * is fully updated.
	 */
	hostp->nh_rpcb_state = NRPCB_UPDATE_INPROGRESS;
	mutex_exit(&hostp->nh_lock);

	stat = rpcbind_getaddr(&hostp->nh_knc, NLM_PROG, vers, &hostp->nh_addr);
	if (stat != RPC_SUCCESS) {
		NLM_ERR("Failed to update RPC binding for host %s. [RPC err: %s]\n",
		    hostp->nh_name, rpc_tpierr2name(stat));
		ret = -1;
		mutex_enter(&hostp->nh_lock);

		/*
		 * No luck. May be the other time some thread calls this function
		 * rpcbind_getaddr() does its job without errors.
		 */
		hostp->nh_rpcb_state = NRPCB_NEED_UPDATE;
	} else {
		mutex_enter(&hostp->nh_lock);
		hostp->nh_rpcb_update_time = ddi_get_lbolt();
		hostp->nh_rpcb_state = NRPCB_UPDATED;
	}

	cv_broadcast(&hostp->nh_rpcb_cv);
	return (ret);
}

/*
 * Refresh RPC handle taken from host handles cache.
 * RPC handle passed to this function can be in one of
 * thee states:
 *  1) Uninitialized (rcp->nr_handle is NULL)
 *     In this case we need to allocate new CLIENT for RPC
 *     handle by calling clnt_tli_kcreate
 *  2) Not fresh (the last time it was used was _before_
 *     update of host's RPC binding).
 *     In this case we need to reinitialize handle with new
 *     RPC binding (host->nh_addr) by calling clnt_tli_kinit.
 *  3) Fresh
 *     In this case reinitialization isn't required.
 */
static int
refresh_nlm_rpc(nlm_rpc_t *rpcp)
{
	int ret = 0;
	struct nlm_host *hostp = rpcp->nr_owner;

	ASSERT(rpcp->nr_owner != NULL);
	if (rpcp->nr_handle == NULL) {
		ret = clnt_tli_kcreate(&hostp->nh_knc, &hostp->nh_addr,
		    NLM_PROG, rpcp->nr_vers, 0, 0, CRED(), &rpcp->nr_handle);
	} else if (rpcp->nr_refresh_time < hostp->nh_rpcb_update_time) {
		ret = clnt_tli_kinit(rpcp->nr_handle, &hostp->nh_knc,
		    &hostp->nh_addr, 0, 0, CRED());
	}

	if (ret == 0)
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
	nlm_rpc_t *rpcp = NULL;
	int rc;

	mutex_enter(&hostp->nh_lock);
	DTRACE_PROBE2(nlm_host_get_rpc, struct nlm_host *, hostp,
	    int, vers);

	/*
	 * Check if some other thread updates RPC binding.
	 * If so, wait until RPC binding update operation is finished.
	 * NOTE: we can't host->nh_addr unitl binding is fresh, because
	 * it may raise an error in code that uses RPC handle returned
	 * by nlm_host_get_rpc().
	 */
	while (hostp->nh_rpcb_state == NRPCB_UPDATE_INPROGRESS) {
		rc = cv_wait_sig(&hostp->nh_rpcb_cv, &hostp->nh_lock);
		if (rc == 0) {
			mutex_exit(&hostp->nh_lock);
			return (EINTR);
		}
	}

	/*
	 * Check if RPC binding was marked for update.
	 * If so, start RPC binding update operation.
	 * NOTE: the operation can be by only one thread at time.
	 */
	if (hostp->nh_rpcb_state == NRPCB_NEED_UPDATE) {
		rc = update_host_rpcbinding(hostp, vers);
		if (rc < 0) {
			mutex_exit(&hostp->nh_lock);
			return (ENOENT);
		}
	}

	rpcp = get_nlm_rpc_fromcache(hostp, vers);
	if (rpcp == NULL) {
		/*
		 * There weren't any RPC handles in a host
		 * cache. No luck, just create a new one.
		 */
		mutex_exit(&hostp->nh_lock);
		rpcp = kmem_zalloc(sizeof (*rpcp), KM_SLEEP);
		rpcp->nr_vers = vers;
		rpcp->nr_owner = hostp;
		mutex_enter(&hostp->nh_lock);
	}

	mutex_exit(&hostp->nh_lock);
	rc = refresh_nlm_rpc(rpcp);
	if (rc != 0) {
		/*
		 * Just put handle back to the cache in hope
		 * that it will be reinitialized later wihout
		 * errors by somebody else...
		 */
		nlm_host_rele_rpc(rpcp);
		return (rc);
	}

out:
	DTRACE_PROBE2(nlm_host_get_rpc__end, struct nlm_host *, hostp,
	    nlm_rpc_t *, rpcp);

	*rpcpp = rpcp;
	return (0);
}

void
nlm_host_rele_rpc(nlm_rpc_t *rpcp)
{
	struct nlm_host *hostp = rpcp->nr_owner;

	ASSERT(rpcp->nr_owner != NULL);
	rpcp->nr_ttl_timeout = ddi_get_lbolt() +
		SEC_TO_TICK(NLM_RPC_TTL_PERIOD);

	mutex_enter(&hostp->nh_lock);
	TAILQ_INSERT_HEAD(&hostp->nh_rpchc, rpcp, nr_link);
	mutex_exit(&hostp->nh_lock);
}
