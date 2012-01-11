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

static struct kmem_cache *nlm_rpch_cache = NULL;

static int nlm_rpch_ctor(void *, void *, int);
static void nlm_rpch_dtor(void *, void *);

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
 */
static void
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
	hostp->nh_rpcb_ustat = RPC_SUCCESS;
	mutex_exit(&hostp->nh_lock);

	stat = rpcbind_getaddr(&hostp->nh_knc, NLM_PROG, vers, &hostp->nh_addr);
	mutex_enter(&hostp->nh_lock);

	if (stat == RPC_SUCCESS) {
		hostp->nh_rpcb_state = NRPCB_UPDATED;

		/*
		 * RPC binding serial number shouldn't be 0.
		 */
		if (++hostp->nh_rpcb_sn == 0)
			hostp->nh_rpcb_sn = 1;
	} else {
		hostp->nh_rpcb_state = NRPCB_NEED_UPDATE;
	}

	hostp->nh_rpcb_ustat = stat;
	cv_broadcast(&hostp->nh_rpcb_cv);
}

/*
 * Refresh RPC handle taken from host handles cache.
 * This function is called when an RPC handle is either
 * uninitialized or was initialized using a binding that's
 * no longer current.
 */
static int
refresh_nlm_rpc(struct nlm_host *hostp, nlm_rpc_t *rpcp)
{
	int ret;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	rpcp->nr_sn = hostp->nh_rpcb_sn;
	mutex_exit(&hostp->nh_lock);
	if (rpcp->nr_handle == NULL) {
		ret = clnt_tli_kcreate(&hostp->nh_knc, &hostp->nh_addr,
		    NLM_PROG, rpcp->nr_vers, 0, NLM_RPC_RETRIES,
		    CRED(), &rpcp->nr_handle);
	} else {
		ret = clnt_tli_kinit(rpcp->nr_handle, &hostp->nh_knc,
		    &hostp->nh_addr, 0, NLM_RPC_RETRIES, CRED());
	}

	mutex_enter(&hostp->nh_lock);
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

	/*
	 * If this handle is either uninitialized, or was
	 * initialized using binding that's now stale
	 * do the init or re-init.
	 * See comments to enum nlm_rpcb_state for more
	 * details.
	 */
	while (hostp->nh_rpcb_state != NRPCB_UPDATED) {
		if (hostp->nh_rpcb_state == NRPCB_UPDATE_INPROGRESS) {
			rc = cv_wait_sig(&hostp->nh_rpcb_cv, &hostp->nh_lock);
			if (rc == 0) {
				mutex_exit(&hostp->nh_lock);
				return (EINTR);
			}
		}

		/*
		 * Check if RPC binding was marked for update.
		 * If so, start RPC binding update operation.
		 * NOTE: the operation can be executed by only
		 * one thread at time.
		 */
		if (hostp->nh_rpcb_state == NRPCB_NEED_UPDATE)
			update_host_rpcbinding(hostp, vers);

		/*
		 * Check if RPC error occured during RPC binding
		 * update operation. If so, report a correspoding
		 * error.
		 */
		if (hostp->nh_rpcb_ustat != RPC_SUCCESS) {
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
		rpcp = kmem_cache_alloc(nlm_rpch_cache, KM_SLEEP);
		rpcp->nr_vers = vers;
		mutex_enter(&hostp->nh_lock);
	}

	/*
	 * Check if binding is not "fresh".
	 * If so, renew it.
	 */
	if (rpcp->nr_handle == NULL ||
	    rpcp->nr_sn != hostp->nh_rpcb_sn) {
		rc = refresh_nlm_rpc(hostp, rpcp);
		if (rc != 0) {
			/*
			 * Just put handle back to the cache in hope
			 * that it will be reinitialized later wihout
			 * errors by somebody else...
			 */
			nlm_host_rele_rpc(hostp, rpcp);
			mutex_exit(&hostp->nh_lock);
			return (rc);
		}
	}

	mutex_exit(&hostp->nh_lock);
	DTRACE_PROBE2(end, struct nlm_host *, hostp,
	    nlm_rpc_t *, rpcp);

	*rpcpp = rpcp;
	return (0);
}

void
nlm_host_rele_rpc(struct nlm_host *hostp, nlm_rpc_t *rpcp)
{
	rpcp->nr_ttl_timeout = ddi_get_lbolt() +
		SEC_TO_TICK(NLM_RPC_TTL_PERIOD);

	mutex_enter(&hostp->nh_lock);
	TAILQ_INSERT_HEAD(&hostp->nh_rpchc, rpcp, nr_link);
	mutex_exit(&hostp->nh_lock);
}

/*
 * The function invalidates host's RPC binding by marking it
 * as not fresh. In this case another time thread tries to
 * get RPC handle from host's handles cache, host's RPC binding
 * will be updated.
 *
 * The function should be executed when RPC call invoked via
 * handle taken from RPC cache returns RPC_PROCUNAVAIL.
 */
void
nlm_host_invalidate_binding(struct nlm_host *hostp)
{
	mutex_enter(&hostp->nh_lock);
	hostp->nh_rpcb_state = NRPCB_NEED_UPDATE;
	mutex_exit(&hostp->nh_lock);
}

void
nlm_rpc_cache_init(void)
{
	nlm_rpch_cache = kmem_cache_create("nlm_rpch_cache",
	    sizeof (nlm_rpc_t), 0, nlm_rpch_ctor, nlm_rpch_dtor,
	    NULL, NULL, NULL, 0);
}

static int
nlm_rpch_ctor(void *datap, void *cdrarg, int kmflags)
{
	nlm_rpc_t *rpcp = (nlm_rpc_t *)datap;

	bzero(rpcp, sizeof (*rpcp));
	return (0);
}

void
nlm_rpch_dtor(void *datap, void *cdrarg)
{
	nlm_rpc_t *rpcp = (nlm_rpc_t *)datap;
	ASSERT(rpcp->nr_handle == NULL);
}
