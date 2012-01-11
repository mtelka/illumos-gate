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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/mount.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/share.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/taskq.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/queue.h>

#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
/* #include <rpc/rpcb_clnt.h> ? */
#include <rpc/rpcb_prot.h>

/* #include <rpcsvc/nfs_proto.h> */
#include <rpcsvc/nlm_prot.h>
#include <rpcsvc/sm_inter.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/export.h>
#include <nfs/rnode.h>

#include "nlm_impl.h"

#if 0	/* XXX */
/*
 * Get an RPC client handle...
 */
int
nlm_clget_impl(clinfo_t *ci, servinfo_t *svp, cred_t *cr, CLIENT **newcl,
    struct chtab **chp, struct nfs_clnt *nfscl)
{
	struct chhead *ch, *newch;
	struct chhead **plistp;
	struct chtab *cp;
	int error;
	k_sigset_t smask;

	if (newcl == NULL || chp == NULL || ci == NULL)
		return (EINVAL);

	*newcl = NULL;
	*chp = NULL;

	/*
	 * Find an unused handle or create one
	 */
	newch = NULL;
	nfscl->nfscl_stat.clgets.value.ui64++;
top:
	/*
	 * Find the correct entry in the cache to check for free
	 * client handles.  The search is based on the RPC program
	 * number, program version number, dev_t for the transport
	 * device, and the protocol family.
	 */
	mutex_enter(&nfscl->nfscl_chtable_lock);
	plistp = &nfscl->nfscl_chtable;
	for (ch = nfscl->nfscl_chtable; ch != NULL; ch = ch->ch_next) {
		if (ch->ch_prog == ci->cl_prog &&
		    ch->ch_vers == ci->cl_vers &&
		    ch->ch_dev == svp->sv_knconf->knc_rdev &&
		    (strcmp(ch->ch_protofmly,
		    svp->sv_knconf->knc_protofmly) == 0))
			break;
		plistp = &ch->ch_next;
	}

	/*
	 * If we didn't find a cache entry for this quadruple, then
	 * create one.  If we don't have one already preallocated,
	 * then drop the cache lock, create one, and then start over.
	 * If we did have a preallocated entry, then just add it to
	 * the front of the list.
	 */
	if (ch == NULL) {
		if (newch == NULL) {
			mutex_exit(&nfscl->nfscl_chtable_lock);
			newch = kmem_alloc(sizeof (*newch), KM_SLEEP);
			newch->ch_timesused = 0;
			newch->ch_prog = ci->cl_prog;
			newch->ch_vers = ci->cl_vers;
			newch->ch_dev = svp->sv_knconf->knc_rdev;
			newch->ch_protofmly = kmem_alloc(
			    strlen(svp->sv_knconf->knc_protofmly) + 1,
			    KM_SLEEP);
			(void) strcpy(newch->ch_protofmly,
			    svp->sv_knconf->knc_protofmly);
			newch->ch_list = NULL;
			goto top;
		}
		ch = newch;
		newch = NULL;
		ch->ch_next = nfscl->nfscl_chtable;
		nfscl->nfscl_chtable = ch;
	/*
	 * We found a cache entry, but if it isn't on the front of the
	 * list, then move it to the front of the list to try to take
	 * advantage of locality of operations.
	 */
	} else if (ch != nfscl->nfscl_chtable) {
		*plistp = ch->ch_next;
		ch->ch_next = nfscl->nfscl_chtable;
		nfscl->nfscl_chtable = ch;
	}

	/*
	 * If there was a free client handle cached, then remove it
	 * from the list, init it, and use it.
	 */
	if (ch->ch_list != NULL) {
		cp = ch->ch_list;
		ch->ch_list = cp->ch_list;
		mutex_exit(&nfscl->nfscl_chtable_lock);
		if (newch != NULL) {
			kmem_free(newch->ch_protofmly,
			    strlen(newch->ch_protofmly) + 1);
			kmem_free(newch, sizeof (*newch));
		}
		(void) clnt_tli_kinit(cp->ch_client, svp->sv_knconf,
		    &svp->sv_addr, ci->cl_readsize, ci->cl_retrans, cr);
		error = sec_clnt_geth(cp->ch_client, svp->sv_secdata, cr,
		    &cp->ch_client->cl_auth);
		if (error || cp->ch_client->cl_auth == NULL) {
			CLNT_DESTROY(cp->ch_client);
			kmem_cache_free(chtab_cache, cp);
			return ((error != 0) ? error : EINTR);
		}
		ch->ch_timesused++;
		*newcl = cp->ch_client;
		*chp = cp;
		return (0);
	}

	/*
	 * There weren't any free client handles which fit, so allocate
	 * a new one and use that.
	 */
#ifdef DEBUG
	atomic_add_64(&nfscl->nfscl_stat.clalloc.value.ui64, 1);
#endif
	mutex_exit(&nfscl->nfscl_chtable_lock);

	nfscl->nfscl_stat.cltoomany.value.ui64++;
	if (newch != NULL) {
		kmem_free(newch->ch_protofmly, strlen(newch->ch_protofmly) + 1);
		kmem_free(newch, sizeof (*newch));
	}

	cp = kmem_cache_alloc(chtab_cache, KM_SLEEP);
	cp->ch_head = ch;

	sigintr(&smask, (int)ci->cl_flags & MI_INT);
	error = clnt_tli_kcreate(svp->sv_knconf, &svp->sv_addr, ci->cl_prog,
	    ci->cl_vers, ci->cl_readsize, ci->cl_retrans, cr, &cp->ch_client);
	sigunintr(&smask);

	if (error != 0) {
		kmem_cache_free(chtab_cache, cp);
#ifdef DEBUG
		atomic_add_64(&nfscl->nfscl_stat.clalloc.value.ui64, -1);
#endif
		/*
		 * Warning is unnecessary if error is EINTR.
		 */
		if (error != EINTR) {
			nfs_cmn_err(error, CE_WARN,
			    "clget: couldn't create handle: %m\n");
		}
		return (error);
	}
	(void) CLNT_CONTROL(cp->ch_client, CLSET_PROGRESS, NULL);
	auth_destroy(cp->ch_client->cl_auth);
	error = sec_clnt_geth(cp->ch_client, svp->sv_secdata, cr,
	    &cp->ch_client->cl_auth);
	if (error || cp->ch_client->cl_auth == NULL) {
		CLNT_DESTROY(cp->ch_client);
		kmem_cache_free(chtab_cache, cp);
#ifdef DEBUG
		atomic_add_64(&nfscl->nfscl_stat.clalloc.value.ui64, -1);
#endif
		return ((error != 0) ? error : EINTR);
	}
	ch->ch_timesused++;
	*newcl = cp->ch_client;
	ASSERT(cp->ch_client->cl_nosignal == FALSE);
	*chp = cp;
	return (0);
}


static void
nlm_clfree_impl(CLIENT *cl, struct chtab *cp, struct nfs_clnt *nfscl)
{
	if (cl->cl_auth != NULL) {
		sec_clnt_freeh(cl->cl_auth);
		cl->cl_auth = NULL;
	}

	/*
	 * Timestamp this cache entry so that we know when it was last
	 * used.
	 */
	cp->ch_freed = gethrestime_sec();

	/*
	 * Add the free client handle to the front of the list.
	 * This way, the list will be sorted in youngest to oldest
	 * order.
	 */
	mutex_enter(&nfscl->nfscl_chtable_lock);
	cp->ch_list = cp->ch_head->ch_list;
	cp->ch_head->ch_list = cp;
	mutex_exit(&nfscl->nfscl_chtable_lock);
}

#define	CL_HOLDTIME	60	/* time to hold client handles */

static void
nlm_clreclaim_zone(struct nfs_clnt *nfscl, uint_t cl_holdtime)
{
	struct chhead *ch;
	struct chtab *cp;	/* list of objects that can be reclaimed */
	struct chtab *cpe;
	struct chtab *cpl;
	struct chtab **cpp;
#ifdef DEBUG
	int n = 0;
#endif

	/*
	 * Need to reclaim some memory, so step through the cache
	 * looking through the lists for entries which can be freed.
	 */
	cp = NULL;

	mutex_enter(&nfscl->nfscl_chtable_lock);

	/*
	 * Here we step through each non-NULL quadruple and start to
	 * construct the reclaim list pointed to by cp.  Note that
	 * cp will contain all eligible chtab entries.  When this traversal
	 * completes, chtab entries from the last quadruple will be at the
	 * front of cp and entries from previously inspected quadruples have
	 * been appended to the rear of cp.
	 */
	for (ch = nfscl->nfscl_chtable; ch != NULL; ch = ch->ch_next) {
		if (ch->ch_list == NULL)
			continue;
		/*
		 * Search each list for entries older then
		 * cl_holdtime seconds.  The lists are maintained
		 * in youngest to oldest order so that when the
		 * first entry is found which is old enough, then
		 * all of the rest of the entries on the list will
		 * be old enough as well.
		 */
		cpl = ch->ch_list;
		cpp = &ch->ch_list;
		while (cpl != NULL &&
		    cpl->ch_freed + cl_holdtime > gethrestime_sec()) {
			cpp = &cpl->ch_list;
			cpl = cpl->ch_list;
		}
		if (cpl != NULL) {
			*cpp = NULL;
			if (cp != NULL) {
				cpe = cpl;
				while (cpe->ch_list != NULL)
					cpe = cpe->ch_list;
				cpe->ch_list = cp;
			}
			cp = cpl;
		}
	}

	mutex_exit(&nfscl->nfscl_chtable_lock);

	/*
	 * If cp is empty, then there is nothing to reclaim here.
	 */
	if (cp == NULL)
		return;

	/*
	 * Step through the list of entries to free, destroying each client
	 * handle and kmem_free'ing the memory for each entry.
	 */
	while (cp != NULL) {
#ifdef DEBUG
		n++;
#endif
		CLNT_DESTROY(cp->ch_client);
		cpl = cp->ch_list;
		kmem_cache_free(chtab_cache, cp);
		cp = cpl;
	}

#ifdef DEBUG
	/*
	 * Update clalloc so that nfsstat shows the current number
	 * of allocated client handles.
	 */
	atomic_add_64(&nfscl->nfscl_stat.clalloc.value.ui64, -n);
#endif
}

/* ARGSUSED */
static void
nlm_clreclaim(void *all)
{
	struct nfs_clnt *nfscl;

#ifdef DEBUG
	clstat_debug.clreclaim.value.ui64++;
#endif
	/*
	 * The system is low on memory; go through and try to reclaim some from
	 * every zone on the system.
	 */
	mutex_enter(&nfs_clnt_list_lock);
	nfscl = list_head(&nfs_clnt_list);
	for (; nfscl != NULL; nfscl = list_next(&nfs_clnt_list, nfscl))
		clreclaim_zone(nfscl, CL_HOLDTIME);
	mutex_exit(&nfs_clnt_list_lock);
}
#endif	/* XXX */
