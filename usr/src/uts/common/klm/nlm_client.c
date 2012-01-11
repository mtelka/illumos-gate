/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2008 Isilon Inc http://www.isilon.com/
 * Authors: Doug Rabson <dfr@rabson.org>
 * Developed with Red Inc: Alfred Perlstein <alfred@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Client-side support for (NFS) VOP_FRLOCK, VOP_SHRLOCK.
 * (called via klmops.c: lm_frlock, lm4_frlock)
 *
 * Source code derived from FreeBSD nlm_advlock.c
 */

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/flock.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/share.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <netinet/in.h>

#include <fs/fs_subr.h>
#include <rpcsvc/nlm_prot.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/export.h>
#include <nfs/rnode.h>

#include "nlm_impl.h"

/* Extra flags for nlm_call_lock() - xflags */
#define	NLM_X_RECLAIM	1
#define	NLM_X_BLOCKING	2

/*
 * Timeout (in seconds) that tells how long client
 * should wait on the blocking lock request until
 * server sends a reply or cancelation event happens.
 * After the timeout expires, client should resend
 * its sleeping lock request.
 */
#define NLM_SLRESEND_TIMEO 10

static volatile uint32_t nlm_xid = 1;

static int nlm_init_fh_by_vp(vnode_t *, struct netobj *, rpcvers_t *);
static int nlm_map_status(nlm4_stats);
static void nlm_wait_grace(void);
static int nlm_map_clnt_stat(enum clnt_stat stat);

static int nlm_frlock_getlk(struct nlm_host *hostp, vnode_t *vp,
    struct flock64 *flkp, int flags, u_offset_t offset,
    struct netobj *fhp, int vers);

static int nlm_frlock_setlk(struct nlm_host *hostp, vnode_t *vp,
    struct flock64 *flkp, int flags, u_offset_t offset,
    struct netobj *fhp, struct flk_callback *flcb,
    int vers, bool_t do_block);

static int nlm_reclaim_lock(struct nlm_host *, vnode_t *,
    struct flock64 *, int32_t);

static void nlm_init_lock(struct nlm4_lock *lock,
	const struct flock64 *fl, struct netobj *fh,
	struct nlm_owner_handle *oh);

static int nlm_call_lock(vnode_t *vp, struct flock64 *flk,
	struct nlm_host *host, struct netobj *fh,
	struct flk_callback *flcb, int vers, int xflags);
static int nlm_call_unlock(vnode_t *vp, struct flock64 *flk,
	struct nlm_host *host, struct netobj *fh, int vers);
static int nlm_call_test(vnode_t *vp, struct flock64 *flk,
	struct nlm_host *host, struct netobj *fh, int vers);
static int nlm_call_cancel(struct nlm4_lockargs *largs,
	struct nlm_host *host, int vers);

static int nlm_local_getlk(vnode_t *vp, struct flock64 *fl, int flags);
static int nlm_local_setlk(vnode_t *vp, struct flock64 *fl, int flags);
static void nlm_local_cancelk(vnode_t *, struct flock64 *);

static void nlm_init_share(struct nlm4_share *share,
	const struct shrlock *sl, struct netobj *fh,
	struct nlm_owner_handle *oh);

static int
nlm_call_share(vnode_t *vp, struct shrlock *shr,
	struct nlm_host *host, struct netobj *fh,
	int vers, int reclaim);
static int
nlm_call_unshare(struct vnode *vp, struct shrlock *shr,
	struct nlm_host *host, struct netobj *fh, int vers);

static int
nlm_local_shrlock(vnode_t *vp, struct shrlock *sl, int cmd, int flags);

static int
nlm_msg(kthread_t *td, const char *server, const char *msg, int error)
{

	if (error) {
		uprintf("nfs server %s: %s, error %d\n", server,
		    msg, error);
	} else {
		uprintf("nfs server %s: %s\n", server, msg);
	}
	return (0);
}

struct nlm_feedback_arg {
	bool_t	nf_printed;
	mntinfo_t *nf_nmp;
};

static void
nlm_down(struct nlm_feedback_arg *nf, kthread_t *td,
    const char *msg, int error)
{
	mntinfo_t *nmp = nf->nf_nmp;

	if (nmp == NULL)
		return;
#if 0	/* XXX */
	mutex_enter(&nmp->mi_lock);
	if (!(nmp->nm_state & NFSSTA_LOCKTIMEO)) {
		nmp->nm_state |= NFSSTA_LOCKTIMEO;
		mutex_exit(&nmp->mi_lock);
		vfs_event_signal(&nmp->nm_mountp->mnt_stat.f_fsid,
		    VQ_NOTRESPLOCK, 0);
	} else {
		mutex_exit(&nmp->mi_lock);
	}
#endif	/* XXX */

	nf->nf_printed = TRUE;
	nlm_msg(td, nmp->mi_curr_serv->sv_hostname, msg, error);
}

static void
nlm_up(struct nlm_feedback_arg *nf, kthread_t *td,
    const char *msg)
{
	mntinfo_t *nmp = nf->nf_nmp;

	if (!nf->nf_printed)
		return;

	nlm_msg(td, nmp->mi_curr_serv->sv_hostname, msg, 0);

#if 0	/* XXX not yet */
	mutex_enter(&nmp->mi_lock);
	if (nmp->nm_state & NFSSTA_LOCKTIMEO) {
		nmp->nm_state &= ~NFSSTA_LOCKTIMEO;
		mutex_exit(&nmp->mi_lock);
		vfs_event_signal(&nmp->nm_mountp->mnt_stat.f_fsid,
		    VQ_NOTRESPLOCK, 1);
	} else {
		mutex_exit(&nmp->mi_lock);
	}
#endif	/* XXX not yet */
}

#if 0	/* XXX not yet */
static void
nlm_feedback(int type, int proc, void *arg)
{
	kthread_t *td = curthread;
	struct nlm_feedback_arg *nf = (struct nlm_feedback_arg *)arg;

	switch (type) {
	case FEEDBACK_REXMIT2:
	case FEEDBACK_RECONNECT:
		nlm_down(nf, td, "lockd not responding", 0);
		break;

	case FEEDBACK_OK:
		nlm_up(nf, td, "lockd is alive again");
		break;
	}
}
#endif	/* XXX not yet */

/* **************************************************************** */

/*
 * Reclaim locks/shares acquired by the client side
 * on the given server represented by hostp.
 * The function is called from a dedicated thread
 * when server reports us that it's entered grace
 * period.
 */
void
nlm_reclaim_client(struct nlm_globals *g, struct nlm_host *hostp)
{
	int32_t state;
	int error, sysid;
	struct locklist *llp_head, *llp;
	bool_t restart;

	sysid = nlm_host_get_sysid(hostp) | NLM_SYSID_CLIENT;
	do {
		error = 0;
		restart = FALSE;
		state = nlm_host_get_state(hostp);

		DTRACE_PROBE3(reclaim__start, struct nlm_globals *, g,
		    struct nlm_host *, hostp, int, state);

		/*
		 * Sleeping locks can not be reclaimed,
		 * so the only thing we can do is to cancel
		 * them.
		 */
		nlm_host_cancel_slocks(g, hostp);

		/*
		 * Try to reclaim all active locks we have
		 */
		llp_head = llp = flk_get_active_locks(sysid, NOPID);
		while (llp != NULL) {
			error = nlm_reclaim_lock(hostp, llp->ll_vp,
			    &llp->ll_flock, state);

			if (error == 0) {
				llp = llp->ll_next;
				continue;
			} else if (error == ERESTART) {
				restart = FALSE;
				break;
			} else {
				/*
				 * Critical error occurred, the lock
				 * can not be recovered, just take it away.
				 */
				nlm_local_cancelk(llp->ll_vp, &llp->ll_flock);
			}

			llp = llp->ll_next;
		}

		flk_free_locklist(llp_head);
		if (restart) {
			/*
			 * Lock reclamation fucntion reported us that
			 * the server state was changed (again), so
			 * try to repeat the whole reclamation process.
			 */
			continue;
		}

		DTRACE_PROBE1(reclaim__end, int, error);

		/*
		 * TODO: recover share reservations
		 */
	} while (state != nlm_host_get_state(hostp));
}

/*
 * nlm_frlock --
 *      NFS advisory byte-range locks.
 *	Called in klmops.c
 *
 * Note that the local locking code (os/flock.c) is used to
 * keep track of remote locks granted by some server, so we
 * can reclaim those locks after a server restarts.  We can
 * also sometimes use this as a cache of lock information.
 *
 * Was: nlm_advlock()
 */
int
nlm_frlock(struct vnode *vp, int cmd, struct flock64 *flkp,
	int flags, u_offset_t offset, struct cred *crp,
	struct netobj *fhp, struct flk_callback *flcb, int vers)
{
	mntinfo_t *mi;
	servinfo_t *sv;
	const char *netid;
	struct nlm_host *hostp;
	int error;
	struct nlm_globals *g;

	mi = VTOMI(vp);
	sv = mi->mi_curr_serv;

	netid = nlm_netid_from_knetconfig(sv->sv_knconf);
	if (netid == NULL) {
		NLM_ERR("nlm_frlock: unknown NFS netid");
		return (ENOSYS);
	}

	g = zone_getspecific(nlm_zone_key, curzone);
	hostp = nlm_host_findcreate(g, sv->sv_hostname, netid, &sv->sv_addr);
	if (hostp == NULL)
		return (ENOSYS);

	/*
	 * Purge cached attributes in order to make sure that
	 * future calls of convoff()/VOP_GETATTR() will get the
	 * latest data.
	 */
	if (flkp->l_whence == SEEK_END)
		PURGE_ATTRCACHE(vp);

	/* Now flk0 is the zero-based lock request. */
	switch (cmd) {
	case F_GETLK:
		error = nlm_frlock_getlk(hostp, vp, flkp, flags,
		    offset, fhp, vers);
		break;

	case F_SETLK:
	case F_SETLKW:
		error = nlm_frlock_setlk(hostp, vp, flkp, flags,
		    offset, fhp, flcb, vers, (cmd == F_SETLKW));
		if (error == 0) {
			/* Start monitoring the host */
			nlm_host_monitor(g, hostp, 0);
		}

		break;

	default:
		error = EINVAL;
		break;
	}

	nlm_host_release(g, hostp);
	return (error);
}

static int
nlm_frlock_getlk(struct nlm_host *hostp, vnode_t *vp,
    struct flock64 *flkp, int flags, u_offset_t offset,
    struct netobj *fhp, int vers)
{
	struct flock64 flk0;
	int error;

	/*
	 * Check local (cached) locks first.
	 * If we find one, no need for RPC.
	 */
	error = nlm_local_getlk(vp, flkp, flags);
	if (error != 0)
		return (error);
	if (flkp->l_type != F_UNLCK)
		return (0);

	/* Not found locally.  Try remote. */
	flk0 = *flkp;
	error = convoff(vp, &flk0, 0, (offset_t)offset);
	if (error != 0)
		return (error);

	error = nlm_call_test(vp, &flk0, hostp, fhp, vers);
	if (error != 0)
		return (error);

	if (flk0.l_type == F_UNLCK) {
		/*
		 * Update the caller's *flkp with information
		 * on the conflicting lock (or lack thereof).
		 * Note: This is the only place where we
		 * modify the caller's *flkp data.
		 */
		flkp->l_type = F_UNLCK;
	} else {
		/*
		 * Found a conflicting lock.  Set the
		 * caller's *flkp with the info, first
		 * converting to the caller's whence.
		 */
		(void)convoff(vp, &flk0, flkp->l_whence, (offset_t)offset);
		*flkp = flk0;
	}

	return (0);
}

static int
nlm_frlock_setlk(struct nlm_host *hostp, vnode_t *vp,
    struct flock64 *flkp, int flags, u_offset_t offset,
    struct netobj *fhp, struct flk_callback *flcb,
    int vers, bool_t do_block)
{
	int error, xflags;

	error = convoff(vp, flkp, 0, (offset_t)offset);
	if (error != 0)
		return (error);

	/*
	 * Fill in l_sysid for the local locking calls.
	 * Also, let's not trust the caller's l_pid.
	 */
	flkp->l_sysid = NLM_SYSID_CLIENT | nlm_host_get_sysid(hostp);
	flkp->l_pid = curproc->p_pid;

	if (flkp->l_type == F_UNLCK) {
		/*
		 * Purge local (cached) lock information first,
		 * then clear the remote lock.
		 */
		(void) nlm_local_setlk(vp, flkp, flags);
		error = nlm_call_unlock(vp, flkp, hostp, fhp, vers);

		return (error);
	}

	if (!do_block) {
		/*
		 * This is a non-blocking "set" request,
		 * so we can check locally first, and
		 * sometimes avoid an RPC call.
		 */
		struct flock64 flk0;

		flk0 = *flkp;
		error = nlm_local_getlk(vp, &flk0, flags);
		if (error != 0 && flk0.l_type != F_UNLCK) {
			/* Found a conflicting lock. */
			error = EAGAIN;
		}

		xflags = 0;
	} else {
		xflags = NLM_X_BLOCKING;
	}

	error = nlm_call_lock(vp, flkp, hostp, fhp, flcb, vers, xflags);
	if (error != 0)
		return (error);

	error = nlm_local_setlk(vp, flkp, flags);
	if (error != 0) {
		NLM_ERR("nlm_frlock_setlk: Failed to set local lock. [err=%d]\n",
			error);
		/* XXX[DK]: unlock remote lock? */
	}

	return (error);
}

/*
 * Cancel all client side remote locks/shares on the
 * given host. Report to the processes that own
 * cancelled locks that they are removed by force
 * by sending SIGLOST.
 */
void
nlm_client_cancel_all(struct nlm_globals *g, struct nlm_host *hostp)
{
	struct locklist *llp_head, *llp;
	struct netobj lm_fh;
	rpcvers_t vers;
	int32_t sysid;
	int error;

	sysid = nlm_host_get_sysid(hostp) | NLM_SYSID_CLIENT;
	nlm_host_cancel_slocks(g, hostp);

	llp_head = llp = flk_get_active_locks(sysid, NOPID);
	while (llp != NULL) {
		llp->ll_flock.l_type = F_UNLCK;

		error = nlm_init_fh_by_vp(llp->ll_vp, &lm_fh, &vers);
		if (error == 0)
			(void) nlm_call_unlock(llp->ll_vp, &llp->ll_flock,
			    hostp, &lm_fh, vers);

		nlm_local_cancelk(llp->ll_vp, &llp->ll_flock);
		llp = llp->ll_next;
	}

	flk_free_locklist(llp_head);

	/* TODO: share reservations */
}

/*
 * The function determines whether the lock "fl" can
 * be safely upplied to the file vnode "vp" corresponds to.
 * The lock can be "safely" applied if all the conditions
 * above are held:
 *  - It's not a mandatory lock
 *  - The vnode wasn't mapped by anyone
 *  - The vnode was mapped, but it hasn't any locks on it.
 *  - The vnode was mapped and all locks it has occupies
 *    the whole file.
 */
int
nlm_safelock(vnode_t *vp, const struct flock64 *fl, cred_t *cr)
{
	rnode_t *rp = VTOR(vp);
	struct vattr va;
	int err;

	if ((rp->r_mapcnt > 0) && (fl->l_start != 0 || fl->l_len != 0))
		return (0);

	va.va_mask = AT_MODE;
	err = nfs3getattr(vp, &va, cr);
	if (err != 0)
		return (0);

	/* NLM4 doesn't allow mandatory file locking */
	if (MANDLOCK(vp, va.va_mode))
		return (0);

	return (1);
}

/*
 * The function determines whether it's safe to map
 * a file correspoding to vnode vp.
 * The mapping is considered to be "safe" if file
 * either has no any locks on it or all locks it
 * has occupy the whole file.
 */
int
nlm_safemap(const vnode_t *vp)
{
	struct locklist *llp, *llp_next;
	struct nlm_slock *nslp;
	struct nlm_globals *g;
	int safe = 1;

	/* Check active locks at first */
	llp = flk_active_locks_for_vp(vp);
	while (llp != NULL) {
		if ((llp->ll_vp == vp) &&
		    ((llp->ll_flock.l_start != 0) ||
		     (llp->ll_flock.l_len != 0)))
			safe = 0;

		llp_next = llp->ll_next;
		VN_RELE(llp->ll_vp);
		kmem_free(llp, sizeof (*llp));
		llp = llp_next;
	}
	if (!safe)
		return (safe);

	/* Then check sleeping locks if any */
	g = zone_getspecific(nlm_zone_key, curzone);
	mutex_enter(&g->lock);
	TAILQ_FOREACH(nslp, &g->nlm_slocks, nsl_link) {
		if (nslp->nsl_state == NLM_SL_BLOCKED	&&
		    nslp->nsl_vp == vp			&&
		    ((nslp->nsl_lock.l_offset != 0)	||
		        (nslp->nsl_lock.l_len != 0))) {
			safe = 0;
			break;
		}
	}

	mutex_exit(&g->lock);
	return (safe);
}

int
nlm_has_sleep(const vnode_t *vp)
{
	struct nlm_globals *g;
	struct nlm_slock *nslp;
	int has_slocks = FALSE;

	g = zone_getspecific(nlm_zone_key, curzone);
	mutex_enter(&g->lock);
	TAILQ_FOREACH(nslp, &g->nlm_slocks, nsl_link) {
		if (nslp->nsl_state == NLM_SL_BLOCKED) {
			has_slocks = TRUE;
			break;
		}
	}

	mutex_exit(&g->lock);
	return (has_slocks);
}

/*
 * The BSD code had functions here to "reclaim" (destroy)
 * remote locks when a vnode is being forcibly destroyed.
 * We just keep vnodes around until statd tells us the
 * client has gone away.
 */

static int
nlm_reclaim_lock(struct nlm_host *hostp, vnode_t *vp,
    struct flock64 *flp, int32_t orig_state)
{
	struct netobj lm_fh;
	int error, state;
	rpcvers_t vers;

	/*
	 * If the remote NSM state changes during recovery, the host
	 * must have rebooted a second time. In that case, we must
	 * restart the recovery.
	 */
	state = nlm_host_get_state(hostp);
	if (state != orig_state)
		return (ERESTART);

	error = nlm_init_fh_by_vp(vp, &lm_fh, &vers);
	if (error != 0)
		return (error);

	return (nlm_call_lock(vp, flp, hostp, &lm_fh,
	        NULL, vers, NLM_X_RECLAIM));
}

/*
 * Moved these to nlm_client.c:
 * nlm_test_rpc
 * nlm_lock_rpc
 * nlm_cancel_rpc
 * nlm_unlock_rpc
 */


/*
 * Get local lock information for some NFS server.
 *
 * This gets (checks for) a local conflicting lock.
 * Note: Modifies passed flock, if a conflict is found,
 * but the caller expects that.
 */
static int
nlm_local_getlk(vnode_t *vp, struct flock64 *fl, int flags)
{
	VERIFY(fl->l_whence == SEEK_SET);
	return (reclock(vp, fl, 0, flags, 0, NULL));
}

/*
 * Set local lock information for some NFS server.
 *
 * Called after a lock request (set or clear) succeeded. We record the
 * details in the local lock manager. Note that since the remote
 * server has granted the lock, we can be sure that it doesn't
 * conflict with any other locks we have in the local lock manager.
 *
 * Since it is possible that host may also make NLM client requests to
 * our NLM server, we use a different sysid value to record our own
 * client locks.
 *
 * Note that since it is possible for us to receive replies from the
 * server in a different order than the locks were granted (e.g. if
 * many local threads are contending for the same lock), we must use a
 * blocking operation when registering with the local lock manager.
 * We expect that any actual wait will be rare and short hence we
 * ignore signals for this.  (XXX not yet signals)
 *
 * XXX: was nlm_record_lock()
 */
static int
nlm_local_setlk(vnode_t *vp, struct flock64 *fl, int flags)
{
	VERIFY(fl->l_whence == SEEK_SET);
	return (reclock(vp, fl, SETFLCK | SLPFLCK, flags, 0, NULL));
}

/*
 * Cancel local lock and send send SIGLOST signal
 * to the lock owner.
 *
 * NOTE: modifies flp
 */
static void
nlm_local_cancelk(vnode_t *vp, struct flock64 *flp)
{
	proc_t *p;

	flp->l_type = F_UNLCK;
	(void) nlm_local_setlk(vp, flp, FREAD | FWRITE);

	/*
	 * Notify lock owner that the lock was lost.
	 */
	mutex_enter(&pidlock);
	p = prfind(flp->l_pid);
	if (p != NULL)
		psignal(p, SIGLOST);

	mutex_exit(&pidlock);
}

/*
 * Do NLM_LOCK call.
 * Was: nlm_setlock()
 *
 * NOTE: nlm_call_lock() function should care about locking/unlocking
 * of rnode->r_lkserlock which should be released before nlm_call_lock()
 * sleeps on waiting lock and acquired when it wakes up.
 */
static int
nlm_call_lock(vnode_t *vp, struct flock64 *flp,
	struct nlm_host *hostp, struct netobj *fhp,
	struct flk_callback *flcb, int vers, int xflags)
{
	struct nlm4_lockargs args;
	struct nlm4_res res;
	struct nlm_owner_handle oh;
	struct nlm_globals *g;
	rnode_t *rnp = VTOR(vp);
	struct nlm_slock *nslp = NULL;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	g = zone_getspecific(nlm_zone_key, curzone);
	nlm_init_lock(&args.alock, flp, fhp, &oh);

	args.exclusive = (flp->l_type == F_WRLCK);
	args.reclaim = xflags & NLM_X_RECLAIM;
	args.state = g->nsm_state;
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;

	oh.oh_sysid = nlm_host_get_sysid(hostp);
	xid = atomic_inc_32_nv(&nlm_xid);

	if (xflags & NLM_X_BLOCKING) {
		args.block = TRUE;
		nslp = nlm_slock_register(g, hostp, &args.alock, vp);
	}

	for (;;) {
		nlm_rpc_t *rpcp;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(hostp, vers, &rpcp);
		if (error != 0) {
			error = ENOLCK;
			goto out;
		}

		bzero(&res, sizeof (res));
		stat = nlm_lock_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(hostp, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			goto out;
		}

		DTRACE_PROBE1(lock__res, enum nlm4_stats, res.stat.stat);
		xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res);
		if (res.stat.stat == nlm4_denied_grace_period) {
			if (args.reclaim) {
				error = ENOLCK;
				goto out;
			}

			nlm_wait_grace();
			continue;
		}


		switch (res.stat.stat) {
		case nlm4_granted:
		case nlm4_blocked:
			error = 0;
			break;

		case nlm4_denied:
			error = ENOLCK;
			break;

		default:
			error = nlm_map_status(res.stat.stat);
		}

		/*
		 * If we deal with either non-blocking lock or
		 * with a blocking locks that wasn't blocked on
		 * the server side (by some reason), our work
		 * is finished.
		 */
		if (nslp == NULL			||
		    res.stat.stat != nlm4_blocked	||
		    error != 0)
			goto out;

		/*
		 * The server should call us back with a
		 * granted message when the lock succeeds.
		 * In order to deal with broken servers,
		 * lost granted messages, or server reboots,
		 * we will also re-try every few seconds.
		 *
		 * Note: We're supposed to call these
		 * flk_invoke_callbacks when blocking.
		 * Take care on rnode->r_lkserlock, we should
		 * release it before going to sleep.
		 */
		flk_invoke_callbacks(flcb, FLK_BEFORE_SLEEP);
		nfs_rw_exit(&rnp->r_lkserlock);

		error = nlm_slock_wait(g, nslp, NLM_SLRESEND_TIMEO);

		/*
		 * NFS expects that we return with rnode->r_lkserlock
		 * locked on write, lock it back.
		 *
		 * NOTE: nfs_rw_enter_sig() can be either interruptible
		 * or not. It depends on options of NFS mount. Here
		 * we're _always_ uninterruptible (independently of mount
		 * options), because nfs_frlock/nfs3_frlock expects that
		 * we return with rnode->r_lkserlock acquired. So we don't
		 * want our lock attempt to be interrupted by a signal.
		 */
		nfs_rw_enter_sig(&rnp->r_lkserlock, RW_WRITER, 0);
		flk_invoke_callbacks(flcb, FLK_AFTER_SLEEP);

		if (error == 0) {
			break;
		} else if (error == EINTR) {
			/*
			 * We need to call the server to cancel our lock request.
			 * NOTE: we need to disable signals in order to prevent
			 * interruption of network RPC calls.
			 */
			k_sigset_t oldmask, newmask;

			DTRACE_PROBE1(cancel__lock, int, error);
			sigfillset(&newmask);
			sigreplace(&newmask, &oldmask);
			nlm_call_cancel(&args, hostp, vers);
			sigreplace(&oldmask, (k_sigset_t *)NULL);
		} else {
			/*
			 * Timeout happened, resend the lock request to
			 * the server. Well, we're a bit paranoid here,
			 * but keep in mind previous request could lost
			 * (especially with conectionless transport).
			 */

			ASSERT(error == ETIMEDOUT);
			continue;
		}
	}

out:
	if (nslp != NULL)
		nlm_slock_unregister(g, nslp);

	return (error);
}

/*
 * Do NLM_CANCEL call.
 * Helper for nlm_call_lock() error recovery.
 */
static int
nlm_call_cancel(struct nlm4_lockargs *largs,
	struct nlm_host *hostp, int vers)
{
	nlm4_cancargs cargs;
	uint32_t xid;
	int error;

	bzero(&cargs, sizeof (cargs));

	xid = atomic_inc_32_nv(&nlm_xid);
	/* XXX: Use largs->cookie here? (same xid) */
	cargs.cookie.n_len = sizeof (xid);
	cargs.cookie.n_bytes = (char *)&xid;
	cargs.block	= largs->block;
	cargs.exclusive	= largs->exclusive;
	cargs.alock	= largs->alock;

	for (;;) {
		nlm_rpc_t *rpcp;
		enum clnt_stat stat;
		struct nlm4_res res;

		error = nlm_host_get_rpc(hostp, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_cancel_rpc(&cargs, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(hostp, rpcp);

		DTRACE_PROBE1(cancel__rloop_end, enum clnt_stat, stat);
		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(cancel__res, enum nlm4_stats, res.stat.stat);
		switch (res.stat.stat) {
			/*
			 * There was nothing to cancel. We are going to go ahead
			 * and assume we got the lock.
			 */
		case nlm_denied:
			/*
			 * The server has recently rebooted.  Treat this as a
			 * successful cancellation.
			 */
		case nlm4_denied_grace_period:
			/*
			 * We managed to cancel.
			 */
		case nlm4_granted:
			error = 0;
			break;

		default:
			/*
			 * Broken server implementation.  Can't really do
			 * anything here.
			 */
			error = EIO;
			break;
		}

		xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res);
		break;
	}

	return (error);
}

/*
 * Do NLM_UNLOCK call.
 * Was: nlm_clearlock
 */
static int
nlm_call_unlock(struct vnode *vp, struct flock64 *flp,
	struct nlm_host *hostp, struct netobj *fhp, int vers)
{
	struct nlm4_unlockargs args;
	struct nlm_owner_handle oh;
	struct nlm4_res res;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	nlm_init_lock(&args.alock, flp, fhp, &oh);

	oh.oh_sysid = nlm_host_get_sysid(hostp);
	xid = atomic_inc_32_nv(&nlm_xid);
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;

	for (;;) {
		nlm_rpc_t *rpcp;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(hostp, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_unlock_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(hostp, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(unlock__res, enum nlm4_stats, res.stat.stat);
		xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res);
		if (res.stat.stat == nlm4_denied_grace_period) {
			nlm_wait_grace();
			continue;
		}

		break;
	}

	/* special cases */
	switch (res.stat.stat) {
	case nlm4_denied:
		error = EINVAL;
		break;
	default:
		error = nlm_map_status(res.stat.stat);
		break;
	}

	return (error);
}

/*
 * Do NLM_TEST call.
 * Was: nlm_getlock()
 */
static int
nlm_call_test(struct vnode *vp, struct flock64 *flp,
	struct nlm_host *hostp, struct netobj *fhp, int vers)
{
	struct nlm4_testargs args;
	struct nlm4_testres res;
	struct nlm4_holder *h;
	struct nlm_owner_handle oh;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	nlm_init_lock(&args.alock, flp, fhp, &oh);

	args.exclusive = (flp->l_type == F_WRLCK);
	oh.oh_sysid = nlm_host_get_sysid(hostp);
	xid = atomic_inc_32_nv(&nlm_xid);
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;

	for (;;) {
		nlm_rpc_t *rpcp;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(hostp, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_test_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(hostp, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(test__res, enum nlm4_stats, res.stat.stat);
		xdr_free((xdrproc_t)xdr_nlm4_testres, (void *)&res);
		if (res.stat.stat == nlm4_denied_grace_period)
			nlm_wait_grace();

		break;
	}

	switch (res.stat.stat) {
	case nlm4_granted:
		flp->l_type = F_UNLCK;
		error = 0;
		break;

	case nlm4_denied:
		h = &res.stat.nlm4_testrply_u.holder;
		flp->l_start = h->l_offset;
		flp->l_len = h->l_len;
		flp->l_pid = h->svid;
		flp->l_type = (h->exclusive) ? F_WRLCK : F_RDLCK;
		flp->l_whence = SEEK_SET;
		flp->l_sysid = 0;
		error = 0;
		break;

	default:
		error = nlm_map_status(res.stat.stat);
		break;
	}

	return (error);
}


static void
nlm_init_lock(struct nlm4_lock *lock,
	const struct flock64 *fl, struct netobj *fh,
	struct nlm_owner_handle *oh)
{

	/* Caller converts to zero-base. */
	VERIFY(fl->l_whence == SEEK_SET);
	bzero(lock, sizeof (*lock));
	bzero(oh, sizeof (*oh));

	lock->caller_name = uts_nodename();
	lock->fh.n_len = fh->n_len;
	lock->fh.n_bytes = fh->n_bytes;
	lock->oh.n_len = sizeof (*oh);
	lock->oh.n_bytes = (void *)oh;
	lock->svid = curproc->p_pid;
	lock->l_offset = fl->l_start;
	lock->l_len = fl->l_len;
}

static int
nlm_locklist_has_unsafe_locks(struct locklist *ll)
{
	struct locklist *ll_next;
	int has = 0;

	while (ll) {
		if ((ll->ll_flock.l_start != 0) ||
		    (ll->ll_flock.l_len != 0))
			has = 1;

		ll_next = ll->ll_next;
		VN_RELE(ll->ll_vp);
		kmem_free(ll, sizeof (*ll));
		ll =ll_next;
	}

	return has;
}

/* ************************************************************** */

int
nlm_shrlock(struct vnode *vp, int cmd, struct shrlock *shr,
	int flags, struct netobj *fh, int vers)
{
	struct shrlock shlk;
	mntinfo_t *mi;
	servinfo_t *sv;
	const char *netid;
	struct nlm_host *host = NULL;
	int error, xflags;
	struct nlm_globals *g;

	mi = VTOMI(vp);
	sv = mi->mi_curr_serv;

	netid = nlm_netid_from_knetconfig(sv->sv_knconf);
	if (netid == NULL) {
		NLM_ERR("nlm_shrlock: unknown NFS netid\n");
		return (ENOSYS);
	}

	g = zone_getspecific(nlm_zone_key, curzone);
	host = nlm_host_findcreate(g, sv->sv_hostname, netid, &sv->sv_addr);
	if (host == NULL)
		return (ENOSYS);

	/*
	 * Fill in s_sysid for the local locking calls.
	 * Also, let's not trust the caller's l_pid.
	 */
	shlk = *shr;
	shlk.s_sysid = NLM_SYSID_CLIENT | nlm_host_get_sysid(host);
	shlk.s_pid = curproc->p_pid;

	if (cmd == F_UNSHARE) {
		/*
		 * Purge local (cached) share information first,
		 * then clear the remote share.
		 */
		(void) nlm_local_shrlock(vp, &shlk, cmd, flags);
		error = nlm_call_unshare(vp, &shlk, host, fh, vers);
		goto out;
	}

	/*
	 * Do the NLM_SHARE RPC.
	 * XXX: Check flags & (FREAD | FWRITE) ?
	 */

	error = nlm_call_share(vp, &shlk, host, fh, vers, FALSE);
	if (error != 0)
		goto out;

	/*
	 * Save the share locally.  This should not fail,
	 * because the server is authoritative about shares
	 * and it just told us we have the share reservation!
	 */
	error = nlm_local_shrlock(vp, shr, cmd, flags);
	if (error != 0) {
		/*
		 * Oh oh, we really don't expect an error here.
		 * XXX: release the remote lock?  Or what?
		 * Ignore the local error for now...
		 */
		NLM_ERR("NLM: set locally, err %d\n", error);
		error = 0;
	}

	/* Start monitoring this host. */
	nlm_host_monitor(g, host, 0);

out:
	nlm_host_release(g, host);

	return (error);
}

/*
 * XXX: share recovery stuff?
 */

/*
 * Moved these to nlm_client.c:
 * nlm_share_rpc
 * nlm_unshare_rpc
 */

/*
 * Set local share information for some NFS server.
 *
 * Called after a share request (set or clear) succeeded. We record
 * the details in the local lock manager. Note that since the remote
 * server has granted the share, we can be sure that it doesn't
 * conflict with any other shares we have in the local lock manager.
 *
 * Since it is possible that host may also make NLM client requests to
 * our NLM server, we use a different sysid value to record our own
 * client shares.
 */
int
nlm_local_shrlock(vnode_t *vp, struct shrlock *shr, int cmd, int flags)
{
	return (fs_shrlock(vp, cmd, shr, flags, CRED(), NULL));
}

/*
 * Do NLM_SHARE call.
 * Was: nlm_setshare()
 */
static int
nlm_call_share(vnode_t *vp, struct shrlock *shr,
	struct nlm_host *host, struct netobj *fh,
	int vers, int reclaim)
{
	return (ENOTSUP);

#if 0 /* XXX: temporary unsupported */
	struct nlm4_shareargs args;
	struct nlm4_shareres res;
	struct nlm_owner_handle oh;
	struct nlm_globals *g;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	g = zone_getspecific(nlm_zone_key, curzone);
	nlm_init_share(&args.share, shr, fh, &oh);

	args.reclaim = reclaim;
	oh.oh_sysid = nlm_host_get_sysid(host);
	xid = atomic_inc_32_nv(&nlm_xid);
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;


	for (;;) {
		nlm_rpc_t *rpcp;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(host, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_share_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(host, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(share__res, enum nlm4_stat, res.stat);
		xdr_free((xdrproc_t)xdr_nlm4_shareres, (void *)&res);
		if (res.stat == nlm4_denied_grace_period) {
			if (args.reclaim)
				return (ENOLCK);

			nlm_wait_grace();
		}

		break;
	}

	switch (res.stat) {
	case nlm4_granted:
		error = 0;
		break;
	case nlm4_blocked:
	case nlm4_denied:
		error = EAGAIN;
		break;
	case nlm4_denied_nolocks:
	case nlm4_deadlck:
		error = ENOLCK;
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
#endif
}

/*
 * Do NLM_UNSHARE call.
 */
static int
nlm_call_unshare(struct vnode *vp, struct shrlock *shr,
	struct nlm_host *host, struct netobj *fh, int vers)
{
	return (ENOTSUP);

#if 0 /* XXX: temporary unsupported */
	struct nlm4_shareargs args;
	struct nlm4_shareres res;
	struct nlm_owner_handle oh;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	nlm_init_share(&args.share, shr, fh, &oh);

	oh.oh_sysid = nlm_host_get_sysid(host);
	xid = atomic_inc_32_nv(&nlm_xid);
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;

	for (;;) {
		nlm_rpc_t *rpcp;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(host, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_unshare_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(host, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(unshare__res, enum nlm4_stat, res.stat);
		xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res);
		if (res.stat == nlm4_denied_grace_period)
			nlm_wait_grace();

		break;
	}

	switch (res.stat) {
	case nlm4_granted:
		error = 0;
		break;
	case nlm4_denied:
		error = EAGAIN;
		break;
	case nlm4_denied_nolocks:
		error = ENOLCK;
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
#endif
}

static void
nlm_init_share(struct nlm4_share *args,
	const struct shrlock *shr, struct netobj *fh,
	struct nlm_owner_handle *oh)
{

	bzero(args, sizeof (*args));
	bzero(oh, sizeof (*oh));

	args->caller_name = uts_nodename();
	args->fh.n_len = fh->n_len;
	args->fh.n_bytes = fh->n_bytes;
	args->oh.n_len = sizeof (*oh);
	args->oh.n_bytes = (void *)oh;

	switch (shr->s_deny) {
	default:
	case F_NODNY:
		args->mode = fsm_DN;
		break;
	case F_RDDNY:
		args->mode = fsm_DR;
		break;
	case F_WRDNY:
		args->mode = fsm_DW;
		break;
	case F_RWDNY:
		args->mode = fsm_DRW;
		break;
	}

	switch (shr->s_access) {
	default:
	case 0:	/* seen with F_UNSHARE */
		args->access = fsa_NONE;
		break;
	case F_RDACC:
		args->access = fsa_R;
		break;
	case F_WRACC:
		args->access = fsa_W;
		break;
	case F_RWACC:
		args->access = fsa_RW;
		break;
	}
}

/*
 * Called when remote NLM server is
 * in grace period. We need to block
 * for some time.
 */
static void
nlm_wait_grace(void)
{
	(void) delay_sig(SEC_TO_TICK(5));
}

/*
 * Initialize filehandle according to the version
 * of NFS vnode was created on. The version of
 * NLM that can be used with given NFS version
 * is saved to lm_vers.
 */
static int
nlm_init_fh_by_vp(vnode_t *vp, struct netobj *fh, rpcvers_t *lm_vers)
{
	mntinfo_t *mi = VTOMI(vp);

	/*
	 * Too bad the NFS code doesn't just carry the FH
	 * in a netobj or a netbuf.
	 */
	switch (mi->mi_vers) {
	case NFS_V3:
		/* See nfs3_frlock() */
		*lm_vers = NLM4_VERS;
		fh->n_len = VTOFH3(vp)->fh3_length;
		fh->n_bytes = (char *)&(VTOFH3(vp)->fh3_u.data);
		break;

	case NFS_VERSION:
		/* See nfs_frlock() */
		*lm_vers = NLM_VERS;
		fh->n_len = sizeof (fhandle_t);
		fh->n_bytes = (char *)VTOFH(vp);
		break;
	default:
		return (ENOSYS);
	}

	return (0);
}

static int
nlm_map_clnt_stat(enum clnt_stat stat)
{
	switch (stat) {
	case RPC_SUCCESS:
		return (0);

	case RPC_TIMEDOUT:
	case RPC_PROGUNAVAIL:
		return (EAGAIN);

	case RPC_INTR:
		return (EINTR);

	default:
		return (EINVAL);
	}
}

static int
nlm_map_status(nlm4_stats stat)
{
	switch (stat) {
	case nlm4_granted:
		return (0);

	case nlm4_denied:
		return (EAGAIN);

	case nlm4_denied_nolocks:
		return (ENOLCK);

	case nlm4_blocked:
		return (EAGAIN);

	case nlm4_denied_grace_period:
		return (EAGAIN);

	case nlm4_deadlck:
		return (EDEADLK);

	case nlm4_rofs:
		return (EROFS);

	case nlm4_stale_fh:
		return (ESTALE);

	case nlm4_fbig:
		return (EFBIG);

	case nlm4_failed:
		return (EACCES);

	default:
		return (EINVAL);
	}
}
