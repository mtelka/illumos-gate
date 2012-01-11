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
 * NFS LockManager, start/stop, support functions, etc.
 * Most of the interesting code is here.
 *
 * Source code derived from FreeBSD nlm_prot_impl.c
 */

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
#include <sys/class.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <netinet/in.h>

#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <rpc/rpcb_prot.h>

#include <rpcsvc/nlm_prot.h>
#include <rpcsvc/sm_inter.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/export.h>
#include <nfs/rnode.h>

#include "nlm_impl.h"

/*
 * If a host is inactive (and holds no locks)
 * for this amount of seconds, we consider it
 * unused, so that we unmonitor and destroy it.
 */
#define	NLM_IDLE_TIMEOUT	300

/*
 * Number of attempts NLM tries to obtain RPC binding
 * of local statd.
 */
#define NLM_NSM_RPCBIND_RETRIES 10

/*
 * Timeout (in seconds) NLM waits before making another
 * attempt to obtain RPC binding of local statd.
 */
#define NLM_NSM_RPCBIND_TIMEOUT 5

/*
 * Given an interger x, the macro is returned
 * -1 if x is negative,
 *  0 if x is zero
 *  1 if x is positive
 */
#define SIGN(x) (((x) < 0) - ((x) > 0))

krwlock_t lm_lck;

/*
 * Grace period handling. The value of nlm_grace_threshold is the
 * Value of ddi_get_lbolt() after which we are serving requests normally.
 */
clock_t nlm_grace_threshold;

/*
 * List of all Zone globals nlm_globals instences
 * linked together.
 */
static struct nlm_globals_list nlm_zones_list;

/*
 * A sysid unique identifier allocated for each new host.
 * NOTE: nlm_next_sysid is shared between all zones, it _must_
 * be accessed very careful. Preferable way is to use atomic
 * operations.
 */
static volatile uint32_t nlm_next_sysid = 0;	/* (g) */

static recovery_cb nlm_recovery_func = NULL;	/* (c) */

/*
 * NLM kmem caches
 */
static struct kmem_cache *nlm_hosts_cache = NULL;
static struct kmem_cache *nlm_vhold_cache = NULL;

/*
 * NLM NSM functions
 */
static int nlm_svc_create_nsm(struct knetconfig *, struct nlm_nsm **);
static void nlm_svc_destroy_nsm(struct nlm_nsm *);
static struct nlm_nsm *nlm_svc_acquire_nsm(struct nlm_globals *);
static void nlm_svc_release_nsm(struct nlm_nsm *);

/*
 * NLM vhold functions
 */
static int nlm_vhold_ctor(void *, void *, int);
static void nlm_vhold_dtor(void *, void *);
static struct nlm_vhold *nlm_vhold_find_locked(struct nlm_host *hostp,
    vnode_t *vp);
static void nlm_vhold_destroy(struct nlm_host *hostp,
    struct nlm_vhold *nvp);
static bool_t nlm_vhold_busy(struct nlm_host *hostp, struct nlm_vhold *nvp);

/*
 * NLM host functions
 */
static void nlm_copy_netbuf(struct netbuf *dst, struct netbuf *src);
static int nlm_host_ctor(void *datap, void *cdrarg, int kmflags);
static void nlm_host_dtor(void *datap, void *cdrarg);
static void nlm_reclaim(void *cdrarg);
static void nlm_host_destroy(struct nlm_host *hostp);
static struct nlm_host *nlm_create_host(struct nlm_globals *g,
    char *name, const char *netid,
    struct knetconfig *knc, struct netbuf *naddr);
static int nlm_netbuf_addrs_cmp(struct netbuf *nb1, struct netbuf *nb2);
static struct nlm_host *nlm_host_find_locked(struct nlm_globals *g,
    const char *netid, struct netbuf *naddr, avl_index_t *wherep);
static void nlm_hosts_gc(struct nlm_globals *g);
static void nlm_host_unregister(struct nlm_globals *g, struct nlm_host *hostp);
static void nlm_host_gc_vholds(struct nlm_host *hostp);
static bool_t nlm_host_has_locks(struct nlm_host *hostp);


/*
 * NLM client/server sleeping locks functions
 */
static void nlm_slock_clnt_destroy(nlm_slock_clnt_t *nscp);
static void nlm_cancel_all_wait_locks(struct nlm_globals *g);
static nlm_slock_srv_t *nlm_slock_srv_find_locked(struct nlm_host *hostp,
    vnode_t *vp, struct flock64 *flp);


/*
 * Acquire the next sysid for remote locks not handled by the NLM.
 *
 * NOTE: the sysids generated by this function for hosts are
 * used later by os/flock.c subsystem. We must be very careful
 * when allocating new sysid because of two things:
 *  1) sysid #0 is used for local locks, then we don't want
 *     any host has this sysid. nlm_acquire_next_sysid never
 *     returns sysid #0.
 *  2) os/flock.c code expects that sysid consists from 2
 *     parts: 1st N bits block - sysid itself, second M bits block -
 *     NLM id (i.e. clusternode id). We don't deal with clustering,
 *     so the sysid nlm_acquire_next_sysid returns won't be greater
 *     than SYSIDMASK.
 */
static int
nlm_acquire_next_sysid(void)
{
	int next_sysid;

	for (;;) {
		next_sysid = (int)atomic_inc_32_nv(&nlm_next_sysid);
		if ((next_sysid != 0) && (next_sysid <= SYSIDMASK))
			break;
	}

	return next_sysid;
}

/*********************************************************************
 * NLM initialization functions.
 */
void
nlm_init(void)
{
	nlm_hosts_cache = kmem_cache_create("nlm_host_cache",
	    sizeof (struct nlm_host), 0, nlm_host_ctor, nlm_host_dtor,
	    nlm_reclaim, NULL, NULL, 0);

	nlm_vhold_cache = kmem_cache_create("nlm_vhold_cache",
	    sizeof (struct nlm_vhold), 0, nlm_vhold_ctor, nlm_vhold_dtor,
	    NULL, NULL, NULL, 0);

	nlm_rpc_init();
	TAILQ_INIT(&nlm_zones_list);
}

void
nlm_globals_register(struct nlm_globals *g)
{
	rw_enter(&lm_lck, RW_WRITER);
	TAILQ_INSERT_TAIL(&nlm_zones_list, g, nlm_link);
	rw_exit(&lm_lck);
}

void
nlm_globals_unregister(struct nlm_globals *g)
{
	rw_enter(&lm_lck, RW_WRITER);
	TAILQ_REMOVE(&nlm_zones_list, g, nlm_link);
	rw_exit(&lm_lck);
}

static void
nlm_reclaim(void *cdrarg)
{
	struct nlm_globals *g;

	rw_enter(&lm_lck, RW_READER);
	TAILQ_FOREACH(g, &nlm_zones_list, nlm_link)
		cv_broadcast(&g->nlm_gc_sched_cv);

	rw_exit(&lm_lck);
}

/*
 * NLM garbage collector thread (GC).
 *
 * NLM GC periodically checks whether there're any host objects
 * that can be cleaned up. It also releases stale vnodes that
 * live on the server side (under protection of vhold objects).
 *
 * NLM host objects are cleaned up from GC thread because
 * operations helping us to determine whether given host has
 * any locks can be quite expensive and it's not good to call
 * them every time the very last reference to the host is dropped.
 * Thus we use "lazy" approach for hosts cleanup.
 *
 * The work of GC is to release stale vnodes on the server side
 * and destroy hosts that haven't any locks and any activity for
 * some time (i.e. idle hosts).
 */
static void
nlm_gc(struct nlm_globals *g)
{
	struct nlm_host *hostp;
	clock_t now, idle_period;

	idle_period = SEC_TO_TICK(NLM_IDLE_TIMEOUT);
	mutex_enter(&g->lock);
	for (;;) {
		/*
		 * GC thread can be explicitly scheduled from
		 * memory reclamation function.
		 */
		cv_timedwait(&g->nlm_gc_sched_cv, &g->lock,
		    ddi_get_lbolt() + idle_period);

		/*
		 * NLM is shutting down, time to die.
		 */
		if (g->run_status == NLM_ST_STOPPING)
			break;

		now = ddi_get_lbolt();
		DTRACE_PROBE2(gc__start, struct nlm_globals *, g,
		    clock_t, now);

		/*
		 * Handle all hosts that are unused at the moment
		 * until we meet one with idle timeout in future.
		 */
		while ((hostp = TAILQ_FIRST(&g->nlm_idle_hosts)) != NULL) {
			bool_t has_locks = FALSE;

			if (hostp->nh_idle_timeout > now)
				break;

			/*
			 * NOTE: it's important to drop nlm_globals lock
			 * before acquiring host lock, because order does
			 * matter. nlm_globals lock _always must be
			 * acquired before host lock and released after it.
			 */
			mutex_exit(&g->lock);
			mutex_enter(&hostp->nh_lock);

			/*
			 * nlm_globals lock was dropped earlier because
			 * garbage collecting of vholds and checking whether
			 * host has any locks/shares are expensive operations.
			 */
			nlm_host_gc_vholds(hostp);
			has_locks = nlm_host_has_locks(hostp);

			mutex_exit(&hostp->nh_lock);
			mutex_enter(&g->lock);

			/*
			 * While we were doing expensive operations outside of
			 * nlm_globals critical section, somebody could
			 * take the host, add lock/share to one of its vnodes
			 * and release the host back. If so, host's idle  timeout
			 * is renewed and our information about locks on the
			 * given host is outdated.
			 */
			if (hostp->nh_idle_timeout > now)
				continue;

			/*
			 * Either host has locks or somebody has began to
			 * use it while we were outside the nlm_globals critical
			 * section. In both cases we have to renew host's timeout
			 * and put it to the end of LRU list.
			 */
			if (has_locks || hostp->nh_refs > 0) {
				TAILQ_REMOVE(&g->nlm_idle_hosts, hostp, nh_link);
				hostp->nh_idle_timeout = now + idle_period;
				TAILQ_INSERT_TAIL(&g->nlm_idle_hosts, hostp, nh_link);
				continue;
			}

			/*
			 * We're here if all the following conditions hold:
			 * 1) Host hasn't any locks or share reservations
			 * 2) Host is unused
			 * 3) Host wasn't touched by anyone at least for
			 *    NLM_IDLE_TIMEOUT seconds.
			 *
			 * So, now we can destroy it.
			 */
			nlm_host_unregister(g, hostp);
			mutex_exit(&g->lock);

			nlm_host_unmonitor(g, hostp);
			nlm_host_destroy(hostp);
			mutex_enter(&g->lock);
		}

		DTRACE_PROBE(gc__end);
	}

	DTRACE_PROBE1(gc__exit, struct nlm_globals *, g);

	/* Let others know that GC has died */
	g->nlm_gc_thread = NULL;
	mutex_exit(&g->lock);

	cv_broadcast(&g->nlm_gc_finish_cv);
	zthread_exit();
}

/*********************************************************************
 * The in-kernel RPC (kRPC) subsystem uses TLI/XTI, which needs
 * both a knetconfig and an address when creating endpoints.
 * These functions keep track of the bindings give to us by
 * the user-level lockd, allowing fetch by "netid".
 */

/*
 * Copy a struct netobj.  (see xdr.h)
 */
void
nlm_copy_netobj(struct netobj *dst, struct netobj *src)
{
	dst->n_len = src->n_len;
	dst->n_bytes = kmem_alloc(src->n_len, KM_SLEEP);
	bcopy(src->n_bytes, dst->n_bytes, src->n_len);
}

/*********************************************************************
 * NLM functions responsible for operations on NSM handle.
 */

/*
 * Create an instance of nlm_nsm structure.
 * The function establishes new (and the only one) connection
 * with local statd and informs it that we're starting
 * or restarting with call SM_SIMU_CRASH.
 *
 * In case of success the function returns 0 and newly allocated
 * nlm_nsm is saved to out_nsm.
 */
static int
nlm_svc_create_nsm(struct knetconfig *knc, struct nlm_nsm **out_nsm)
{
	CLIENT *clnt = NULL;
	struct netbuf nb;
	struct nlm_nsm *nsm;
	char myaddr[SYS_NMLN + 2];
	enum clnt_stat stat;
	int error, retries;

	/*
	 * Get an RPC client handle for the local statd.
	 *
	 * Create the "self" host address, which is like
	 * "nodename.service" where the service is empty,
	 * and nodename is the zone's node name.
	 */
	nb.buf = myaddr;
	nb.maxlen = sizeof (myaddr);
	nb.len = snprintf(nb.buf, nb.maxlen, "%s.", uts_nodename());

	/*
	 * Try several times to get port of local statd service.
	 * If rpcbind_getaddr returns either RPC_INTR or
	 * RPC_PROGNOTREGISTERED, retry an attempt, but wait
	 * for NLM_NSM_RPCBIND_TIMEOUT seconds berofore.
	 */
	for (retries = 0; retries < NLM_NSM_RPCBIND_RETRIES; retries++) {
		stat = rpcbind_getaddr(knc, SM_PROG, SM_VERS, &nb);

		if (stat != RPC_INTR && stat != RPC_PROGNOTREGISTERED)
			break;

		delay(SEC_TO_TICK(NLM_NSM_RPCBIND_TIMEOUT));
	}

	if (stat != RPC_SUCCESS) {
		DTRACE_PROBE2(rpcbind__error, enum clnt_stat, stat,
		    int, retries);
		error = ENOENT;
		goto err;
	}

	/*
	 * Create a RPC handle that'll be used for
	 * communication with local statd
	 */
	error = clnt_tli_kcreate(knc, &nb, SM_PROG, SM_VERS,
	    0, NLM_RPC_RETRIES, CRED(), &clnt);
	if (error != 0)
		goto err;

	stat = sm_simu_crash_1(NULL, NULL, clnt);
	if (stat != RPC_SUCCESS) {
		struct rpc_err rpcerr;

		CLNT_GETERR(clnt, &rpcerr);
		error = rpcerr.re_errno;
		goto err;
	}

	nsm = kmem_zalloc(sizeof (*nsm), KM_SLEEP);
	sema_init(&nsm->sem, 1, NULL, SEMA_DEFAULT, NULL);
	nsm->refcnt = 1;
	nsm->handle = clnt;
	*out_nsm = nsm;

	return (0);

err:
	if (clnt != NULL)
		CLNT_DESTROY(clnt);

	return (error);
}

/*
 * Function destroes nlm_nsm structure and its mutex.
 * NOTE: must be called when nsm->refcnt == 0.
 * NOTE: nsm->handle must be released before this function is called.
 */
static void
nlm_svc_destroy_nsm(struct nlm_nsm *nsm)
{
	ASSERT(nsm->refcnt == 0);
	sema_destroy(&nsm->sem);
	kmem_free(nsm, sizeof(*nsm));
}

/*
 * Returns serialized nlm_nsm structure for given zone.
 * NOTE: the instance returned by this function must be
 * explicitly released by calling nlm_svc_release_nsm.
 */
static struct nlm_nsm *
nlm_svc_acquire_nsm(struct nlm_globals *g)
{
	struct nlm_nsm *nsm;

	mutex_enter(&g->lock);
	nsm = g->nlm_nsm;
	nsm->refcnt++;
	mutex_exit(&g->lock);

	sema_p(&nsm->sem);
	return nsm;
}

/*
 * Relases nlm_nsm instance.
 * If the function finds that it's the last reference to an instance,
 * it destroes nsm->handle (if any) and then destroes instance itself.
 */
static void
nlm_svc_release_nsm(struct nlm_nsm *nsm)
{
	sema_v(&nsm->sem);
	if (atomic_dec_uint_nv(&nsm->refcnt) == 0) {
		if (nsm->handle)
			CLNT_DESTROY(nsm->handle);

		nlm_svc_destroy_nsm(nsm);
	}
}

/*********************************************************************
 * NLM vhold functions
 *********************************************************************
 *
 * See comment to definition of nlm_vhold structure.
 *
 * NLM vhold object is a container of vnode on NLM side.
 * Vholds are used for two purposes:
 * 1) Hold vnode (with VN_HOLD) while it has any locks;
 * 2) Keep a track of all vnodes remote host touched
 *    with lock/share operations on NLM server, so that NLM
 *    can know what vnodes are potentially locked;
 *
 * Vholds are used on side only. For server side it's really
 * important to keep vnodes held while they potentially have
 * any locks/shares. In contrast, it's not important for clinet
 * side at all. When particular vnode comes to the NLM client side
 * code, it's already held (VN_HOLD) by the process calling
 * lock/share function (it's referenced because client calls open()
 * before making locks or shares).
 *
 * Vhold objects are cleaned up by GC thread when parent host
 * becomes idle and its idle timeout is expired.
 */

/*
 * Get NLM vhold object corresponding to vnode "vp".
 * If no such object was found, create a new one.
 *
 * The purpose of this function is to associate vhold
 * object with given vnode, so that:
 * 1) vnode is hold (VN_HOLD) while vhold object is alive.
 * 2) host has a track of all vnodes it touched by lock
 *    or share operations. These vnodes are accessible
 *    via collection of vhold objects.
 */
struct nlm_vhold *
nlm_vhold_get(struct nlm_host *hostp, vnode_t *vp)
{
	struct nlm_vhold *nvp, *new_nvp = NULL;

	mutex_enter(&hostp->nh_lock);
	nvp = nlm_vhold_find_locked(hostp, vp);
	if (nvp != NULL)
		goto out;

	/* nlm_vhold wasn't found, then create a new one */
	mutex_exit(&hostp->nh_lock);
	new_nvp = kmem_cache_alloc(nlm_vhold_cache, KM_SLEEP);

	/*
	 * Check if another thread has already
	 * created the same nlm_vhold.
	 */
	mutex_enter(&hostp->nh_lock);
	nvp = nlm_vhold_find_locked(hostp, vp);
	if (nvp == NULL) {
		nvp = new_nvp;
		new_nvp = NULL;

		nvp->nv_vp = vp;
		nvp->nv_refcnt = 1;
		VN_HOLD(nvp->nv_vp);

		VERIFY(mod_hash_insert(hostp->nh_vholds_by_vp,
		        (mod_hash_key_t)vp, (mod_hash_val_t)nvp) == 0);
		TAILQ_INSERT_TAIL(&hostp->nh_vholds_list, nvp, nv_link);
	}

out:
	mutex_exit(&hostp->nh_lock);
	if (new_nvp != NULL)
		kmem_cache_free(nlm_vhold_cache, new_nvp);

	return (nvp);
}

/*
 * Drop a reference to vhold object nvp.
 */
void
nlm_vhold_release(struct nlm_host *hostp, struct nlm_vhold *nvp)
{
	if (nvp == NULL)
		return;

	mutex_enter(&hostp->nh_lock);
	ASSERT(nvp->nv_refcnt > 0);
	nvp->nv_refcnt--;
	mutex_exit(&hostp->nh_lock);
}

static void
nlm_vhold_destroy(struct nlm_host *hostp, struct nlm_vhold *nvp)
{
	ASSERT(MUTEX_HELD(&hostp->nh_lock));
	ASSERT(nvp->nv_refcnt == 0);

	VERIFY(mod_hash_remove(hostp->nh_vholds_by_vp,
	        (mod_hash_key_t)nvp->nv_vp,
	        (mod_hash_val_t)&nvp) == 0);

	TAILQ_REMOVE(&hostp->nh_vholds_list, nvp, nv_link);
	VN_RELE(nvp->nv_vp);
	nvp->nv_vp = NULL;

	kmem_cache_free(nlm_vhold_cache, nvp);
}

/*
 * Return TRUE if the given vhold is busy.
 * Vhold object is considered to be "busy" when
 * all the following conditions hold:
 * 1) No one uses it at the moment;
 * 2) It hasn't any locks;
 * 3) It hasn't any share reservations;
 */
static bool_t
nlm_vhold_busy(struct nlm_host *hostp, struct nlm_vhold *nvp)
{
	vnode_t *vp;
	int32_t sysid;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	if (nvp->nv_refcnt > 0)
		return (TRUE);

	vp = nvp->nv_vp;
	sysid = hostp->nh_sysid;
	if (flk_has_remote_locks_for_sysid(vp, sysid) ||
	    shr_has_remote_shares(vp, sysid))
		return (TRUE);

	return (FALSE);
}

static int
nlm_vhold_ctor(void *datap, void *cdrarg, int kmflags)
{
	struct nlm_vhold *nvp = (struct nlm_vhold *)datap;

	bzero(nvp, sizeof (*nvp));
	return (0);
}

static void
nlm_vhold_dtor(void *datap, void *cdrarg)
{
	struct nlm_vhold *nvp = (struct nlm_vhold *)datap;
	ASSERT(nvp->nv_vp == NULL);
}

static struct nlm_vhold *
nlm_vhold_find_locked(struct nlm_host *hostp, vnode_t *vp)
{
	struct nlm_vhold *nvp = NULL;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));
	(void) mod_hash_find(hostp->nh_vholds_by_vp,
	    (mod_hash_key_t)vp,
	    (mod_hash_val_t)&nvp);

	if (nvp != NULL)
		nvp->nv_refcnt++;

	return (nvp);
}

/*
 * In the BSD code, this was called in the context of the
 * F_UNLCK caller that allowed our F_SETLKW to succeed.
 * Here, F_SETLKW is done from the RPC service thread in a way
 * that allows it to simply blocks in the F_SETLK call.
 * XXX: We probably don't need this function.
 */
#if 0 /* XXX */
static void
nlm_lock_callback(flk_cb_when_t when, void *arg)
{
	struct nlm_async_lock *af = (struct nlm_async_lock *)arg;

}
#endif

/*
 * Cancel pending blocked locks for this client.
 */
static void
nlm_destroy_client_pending(struct nlm_host *host)
{
	nlm_slock_srv_t *nssp, *next_nssp;

	ASSERT(MUTEX_HELD(&host->nh_lock));

	/*
	 * Cancel all blocked lock requests.
	 * The blocked threads will cleanup.
	 */
	nssp = TAILQ_FIRST(&host->nh_srv_slocks);
	while (nssp != NULL) {
		next_nssp = TAILQ_NEXT(nssp, nss_link);
#if 0
		(void) nlm_cancel_async_lock(nssp);
#endif
		nssp = next_nssp;
	}
}

/*
 * Destroy any locks the client holds.
 * Do F_UNLKSYS on all it's vnodes.
 */
static void
nlm_destroy_client_locks(struct nlm_host *host)
{
	struct nlm_vhold *nvp;
	struct flock64 fl;
	int flags;

	ASSERT(MUTEX_HELD(&host->nh_lock));

	bzero(&fl, sizeof (fl));
	fl.l_type = F_UNLKSYS;
	fl.l_sysid = host->nh_sysid;
	flags = F_REMOTELOCK | FREAD | FWRITE;

	TAILQ_FOREACH(nvp, &host->nh_vholds_list, nv_link) {
		(void) VOP_FRLOCK(nvp->nv_vp, F_SETLK, &fl,
		    flags, 0, NULL, CRED(), NULL);
	}
}

/*********************************************************************
 * NLM host functions
 */

static void
nlm_copy_netbuf(struct netbuf *dst, struct netbuf *src)
{
	ASSERT(src->len <= src->maxlen);

	dst->maxlen = src->maxlen;
	dst->len = src->len;
	dst->buf = kmem_zalloc(src->maxlen, KM_SLEEP);
	bcopy(src->buf, dst->buf, src->len);
}

static int
nlm_host_ctor(void *datap, void *cdrarg, int kmflags)
{
	struct nlm_host *hostp = (struct nlm_host *)datap;

	bzero(hostp, sizeof (*hostp));
	return (0);
}

static void
nlm_host_dtor(void *datap, void *cdrarg)
{
	struct nlm_host *hostp = (struct nlm_host *)datap;
	ASSERT(hostp->nh_refs == 0);
}

static void
nlm_host_unregister(struct nlm_globals *g, struct nlm_host *hostp)
{
	ASSERT(MUTEX_HELD(&g->lock));
	ASSERT(hostp->nh_refs == 0);

	avl_remove(&g->nlm_hosts_tree, hostp);
	VERIFY(mod_hash_remove(g->nlm_hosts_hash,
	        (mod_hash_key_t)(uintptr_t)hostp->nh_sysid,
	        (mod_hash_val_t)&hostp) == 0);
	TAILQ_REMOVE(&g->nlm_idle_hosts, hostp, nh_link);
}

/*
 * Free resources used by a host. This is called after the reference
 * count has reached zero so it doesn't need to worry about locks.
 */
static void
nlm_host_destroy(struct nlm_host *hostp)
{
	ASSERT(hostp->nh_name != NULL);
	ASSERT(hostp->nh_netid != NULL);
	ASSERT(TAILQ_EMPTY(&hostp->nh_srv_slocks));
	ASSERT(TAILQ_EMPTY(&hostp->nh_vholds_list));

	strfree(hostp->nh_name);
	strfree(hostp->nh_netid);
	kmem_free(hostp->nh_addr.buf, sizeof (struct netbuf));

	nlm_rpc_cache_destroy(hostp);

	ASSERT(TAILQ_EMPTY(&hostp->nh_vholds_list));
	mod_hash_destroy_ptrhash(hostp->nh_vholds_by_vp);

	mutex_destroy(&hostp->nh_lock);
	cv_destroy(&hostp->nh_rpcb_cv);

	kmem_cache_free(nlm_hosts_cache, hostp);
}

void
nlm_set_recovery_cb(recovery_cb func)
{
	nlm_recovery_func = func;
}


/*
 * Thread start callback for client lock recovery
 */
static void
nlm_client_recovery_start(void *arg)
{
	struct nlm_globals *g;
	struct nlm_host *host = (struct nlm_host *)arg;

	NLM_DEBUG(NLM_LL2, "NLM: client lock recovery for %s started\n",
	    host->nh_name);

	/* nlm_client_recovery(host); */
	if (nlm_recovery_func != NULL)
		(*nlm_recovery_func)(host);

	NLM_DEBUG(NLM_LL2, "NLM: client lock recovery for %s completed\n",
	    host->nh_name);

	g = zone_getspecific(nlm_zone_key, curzone);
	/* Note: refcnt was incremented before this thread started. */
	nlm_host_release(g, host);

	/* XXX kthread_exit(); */
}

/*
 * Cleanup SERVER-side state after a client restarts,
 * or becomes unresponsive, or whatever.
 *
 * This is called by the local NFS statd when we receive a
 * host state change notification.  (also nlm_svc_stopping)
 * XXX: Does NFS statd call us only after host restart?
 *
 * We unlock any active locks owned by the host. When rpc.lockd is
 * shutting down, this function is called with newstate set to zero
 * which allows us to cancel any pending async locks and clear the
 * locking state.
 */
void
nlm_host_notify_server(struct nlm_host *host, int32_t state)
{
}

/*
 * Cleanup CLIENT-side state after a server restarts,
 * or becomes unresponsive, or whatever.
 *
 * This is called by the local NFS statd when we receive a
 * host state change notification.  (also nlm_svc_stopping)
 *
 * Deal with a server restart.  If we are stopping the
 * NLM service, we'll have newstate == 0, and will just
 * cancel all our client-side lock requests.  Otherwise,
 * star the "recovery" process to reclaim any locks
 * we hold on this server.
 */

void
nlm_host_notify_client(struct nlm_host *host, int32_t state)
{

	/*
	 * XXX: Walk list of locks...
	 *   where we own it, and on system H,
	 *      count++
	 *
	 * See: flk_get_active_locks(sysid, NOPID);

XXX More porting work.  We only want there to ever be one recovery
thread running for each host.  So, we can let the host object carry
state about the recovery thread running, if any, etc.

So, here:  (a) check if there's a recovery thread yet, and if not,
mark that one is starting.  (b) get the list of locks for this sysid.
if no locks, mark recovery complete now and don't bother starting the
recovery thread.  If there are some locks, store that list in the host
object and start the recovery thread.  mark recovery as 'running'. */
}

/*
 * Create a new NLM host.
 */
static struct nlm_host *
nlm_create_host(struct nlm_globals *g, char *name,
    const char *netid, struct knetconfig *knc, struct netbuf *naddr)
{
	struct nlm_host *host;

	host = kmem_cache_alloc(nlm_hosts_cache, KM_SLEEP);

	mutex_init(&host->nh_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&host->nh_rpcb_cv, NULL, CV_DEFAULT, NULL);
	host->nh_refs = 1;

	host->nh_name = strdup(name);
	host->nh_netid = strdup(netid);
	host->nh_knc = *knc;
	nlm_copy_netbuf(&host->nh_addr, naddr);

	host->nh_state = 0;
	host->nh_rpcb_state = NRPCB_NEED_UPDATE;

	host->nh_vholds_by_vp = mod_hash_create_ptrhash("nlm vholds hash",
	    32, mod_hash_null_valdtor, sizeof (vnode_t));

	TAILQ_INIT(&host->nh_vholds_list);
	TAILQ_INIT(&host->nh_srv_slocks);
	TAILQ_INIT(&host->nh_rpchc);

	return (host);
}

/*
 * Garbage collect stale vhold objects.
 *
 * In other words check whether vnodes that are
 * held by vnold objects still have any locks
 * or shares or still in use. If they aren't,
 * just destroy them.
 */
static void
nlm_host_gc_vholds(struct nlm_host *hostp)
{
	struct nlm_vhold *nvp, *nvp_tmp;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));
	TAILQ_FOREACH_SAFE(nvp, nvp_tmp, &hostp->nh_vholds_list, nv_link) {
		if (nlm_vhold_busy(hostp, nvp))
			continue;

		nlm_vhold_destroy(hostp, nvp);
	}
}

/*
 * Determine whether the given host owns any
 * locks or share reservations.
 */
static bool_t
nlm_host_has_locks(struct nlm_host *hostp)
{
	int32_t clnt_sysid;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	/*
	 * Check the server side at first.
	 * It's cheap and simple: if server has
	 * any locks/shares there must be vhold
	 * object storing the affected vnode.
	 *
	 * NOTE: We don't need to check sleeping
	 * locks on the server side, because if
	 * server side sleeping lock is alive,
	 * there must be a vhold object corresponding
	 * to target vnode.
	 */
	if (!TAILQ_EMPTY(&hostp->nh_vholds_list))
		return (TRUE);

	/*
	 * Then check whether cliet side made any locks.
	 *
	 * XXX: It's not the way I'd like to do the check,
	 * because flk_sysid_has_locks() can be very
	 * expensive by design. Unfortunatelly it iterates
	 * throght all locks on the system, doesn't matter
	 * were they made on remote system via NLM or
	 * on local system via reclock. To understand the
	 * problem, consider that there're dozens of thousands
	 * of locks that are made on some ZFS dataset. And there's
	 * another dataset shared by NFS where NLM client had locks
	 * some time ago, but doesn't have them now.
	 * In this case flk_sysid_has_locks() will iterate
	 * thrught dozens of thousands locks until it returns us
 	 * FALSE.
	 * Oh, I hope that in shiny future somebody will make
	 * local lock manager (os/flock.c) better, so that
	 * it'd be more friedly to remote locks and
	 * flk_sysid_has_locks() wouldn't be so expensive.
	 */
	if (flk_sysid_has_locks(hostp->nh_sysid |
	        NLM_SYSID_CLIENT, FLK_QUERY_ACTIVE))
		return (TRUE);

	/*
	 * FIXME: Share reservations on the client side are
	 * temporary disabled. The reason is that there's no
	 * function similar to flk_sysid_has_locks() for share
	 * reservations, so we can not determine whether host
	 * has any shares. Actually os/share.c can answer a question
	 * whether particular _vnode_ has any shares. But on the
	 * client side we don't have a track of vnodes. The problem
	 * having collection of touched vnodes on the client side
	 * is that client (in contrast to server) must release vnode
	 * (by VN_RELE) ASAP, because NFS code won't be able to
	 * unmount the filesystem with some vnodes in use, it also
	 * has a tricy part of file removing code that would affect
	 * us if we would track vnodes on the client. NFS file
	 * removing functions (see nfs3_remove() as an example)
	 * won't remove a file if its vnode is held by someone.
	 * Instead it just renames a file and gives it randomly
	 * generated name (for example: .nfsB701). I don't know
	 * why it does this...
	 * So for this moment I don't know how to check whether
	 * host has share reservations without keeping track
	 * of vnodes touched by the host on the client side.
	 * Moreover, I don't know how to track vnodes on the
	 * client side without some modification of NFSv2/NFSv3
	 * code.
	 */

	return (FALSE);
}

/*
 * This function compares only addresses of two netbufs
 * that belong to NC_TCP[6] or NC_UDP[6] protofamily.
 * Port part of netbuf is ignored.
 *
 * Return values:
 *  -1: nb1's address is "smaller" than nb2's
 *   0: addresses are equal
 *   1: nb1's address is "greater" than nb2's
 */
static int
nlm_netbuf_addrs_cmp(struct netbuf *nb1, struct netbuf *nb2)
{
	union nlm_addr {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} *na1, *na2;
	int res;

	na1 = (union nlm_addr *)nb1->buf;
	na2 = (union nlm_addr *)nb2->buf;

	if (na1->sa.sa_family < na2->sa.sa_family)
		return (-1);
	if (na1->sa.sa_family > na2->sa.sa_family)
		return (1);

	switch (na1->sa.sa_family) {
	case AF_INET:
		res = memcmp(&na1->sin.sin_addr, &na2->sin.sin_addr,
		    sizeof (na1->sin.sin_addr));
		break;
	case AF_INET6:
		res = memcmp(&na1->sin6.sin6_addr, &na2->sin6.sin6_addr,
		    sizeof (na1->sin6.sin6_addr));
		break;
	default:
		VERIFY(0);
		break;
	}

	return (SIGN(res));
}

/*
 * Compare two nlm hosts.
 * Return values:
 * -1: host1 is "smaller" than host2
 *  0: host1 is equal to host2
 *  1: host1 is "greater" than host2
 */
int
nlm_host_cmp(const void *p1, const void *p2)
{
	struct nlm_host *h1 = (struct nlm_host *)p1;
	struct nlm_host *h2 = (struct nlm_host *)p2;
	int res;

	res = nlm_netbuf_addrs_cmp(&h1->nh_addr, &h2->nh_addr);
	if (res != 0)
		return (res);

	res = strcmp(h1->nh_netid, h2->nh_netid);
	return (SIGN(res));
}

/*
 * Find the host specified by...  (see below)
 * If found, increment the ref count.
 */
static struct nlm_host *
nlm_host_find_locked(struct nlm_globals *g, const char *netid,
    struct netbuf *naddr, avl_index_t *wherep)
{
	struct nlm_host *hostp, key;
	avl_index_t pos;

	ASSERT(MUTEX_HELD(&g->lock));

	key.nh_netid = (char *)netid;
	key.nh_addr.buf = naddr->buf;
	key.nh_addr.len = naddr->len;
	key.nh_addr.maxlen = naddr->maxlen;

	hostp = avl_find(&g->nlm_hosts_tree, &key, &pos);

	if (hostp != NULL) {
		/*
		 * Host is inuse now. Remove it from idle
		 * hosts list if needed.
		 */
		if (hostp->nh_refs == 0)
			TAILQ_REMOVE(&g->nlm_idle_hosts, hostp, nh_link);

		hostp->nh_refs++;
	}
	if (wherep != NULL)
		*wherep = pos;

	return (hostp);
}

/*
 * Find NLM host for the given name and address.
 */
struct nlm_host *
nlm_host_find(struct nlm_globals *g, const char *netid,
    struct netbuf *addr)
{
	struct nlm_host *hostp;

	mutex_enter(&g->lock);
	hostp = nlm_host_find_locked(g, netid, addr, NULL);
	mutex_exit(&g->lock);

	return (hostp);
}


/*
 * Find or create an NLM host for the given name and address.
 *
 * The remote host is determined by all of: name, netidd, address.
 * Note that the netid is whatever nlm_svc_add_ep() gave to
 * svc_tli_kcreate() for the service binding.  If any of these
 * are different, allocate a new host (new sysid).
 */
struct nlm_host *
nlm_host_findcreate(struct nlm_globals *g, char *name,
    const char *netid, struct netbuf *addr)
{
	int err;
	struct nlm_host *host, *newhost = NULL;
	struct knetconfig knc;
	avl_index_t where;

	mutex_enter(&g->lock);
	host = nlm_host_find_locked(g, netid, addr, NULL);
	mutex_exit(&g->lock);
	if (host != NULL)
		return (host);

	err = nlm_knetconfig_from_netid(netid, &knc);
	if (err)
		return (NULL);

	/*
	 * Do allocations (etc.) outside of mutex,
	 * and then check again before inserting.
	 */
	newhost = nlm_create_host(g, name, netid, &knc, addr);
	mutex_enter(&g->lock);
	host = nlm_host_find_locked(g, netid, addr, &where);
	if (host == NULL) {
		host = newhost;
		newhost = NULL;
		host->nh_sysid = nlm_acquire_next_sysid();

		/*
		 * Insert host to the hosts AVL tree that is
		 * used to lookup by <netid, address> pair.
		 */
		avl_insert(&g->nlm_hosts_tree, host, where);

		/*
		 * Insert host ot the hosts hash table that is
		 * used to lookup host by sysid.
		 */
		VERIFY(mod_hash_insert(g->nlm_hosts_hash,
		        (mod_hash_key_t)(uintptr_t)host->nh_sysid,
		        (mod_hash_val_t)host) == 0);
	}

	mutex_exit(&g->lock);
	if (newhost != NULL)
		nlm_host_destroy(newhost);

	return (host);
}

/*
 * Find the NLM host that matches the value of 'sysid'.
 * If found, return it with a new ref,
 * else return NULL.
 */
struct nlm_host *
nlm_host_find_by_sysid(struct nlm_globals *g, int sysid)
{
	mod_hash_val_t hval;
	struct nlm_host *hostp = NULL;

	mutex_enter(&g->lock);
	mod_hash_find(g->nlm_hosts_hash,
	    (mod_hash_key_t)(uintptr_t)sysid,
	    (mod_hash_val_t)&hostp);

	if (hostp == NULL)
		goto out;

	/*
	 * Host is inuse now. Remove it
	 * from idle hosts list if needed.
	 */
	if (hostp->nh_refs == 0)
		TAILQ_REMOVE(&g->nlm_idle_hosts, hostp, nh_link);

	hostp->nh_refs++;

out:
	mutex_exit(&g->lock);
	return (hostp);
}

/*
 * Release the given host.
 * I.e. drop a reference that was taken earlier by one of
 * the following functions: nlm_host_findcreate(), nlm_host_find(),
 * nlm_host_find_by_sysid().
 *
 * When the very last reference is dropped, host is moved to
 * so-called "idle state". All hosts that are in idle state
 * have an idle timeout. If timeout is expired, GC thread
 * checks whether hosts have any locks and if they heven't
 * any, it removes them.
 * NOTE: only unused hosts can be in idle state.
 */
void
nlm_host_release(struct nlm_globals *g, struct nlm_host *hostp)
{
	if (hostp == NULL)
		return;

	mutex_enter(&g->lock);
	ASSERT(hostp->nh_refs > 0);

	hostp->nh_refs--;
	if (hostp->nh_refs != 0) {
		mutex_exit(&g->lock);
		return;
	}

	/*
	 * The very last reference to the host was dropped,
	 * thus host is unused now. Set its idle timeout
	 * and move it to the idle hosts LRU list.
	 */
	hostp->nh_idle_timeout = ddi_get_lbolt() +
		SEC_TO_TICK(NLM_IDLE_TIMEOUT);

	TAILQ_INSERT_TAIL(&g->nlm_idle_hosts, hostp, nh_link);
	mutex_exit(&g->lock);
}

/*
 * Unregister this NLM host (NFS client) with the local statd
 * due to idleness (no locks held for a while).
 */
void
nlm_host_unmonitor(struct nlm_globals *g, struct nlm_host *host)
{
	mon_id args;
	sm_stat res;
	enum clnt_stat stat;
	struct nlm_nsm *nsm;

	VERIFY(host->nh_refs == 0);
	if (!(host->nh_flags & NLM_NH_MONITORED))
		return;

	/*
	 * We put our assigned system ID value in the priv field to
	 * make it simpler to find the host if we are notified of a
	 * host restart.
	 */
	args.mon_name = host->nh_name;
	args.my_id.my_name = uts_nodename();
	args.my_id.my_prog = NLM_PROG;
	args.my_id.my_vers = NLM_SM;
	args.my_id.my_proc = NLM_SM_NOTIFY1;

	/* Call SM_UNMON */
	nsm = nlm_svc_acquire_nsm(g);
	stat = sm_unmon_1(&args, &res, nsm->handle);
	if (stat != RPC_SUCCESS) {
		struct rpc_err err;

		CLNT_GETERR(nsm->handle, &err);
		nlm_svc_release_nsm(nsm);
		NLM_WARN("NLM: Failed to contact statd, stat=%d error=%d\n",
		    stat, err.re_errno);
		return;
	}

	nlm_svc_release_nsm(nsm);
	host->nh_flags &= ~NLM_NH_MONITORED;
	DTRACE_PROBE2(unmon__done, struct nlm_host *, host,
	    int, res.state);
}

/*
 * Ask the local NFS statd to begin monitoring this host.
 * It will call us back when that host restarts, using the
 * prog,vers,proc specified below, i.e. NLM_SM_NOTIFY1,
 * which is handled in nlm_do_notify1().
 */
void
nlm_host_monitor(struct nlm_globals *g, struct nlm_host *host, int state)
{
	struct mon args;
	sm_stat_res res;
	enum clnt_stat stat;
	struct nlm_nsm *nsm;

	if (state && !host->nh_state) {
		/*
		 * This is the first time we have seen an NSM state
		 * Value for this host. We record it here to help
		 * detect host reboots.
		 */
		host->nh_state = state;
	}

	mutex_enter(&host->nh_lock);
	if (host->nh_flags & NLM_NH_MONITORED) {
		mutex_exit(&host->nh_lock);
		return;
	}

	mutex_exit(&host->nh_lock);

	/*
	 * Tell statd how to call us with status updates for
	 * this host. Updates arrive via nlm_do_notify1().
	 *
	 * We put our assigned system ID value in the priv field to
	 * make it simpler to find the host if we are notified of a
	 * host restart.
	 */
	bzero(&args, sizeof (args));
	args.mon_id.mon_name = host->nh_name;
	args.mon_id.my_id.my_name = uts_nodename();
	args.mon_id.my_id.my_prog = NLM_PROG;
	args.mon_id.my_id.my_vers = NLM_SM;
	args.mon_id.my_id.my_proc = NLM_SM_NOTIFY1;
	bcopy(&host->nh_sysid, args.priv, sizeof (host->nh_sysid));

	/* Call SM_MON */
	nsm = nlm_svc_acquire_nsm(g);
	stat = sm_mon_1(&args, &res, nsm->handle);
	if (stat != RPC_SUCCESS) {
		struct rpc_err err;

		CLNT_GETERR(nsm->handle, &err);
		nlm_svc_release_nsm(nsm);
		NLM_WARN("Failed to contact local NSM, stat=%d, error=%d\n",
		    stat, err.re_errno);
		return;
	}

	nlm_svc_release_nsm(nsm);
	if (res.res_stat == stat_fail) {
		NLM_WARN("Local NSM refuses to monitor %s\n", host->nh_name);
		return;
	}

	mutex_enter(&host->nh_lock);
	host->nh_flags |= NLM_NH_MONITORED;
	mutex_exit(&host->nh_lock);
}

int
nlm_host_get_sysid(struct nlm_host *host)
{
	return (host->nh_sysid);
}

int
nlm_host_get_state(struct nlm_host *host)
{

	return (host->nh_state);
}

/*********************************************************************
 * NLM client/server sleeping locks
 */

/*
 * Our local client-side code calls this to block on a remote lock.
 * (See nlm_call_lock). This is here (in the server-side code)
 * because this server function gets the granted callback.
 */
nlm_slock_clnt_t *
nlm_slock_clnt_register(
	struct nlm_globals *g,
	struct nlm_host *host,
	struct nlm4_lock *lock,
	struct vnode *vp)
{
	struct nlm_owner_handle *oh;
	nlm_slock_clnt_t *nscp;

	ASSERT(lock->oh.n_len == sizeof (*oh));

	oh = (void *) lock->oh.n_bytes;
	nscp = kmem_zalloc(sizeof (*nscp), KM_SLEEP);
	cv_init(&nscp->nsc_cond, NULL, CV_DEFAULT, NULL);
	nscp->nsc_lock = *lock;
	nlm_copy_netobj(&nscp->nsc_fh, &nscp->nsc_lock.fh);
	nscp->nsc_state = NLM_WS_BLOCKED;
	nscp->nsc_host = host;
	nscp->nsc_vp = vp;

	mutex_enter(&g->lock);
	TAILQ_INSERT_TAIL(&g->nlm_clnt_slocks, nscp, nsc_link);
	mutex_exit(&g->lock);

	return (nscp);
}

/*
 * Remove this lock from the wait list.
 */
void
nlm_slock_clnt_deregister(struct nlm_globals *g, nlm_slock_clnt_t *nscp)
{
	mutex_enter(&g->lock);
	TAILQ_REMOVE(&g->nlm_clnt_slocks, nscp, nsc_link);
	mutex_exit(&g->lock);

	nlm_slock_clnt_destroy(nscp);
}

/*
 * Wait for a granted callback for a blocked lock request.
 * If a signal interrupted the wait, return EINTR -
 * the caller must arrange to send a cancellation to
 * the server. On success return 0.
 */
int
nlm_slock_clnt_wait(struct nlm_globals *g,
    nlm_slock_clnt_t *nscp, bool_t is_intr)
{
	struct nlm_host *host = nscp->nsc_host;
	int error = 0;

	/*
	 * If the granted message arrived before we got here,
	 * nw->nw_state will be GRANTED - in that case, don't sleep.
	 */
	mutex_enter(&g->lock);
	if (nscp->nsc_state == NLM_WS_BLOCKED) {
		if (!is_intr)
			cv_wait(&nscp->nsc_cond, &g->lock);
		else {
			if (cv_wait_sig(&nscp->nsc_cond, &g->lock) == 0)
				error = EINTR;
		}
	}

	TAILQ_REMOVE(&g->nlm_clnt_slocks, nscp, nsc_link);
	mutex_exit(&g->lock);

	if (error == 0) { /* Got cv_signal or didn't block */
		/*
		 * The granted message may arrive after the
		 * interrupt/timeout but before we manage to lock the
		 * mutex. Detect this by examining nw_lock.
		 */
		if (nscp->nsc_state == NLM_WS_CANCELLED)
			error = EINTR;

	} else { /* Was interrupted */
		/*
		 * The granted message may arrive after the
		 * interrupt/timeout but before we manage to lock the
		 * mutex. Detect this by examining nw_lock.
		 */
		if (nscp->nsc_state == NLM_WS_GRANTED)
			error = 0;
	}

	nlm_slock_clnt_destroy(nscp);
	return (error);
}

/*
 * Destroy nlm_waiting_lock structure instance
 */
static void
nlm_slock_clnt_destroy(nlm_slock_clnt_t *nscp)
{
	kmem_free(nscp->nsc_fh.n_bytes, nscp->nsc_fh.n_len);
	cv_destroy(&nscp->nsc_cond);
	kmem_free(nscp, sizeof (*nscp));
}

/*
 * Create and register new unique server-side sleeping lock.
 * If such a lock has been registered already the function
 * returns NULL.
 */
nlm_slock_srv_t *
nlm_slock_srv_create(struct nlm_host *hostp,
    vnode_t *vp, struct flock64 *flp)
{
	nlm_slock_srv_t *nssp, *tmp_nssp;

	nssp = kmem_zalloc(sizeof (*nssp), KM_SLEEP);
	nssp->nss_host = hostp;
	nssp->nss_vp = vp;
	nssp->nss_refcnt = 1;
	nssp->nss_fl = *flp;

	mutex_enter(&hostp->nh_lock);

	/*
	 * Check if other thead has already registered
	 * the same sleeping lock.
	 */
	tmp_nssp = nlm_slock_srv_find_locked(hostp, vp, flp);
	if (tmp_nssp != NULL) {
		/* Found a duplicate, free allocated lock */
		mutex_exit(&hostp->nh_lock);
		kmem_free(nssp, sizeof (*nssp));
		nssp = NULL;
	} else {
		/* Not found. Insert our new entry. */
		TAILQ_INSERT_TAIL(&hostp->nh_srv_slocks, nssp, nss_link);
		mutex_exit(&hostp->nh_lock);
	}

	return (nssp);
}

/*
 * Deregister and free server-side sleeping lock.
 */
void
nlm_slock_srv_deregister(struct nlm_host *hostp, nlm_slock_srv_t *nssp)
{
	mutex_enter(&hostp->nh_lock);
	if (--nssp->nss_refcnt > 0) {
		mutex_exit(&hostp->nh_lock);
		return;
	}

	TAILQ_REMOVE(&hostp->nh_srv_slocks, nssp, nss_link);
	mutex_exit(&hostp->nh_lock);

	kmem_free(nssp, sizeof (*nssp));
}

/*
 * Lookup server-side sleeping lock
 * by given file lock and vnode.
 */
nlm_slock_srv_t *
nlm_slock_srv_find(struct nlm_host *hostp,
    vnode_t *vp, struct flock64 *flp)
{
	nlm_slock_srv_t *nssp;

	mutex_enter(&hostp->nh_lock);
	nssp = nlm_slock_srv_find_locked(hostp, vp, flp);
	mutex_exit(&hostp->nh_lock);

	return (nssp);
}

/*
 * Find server-side sleeping lock by given vnode
 * and file lock structure.
 * NOTE: host's lock must be acquired.
 */
static nlm_slock_srv_t *
nlm_slock_srv_find_locked(struct nlm_host *hostp,
    vnode_t *vp, struct flock64 *flp)
{
	nlm_slock_srv_t *nssp = NULL;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));
	TAILQ_FOREACH(nssp, &hostp->nh_srv_slocks, nss_link) {
		if (nssp->nss_vp == vp &&
		    nssp->nss_fl.l_start	== flp->l_start &&
		    nssp->nss_fl.l_len == flp->l_len &&
		    nssp->nss_fl.l_pid == flp->l_pid &&
		    nssp->nss_fl.l_type == flp->l_type) {
			nssp->nss_refcnt++;
			break;
		}
	}

	return (nssp);
}

/*
 * Cancel all wait locks registered on the moment
 * function is called.
 * NOTE: nlm_cancel_all_wait_locks must be called
 * with g->lock acquired.
 */
static void
nlm_cancel_all_wait_locks(struct nlm_globals *g)
{
	nlm_slock_clnt_t * nscp;

	ASSERT(MUTEX_HELD(&g->lock));
	TAILQ_FOREACH(nscp, &g->nlm_clnt_slocks, nsc_link) {
		nscp->nsc_state = NLM_WS_CANCELLED;
		cv_broadcast(&nscp->nsc_cond);
	}
}

/* ******************************************************************* */

/*
 * Syscall interface with userland.
 * Bind RPC service endpoints.
 *
 * Local-only transports get a different set of programs than
 * network transports.  The local transport is used by statd
 * to call us back with host monitoring events using NLM_SM
 * (version==2) but for safety, don't let remote callers use
 * any calls in that program.
 */

/*
 * RPC service registrations for LOOPBACK,
 * allowed to call the real nlm_prog_2.
 * None of the others are used locally.
 */
static SVC_CALLOUT nlm_svcs_lo[] = {
	{ NLM_PROG, 2, 2, nlm_prog_2 }, /* NLM_SM */
};
static SVC_CALLOUT_TABLE nlm_sct_lo = {
	sizeof (nlm_svcs_lo) / sizeof (nlm_svcs_lo[0]),
	FALSE,	/* dynamically allocated? */
	nlm_svcs_lo	/* table above */
};

/*
 * RPC service registration for inet transports.
 * Note that the version 2 (NLM_SM) entries are
 * all NULL (noproc) in these dispatchers.
 */
static SVC_CALLOUT nlm_svcs_in[] = {
	{ NLM_PROG, 4, 4, nlm_prog_4 },	/* NLM4_VERS */
	{ NLM_PROG, 1, 3, nlm_prog_3 },	/* NLM_VERS - NLM_VERSX */
};
static SVC_CALLOUT_TABLE nlm_sct_in = {
	sizeof (nlm_svcs_in) / sizeof (nlm_svcs_in[0]),
	FALSE,	/* dynamically allocated? */
	nlm_svcs_in	/* table above */
};

static void nlm_xprtclose(const SVCMASTERXPRT *xprt);

/*
 * Called by klmmod.c when lockd adds a network endpoint
 * on which we should begin RPC services.
 */
int
nlm_svc_add_ep(struct nlm_globals *g, struct file *fp,
    const char *netid, struct knetconfig *knc)
{
	int err;
	SVCMASTERXPRT *xprt = NULL;
	SVC_CALLOUT_TABLE *sct;

	if (0 == strcmp(knc->knc_protofmly, NC_LOOPBACK))
		sct = &nlm_sct_lo;
	else
		sct = &nlm_sct_in;

	err = svc_tli_kcreate(fp, 0, (char *)netid, NULL, &xprt,
	    sct, nlm_xprtclose, NLM_SVCPOOL_ID, FALSE);
	if (err) {
		NLM_DEBUG(NLM_LL1, "nlm_svc_add_ep: svc_tli_kcreate failed for "
		    "<netid=%s, protofamily=%s> [ERR=%d]\n", netid, knc->knc_protofmly,
			err);
	}

	return (0);
}

/*
 * The first transport passed in by the user-level lockd is
 * the loopback we'll use to talk to the statd.  Check that
 * we get what we're expecting, and setup the RPC client
 * handle we'll used to talk to statd.
 *
 * Call chain: lm_svc -> klm_start_lm
 * NOTE: g->run_status must be NLM_ST_STARTING
 * Called  before lockd starts up service on the
 * first endpoint.
 */
int
nlm_svc_starting(struct nlm_globals *g, struct file *fp,
    const char *netid, struct knetconfig *knc)
{
	clock_t time_uptime;
	struct nlm_nsm *nsm;
	int err;

	VERIFY(g->run_status == NLM_ST_STARTING);
	VERIFY(g->nlm_gc_thread == NULL);
	VERIFY(g->nlm_nsm == NULL);

	/*
	 * Create an NLM garbage collector thread that will
	 * clean up stale vholds and hosts objects.
	 */
	g->nlm_gc_thread = zthread_create(NULL, 0, nlm_gc,
	    g, 0, minclsyspri);

	err = nlm_svc_create_nsm(knc, &nsm);
	if (err != 0) {
		NLM_WARN("NLM: Failed to contact to local NSM: errno=%d\n", err);
		err = EIO;
		goto shutdown_lm;
	}

	mutex_enter(&g->lock);
	VERIFY(g->nlm_nsm == NULL);

	g->nlm_nsm = nsm;
	time_uptime = ddi_get_lbolt();
	g->grace_threshold = time_uptime +
	    SEC_TO_TICK(g->grace_period);
	g->run_status = NLM_ST_UP;

	mutex_exit(&g->lock);

	/* Register endpoint used for communications with local NLM */
	err = nlm_svc_add_ep(g, fp, netid, knc);
	if (err)
		goto shutdown_lm;

	return (0);

shutdown_lm:
	/* XXX[DK]: Probably we should call nlm_svc_stopping here... */
	mutex_enter(&g->lock);
	if (g->nlm_nsm) {
		CLNT_DESTROY(g->nlm_nsm->handle);
		nlm_svc_destroy_nsm(g->nlm_nsm);
		g->nlm_nsm = NULL;
	}

	g->run_status = NLM_ST_DOWN;
	g->lockd_pid = 0;
	mutex_exit(&g->lock);
	return (err);
}

/*
 * Called by klmmod.c when lockd is going away.
 * Note: run_status == NLM_ST_STOPPING
 * XXX: figure out where to call this...
 */
void
nlm_svc_stopping(struct nlm_globals *g)
{
	struct nlm_host *host, *nhost;
	struct nlm_nsm *nsm;

	/*
	 * Trash all the existing state so that if the server
	 * restarts, it gets a clean slate. This is complicated by the
	 * possibility that there may be other threads trying to make
	 * client locking requests.

Set a flag to prevent creation of new host entries.
Walk existing host entries marking them "dead".
Wait for threads using them to leave...

	 * First we fake a client reboot notification which will
	 * cancel any pending async locks and purge remote lock state
	 * from the local lock manager. We release the reference from
	 * nlm_hosts to the host (which may remove it from the list
	 * and free it). After this phase, the only entries in the
	 * nlm_host list should be from other threads performing
	 * client lock requests. We arrange to defer closing the
	 * sockets until the last RPC client handle is released.
	 */
#if 0 /* XXX */
	mutex_enter(&g->lock);
	nlm_cancel_all_wait_locks(g);

	/* TAILQ_FOREACH_SAFE */
	host = TAILQ_FIRST(&g->nlm_hosts);
	while (host != NULL) {
		nhost = TAILQ_NEXT(host, nh_link);
		mutex_exit(&g->lock);
		nlm_host_notify_server(host, 0);
		/* nlm_host_release(host)	* XXX wrong... */
		mutex_enter(&g->lock);
		host = nhost;
	}
	/* TAILQ_FOREACH_SAFE */
	host = TAILQ_FIRST(&g->nlm_hosts);
	while (host != NULL) {
		nhost = TAILQ_NEXT(host, nh_link);
		mutex_enter(&host->nh_lock);

		if (host->nh_srvrpc.nr_client ||
		    host->nh_clntrpc.nr_client) {
			if (host->nh_addr.ss_family == AF_INET)
				v4_used++;
#ifdef INET6
			if (host->nh_addr.ss_family == AF_INET6)
				v6_used++;
#endif
			/*
			 * Note that the rpc over udp code copes
			 * correctly with the fact that a socket may
			 * be used by many rpc handles.
			 */
			if (host->nh_srvrpc.nr_client)
				CLNT_CONTROL(host->nh_srvrpc.nr_client,
				    CLSET_FD_CLOSE, 0);
			if (host->nh_clntrpc.nr_client)
				CLNT_CONTROL(host->nh_clntrpc.nr_client,
				    CLSET_FD_CLOSE, 0);
		}

		mutex_exit(&host->nh_lock);
		host = nhost;
	}

	nsm = g->nlm_nsm;
	g->nlm_nsm = NULL;
	mutex_exit(&g->lock);

	nlm_svc_release_nsm(nsm);

	if (!v4_used)
		soclose(nlm_socket);
	nlm_socket = NULL;
	if (!v6_used)
		soclose(nlm_socket6);
	nlm_socket6 = NULL;
#endif /* XXX */
}

/*
 * Called by the RPC code when it's done with this transport.
 */
static void nlm_xprtclose(const SVCMASTERXPRT *xprt)
{
	char *netid;

	netid = svc_getnetid(xprt);
	/* Destroy all hosts using this netid...  */
	(void) netid;

	/* XXX - todo */
}
