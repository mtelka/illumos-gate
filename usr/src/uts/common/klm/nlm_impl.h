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
 *
 * $FreeBSD$
 */

/*
 * NFS Lock Manager (NLM) private declarations, etc.
 *
 * Source code derived from FreeBSD nlm.h
 */

#ifndef	_NLM_NLM_H_
#define	_NLM_NLM_H_

#include <sys/cmn_err.h>
#include <sys/queue.h>
#include <sys/modhash.h>
#include <sys/avl.h>

#define	RPC_MSGOUT(args...)	cmn_err(CE_NOTE, args)
#define	NLM_ERR(...)		cmn_err(CE_NOTE, __VA_ARGS__)
#define	NLM_WARN(...)		cmn_err(CE_WARN, __VA_ARGS__)

#ifndef	SEEK_SET
#define	SEEK_SET	0
#endif
#ifndef	SEEK_CUR
#define	SEEK_CUR	1
#endif
#ifndef	SEEK_END
#define	SEEK_END	2
#endif

struct nlm_host;
struct vnode;
struct exportinfo;

/*
 * Callback functions for nlm_do_lock() and others.
 *
 * Calls to nlm_do_lock are unusual, because it needs to handle
 * the reply itself, instead of letting it happen the normal way.
 * It also needs to make an RPC call _back_ to the client when a
 * blocked lock request completes.
 *
 * We pass three callback functions to nlm_do_lock:
 *    nlm_reply_cb: send a normal RPC reply
 *      nlm_res_cb: do a _res (message style) RPC (call)
 * nlm_testargs_cb: do a "granted" RPC call (after blocking)
 * Only one of the 1st or 2nd is used.
 * The 3rd is used only for blocking
 *
 * We also use callback functions for all the _msg variants
 * of the NLM svc calls, where the reply is a reverse call.
 * The nlm_testres_cb is used by the _test_msg svc calls.
 * The nlm_res_cb type is used by the other _msg calls.
 */
typedef bool_t (*nlm_reply_cb)(SVCXPRT *, nlm4_res *);
typedef enum clnt_stat (*nlm_res_cb)(nlm4_res *, void *, CLIENT *);
typedef enum clnt_stat (*nlm_testargs_cb)(nlm4_testargs *, void *, CLIENT *);
typedef enum clnt_stat (*nlm_testres_cb)(nlm4_testres *, void *, CLIENT *);

/*
 * Could use flock.h flk_nlm_status_t instead, but
 * prefer our own enum with initial zero...
 */
typedef enum {
	NLM_ST_DOWN = 0,
	NLM_ST_STOPPING,
	NLM_ST_UP,
	NLM_ST_STARTING
} nlm_run_status_t;

/*
 * Locks:
 * (l)		locked by nh_lock
 * (s)		only accessed via server RPC which is single threaded
 * (g)		locked by nlm_globals->lock
 * (c)		const until freeing
 * (a)		modified using atomic ops
 */

/*
 * NLM sleeping lock request.
 *
 * Sleeping lock requests are server side only objects
 * that are created when client asks server to add new
 * sleeping lock and when this lock needs to block.
 * Server keeps a track of these requests in order to be
 * able to cancel them or clean them up.
 *
 * Sleeping lock requests are closely tiled with particular
 * vnode or, strictly speaking, NLM vhold object that holds
 * the vnode.
 *
 * struct nlm_slreq:
 *   nsr_fl: an information about file lock
 *   nsr_link: a list node to store lock requests
 *             in vhold object.
 */
struct nlm_slreq {
	struct flock64		nsr_fl;
	TAILQ_ENTRY(nlm_slreq)	nsr_link;
};
TAILQ_HEAD(nlm_slreq_list, nlm_slreq);

/*
 * NLM vhold object is a sort of wrapper on vnodes remote
 * clients have locked (or added share reservation)
 * on NLM server. Vhold keeps vnode held (by VN_HOLD())
 * while vnode has any locks or shares made by parent host.
 * Vholds are used for two purposes:
 * 1) Hold vnode (with VN_HOLD) while it has any locks;
 * 2) Keep a track of all vnodes remote host touched
 *    with lock/share operations on NLM server, so that NLM
 *    can know what vnodes are potentially locked;
 *
 * Vholds are used on server side only. For server side it's really
 * important to keep vnodes held while they potentially have
 * any locks/shares. In contrast, it's not important for clinet
 * side at all. When particular vnode comes to the NLM client side
 * code, it's already held (VN_HOLD) by the process calling
 * lock/share function (it's referenced because client calls open()
 * before making locks or shares).
 *
 * Each NLM host object has a collection of vholds associated
 * with vnodes host touched earlier by adding locks or shares.
 * Having this collection allows us to decide if host is still
 * in use. When it has any vhold objects it's considered to be
 * in use. Otherwise we're free to destroy it.
 *
 * Vholds are destroyed by the NLM garbage collecter thread that
 * periodically checks whether they have any locks or shares.
 * Checking occures when parent host is untouched by client
 * or server for some period of time.
 *
 * struct nlm_vhold:
 *   nv_vp: a pointer to vnode that is hold by given nlm_vhold
 *   nv_refcnt: reference counter (non zero when vhold is inuse)
 *   nv_slreqs: sleeping lock requests that were made on the nv_vp
 *   nv_link: list node to store vholds in host's nh_vnodes_list
 */
struct nlm_vhold {
	vnode_t			*nv_vp;
	int			nv_refcnt;
	struct nlm_slreq_list	nv_slreqs;
	TAILQ_ENTRY(nlm_vhold)	nv_link;
};
TAILQ_HEAD(nlm_vhold_list, nlm_vhold);

/*
 * Client side sleeping lock state.
 * - NLM_SL_BLOCKED: some thread is blocked on this lock
 * - NLM_SL_GRANTED: server granted us the lock
 * - NLM_SL_CANCELLED: the lock is cancelled (i.e. invalid/inactive)
 */
typedef enum nlm_slock_state {
	NLM_SL_UNKNOWN = 0,
	NLM_SL_BLOCKED,
	NLM_SL_GRANTED,
	NLM_SL_CANCELLED
} nlm_slock_state_t;

/*
 * A client side sleeping lock request (set by F_SETLKW)
 * stored in nlm_slocks collection of nlm_globals.
 *
 *  struct nlm_slock
 *   nsl_state: Sleeping lock state.
 *             (see nlm_slock_state for more information)
 *   nsl_cond: Condvar that is used when sleeping lock
 *            needs to wait for a GRANT callback
 *            or cancellation event.
 *   nsl_lock: nlm4_lock structure that is sent to the server
 *   nsl_fh: Filehandle that corresponds to nw_vp
 *   nsl_host: A host owning this sleeping lock
 *   nsl_vp: A vnode sleeping lock is waiting on.
 *   nsl_link: A list node for nlm_globals->nlm_slocks list.
 */
struct nlm_slock {
	nlm_slock_state_t	nsl_state;
	kcondvar_t		nsl_cond;
	nlm4_lock		nsl_lock;
	struct netobj		nsl_fh;
	struct nlm_host		*nsl_host;
	struct vnode		*nsl_vp;
	TAILQ_ENTRY(nlm_slock)	nsl_link;
};
TAILQ_HEAD(nlm_slock_list, nlm_slock);

/*
 * NLM RPC handle object.
 *
 * In kRPC subsystem it's unsafe to use one RPC handle by
 * several threads simultaneously. It was designed so that
 * each thread has to create an RPC handle that it'll use.
 * RPC handle creation can be quite expensive operation, especially
 * with session oriented protocols (such as TCP) that need to
 * establish session at first. NLM RPC handle object is a sort of
 * wrapper on kRPC handle object that can be cached and used in
 * future. We store all created RPC handles for given host in a
 * host's RPC handles cache, so that to make new requests threads
 * can simply take ready objects from the cache. That improves
 * NLM performance.
 *
 * nlm_rpc_t:
 *   nr_handle: a kRPC handle itself.
 *   nr_vers: a version of NLM protocol kRPC handle was
 *            created for.
 *   nr_link: a list node to store NLM RPC handles in the host
 *            RPC handles cache.
 */
typedef struct nlm_rpc {
	CLIENT	  *nr_handle;
	rpcvers_t  nr_vers;
	TAILQ_ENTRY(nlm_rpc) nr_link;
} nlm_rpc_t;
TAILQ_HEAD(nlm_rpch_list, nlm_rpc);

/*
 * Describes the state of NLM host's RPC binding.
 * RPC binding can be in one of three states:
 * 1) NRPCB_NEED_UPDATE:
 *    Binding is either not initialized or stale.
 * 2) NRPCB_UPDATE_INPROGRESS:
 *    When some thread updates host's RPC binding,
 *    it sets binding's state to NRPCB_UPDATE_INPROGRESS
 *    which denotes that other threads must wait until
 *    update process is finished.
 * 3) NRPCB_UPDATED:
 *    Denotes that host's RPC binding is both initialized
 *    and fresh.
 */
enum nlm_rpcb_state {
	NRPCB_NEED_UPDATE = 0,
	NRPCB_UPDATE_INPROGRESS,
	NRPCB_UPDATED
};

/*
 * NLM host flags
 */
#define	NLM_NH_MONITORED 0x01
#define	NLM_NH_RECLAIM   0x02

/*
 * lm_sysid structure was used by old (closed source)
 * klmmod for (at least as it seems) the same purpose
 * we use nlm_host structure. lm_sysid can not be
 * simply removed, because it is used by the code
 * outside of klmmod. So we introduce it hear as
 * simple "compatibily layer". It's part of nlm_host
 * structure and it contains a pointer to parent
 * host.
 */
struct lm_sysid {
	struct nlm_host *ls_host;
};

/*
 * NLM host object is the most major structure in NLM.
 * It identifies remote client or remote server or both.
 * NLM host object keep a track of all vnodes client/server
 * locked and all sleeping locks it has. All lock/unlock
 * operations are done using host object.
 *
 * nlm_host:
 *   nh_lock: a mutex protecting host object fields
 *   nh_refs: reference counter. Identifies how many threads
 *            uses this host object.
 *   nh_link: a list node for keeping host in zone-global list.
 *   nh_by_addr: an AVL tree node for keeping host in zone-global tree.
 *              Host can be looked up in the tree by <netid, address>
 *              pair.
 *   nh_name: host name.
 *   nh_netid: netid string identifying type of transport host uses.
 *   nh_knc: host's knetconfig (used by kRPC subsystem).
 *   nh_addr: host's address (either IPv4 or IPv6).
 *   nh_lms: lm_sysid instance, for compatibility with old klmmod
 *   nh_sysid: unique sysid associated with this host.
 *   nh_state: last seen host's state reported by NSM.
 *   nh_flags: ORed host flags.
 *   nh_idle_timeout: host idle timeout. When expired host is freed.
 *   nh_recl_cv: condition variable used for reporting that reclamation
 *               process is finished.
 *   nh_rpcb_cv: condition variable that is used to make sure
 *               that only one thread renews host's RPC binding.
 *   nh_rpcb_ustat: error code returned by RPC binding update operation.
 *   nh_rpcb_state: host's RPC binding state (see enum nlm_rpcb_state
 *                  for more details).
 *   nh_rpchc: host's RPC handles cache.
 *   nh_vholds_by_vp: a hash table of all vholds host owns. (used for lookup)
 *   nh_vholds_list: a linked list of all vholds host owns. (used for iteration)
 */
struct nlm_host {
	kmutex_t		nh_lock;
	volatile uint_t		nh_refs;
	TAILQ_ENTRY(nlm_host)	nh_link;
	avl_node_t		nh_by_addr;
	char			*nh_name;
	char			*nh_netid;
	struct knetconfig	nh_knc;
	struct netbuf		nh_addr;
	struct lm_sysid		nh_lms;
	sysid_t			nh_sysid;
	int32_t			nh_state;
	clock_t			nh_idle_timeout;
	uint8_t			nh_flags;
	kcondvar_t		nh_recl_cv;
	kcondvar_t		nh_rpcb_cv;
	enum clnt_stat		nh_rpcb_ustat;
	enum nlm_rpcb_state	nh_rpcb_state;
	struct nlm_rpch_list	nh_rpchc;
	mod_hash_t		*nh_vholds_by_vp;
	struct nlm_vhold_list	nh_vholds_list;
};
TAILQ_HEAD(nlm_host_list, nlm_host);

/*
 * nlm_nsm structure describes RPC client handle that can be
 * used to communicate with local NSM via kRPC.
 *
 * We need to wrap handle with nlm_nsm structure because kRPC
 * can not share one handle between several threads. It's assumed
 * that NLM uses only one NSM handle per zone, thus all RPC operations
 * on NSM's handle are serialized using nlm_nsm->sem semaphore.
 *
 * nlm_nsm also contains refcnt field used for reference counting.
 * It's used because there exist a possibility of simultaneous
 * execution of NLM shutdown operation and host monitor/unmonitor
 * operations.
 *
 * struct nlm_nsm:
 *  ns_sem: a semaphore for serialization network operations to statd
 *  ns_knc: a kneconfig describing transport that is used for communication
 *  ns_addr: an address of local statd we're talking to
 *  ns_handle: an RPC handle used for talking to local statd
 */
struct nlm_nsm {
	ksema_t			ns_sem;
	struct knetconfig	ns_knc;
	struct netbuf		ns_addr;
	CLIENT			*ns_handle;
};

struct nlm_globals {
	kmutex_t			lock;
	clock_t				grace_threshold;
	pid_t				lockd_pid;
	nlm_run_status_t		run_status;
	int32_t				nsm_state;
	kthread_t			*nlm_gc_thread;
	kcondvar_t			nlm_gc_sched_cv;
	kcondvar_t			nlm_gc_finish_cv;
	struct nlm_nsm			nlm_nsm;
	avl_tree_t			nlm_hosts_tree;
	mod_hash_t			*nlm_hosts_hash;
	struct nlm_host_list		nlm_idle_hosts;
	struct nlm_slock_list		nlm_slocks;
	int				cn_idle_tmo;
	int				grace_period;
	int				retrans_tmo;
	TAILQ_ENTRY(nlm_globals)	nlm_link;
};
TAILQ_HEAD(nlm_globals_list, nlm_globals);


/*
 * This is what we pass as the "owner handle" for NLM_LOCK.
 * This lets us find the blocked lock in NLM_GRANTED.
 * It also exposes on the wire what we're using as the
 * sysid for any server, which can be very helpful for
 * problem diagnosis.  (Observability is good).
 */
struct nlm_owner_handle {
	sysid_t oh_sysid;		/* of remote host */
};

/*
 * Number retries NLM RPC call is repeatead in case of failure.
 * (used in case of conectionless transport).
 */
#define	NLM_RPC_RETRIES 5

/*
 * Klmmod global variables
 */
extern krwlock_t lm_lck;
extern zone_key_t nlm_zone_key;

/*
 * NLM interface functions (called directly by
 * either klmmod or klmpos)
 */
extern int nlm_frlock(struct vnode *, int, struct flock64 *, int, u_offset_t,
    struct cred *, struct netobj *, struct flk_callback *, int);
extern int nlm_shrlock(struct vnode *, int, struct shrlock *, int,
    struct netobj *, int);
extern int nlm_safemap(const vnode_t *);
extern int nlm_safelock(vnode_t *, const struct flock64 *, cred_t *);
extern int nlm_has_sleep(const vnode_t *);
extern void nlm_register_lock_locally(struct vnode *, struct lm_sysid *,
    struct flock64 *, int, u_offset_t);
int nlm_vp_active(const vnode_t *vp);
void nlm_sysid_free(sysid_t);
int nlm_vp_active(const vnode_t *);
void nlm_unexport(struct exportinfo *);

/*
 * NLM startup/shutdown
 */
int nlm_svc_starting(struct nlm_globals *, struct file *,
    const char *, struct knetconfig *);
void nlm_svc_stopping(struct nlm_globals *);
int nlm_svc_add_ep(struct nlm_globals *, struct file *,
    const char *, struct knetconfig *);

/*
 * NLM internal functions for initialization.
 */
void nlm_init(void);
void nlm_rpc_init(void);
void nlm_rpc_cache_destroy(struct nlm_host *);
void nlm_globals_register(struct nlm_globals *);
void nlm_globals_unregister(struct nlm_globals *);
sysid_t nlm_sysid_alloc(void);

/*
 * Client reclamation/cancelation
 */
void nlm_reclaim_client(struct nlm_globals *, struct nlm_host *);
void nlm_client_cancel_all(struct nlm_globals *, struct nlm_host *);

/* (nlm_rpc_clnt.c) */
enum clnt_stat nlm_null_rpc(CLIENT *, rpcvers_t);
enum clnt_stat nlm_test_rpc(nlm4_testargs *, nlm4_testres *,
    CLIENT *, rpcvers_t);
enum clnt_stat nlm_lock_rpc(nlm4_lockargs *, nlm4_res *,
    CLIENT *, rpcvers_t);
enum clnt_stat nlm_cancel_rpc(nlm4_cancargs *, nlm4_res *,
    CLIENT *, rpcvers_t);
enum clnt_stat nlm_unlock_rpc(nlm4_unlockargs *, nlm4_res *,
    CLIENT *, rpcvers_t);
enum clnt_stat nlm_share_rpc(nlm4_shareargs *, nlm4_shareres *,
    CLIENT *, rpcvers_t);
enum clnt_stat nlm_unshare_rpc(nlm4_shareargs *, nlm4_shareres *,
    CLIENT *, rpcvers_t);


/*
 * RPC service functions.
 * nlm_dispatch.c
 */
void nlm_prog_2(struct svc_req *rqstp, SVCXPRT *transp);
void nlm_prog_3(struct svc_req *rqstp, SVCXPRT *transp);
void nlm_prog_4(struct svc_req *rqstp, SVCXPRT *transp);

/*
 * Functions for working with knetconfigs (nlm_netconfig.c)
 */
const char *nlm_knc_to_netid(struct knetconfig *);
int nlm_knc_from_netid(const char *, struct knetconfig *);
void nlm_knc_activate(struct knetconfig *);

/*
 * NLM host functions (nlm_impl.c)
 */
struct nlm_host *nlm_host_findcreate(struct nlm_globals *, char *,
    const char *, struct netbuf *);
struct nlm_host *nlm_host_find(struct nlm_globals *,
    const char *, struct netbuf *);
struct nlm_host *nlm_host_find_by_sysid(struct nlm_globals *, sysid_t);
void nlm_host_release(struct nlm_globals *, struct nlm_host *);

void nlm_host_monitor(struct nlm_globals *, struct nlm_host *, int);
void nlm_host_unmonitor(struct nlm_globals *, struct nlm_host *);

void nlm_host_notify_server(struct nlm_host *, int32_t);
void nlm_host_notify_client(struct nlm_host *, int32_t);

int nlm_host_get_sysid(struct nlm_host *);
int nlm_host_get_state(struct nlm_host *);

struct nlm_vhold *nlm_vhold_get(struct nlm_host *, vnode_t *);
void nlm_vhold_release(struct nlm_host *, struct nlm_vhold *);
struct nlm_vhold *nlm_vhold_find_locked(struct nlm_host *, const vnode_t *);

struct nlm_slock *nlm_slock_register(struct nlm_globals *,
    struct nlm_host *, struct nlm4_lock *, struct vnode *);
void nlm_slock_unregister(struct nlm_globals *, struct nlm_slock *);
int nlm_slock_wait(struct nlm_globals *, struct nlm_slock *, uint_t);
int nlm_slock_grant(struct nlm_globals *,
    struct nlm_host *, struct nlm4_lock *);
void nlm_host_cancel_slocks(struct nlm_globals *, struct nlm_host *);

int nlm_slreq_register(struct nlm_host *,
    struct nlm_vhold *, struct flock64 *);
int nlm_slreq_unregister(struct nlm_host *,
    struct nlm_vhold *, struct flock64 *);

int nlm_host_wait_grace(struct nlm_host *);
int nlm_host_cmp(const void *, const void *);
void nlm_copy_netobj(struct netobj *, struct netobj *);

int nlm_host_get_rpc(struct nlm_host *, int, nlm_rpc_t **);
void nlm_host_rele_rpc(struct nlm_host *, nlm_rpc_t *);

/*
 * NLM server functions (nlm_service.c)
 */
int nlm_vp_active(const vnode_t *vp);
void nlm_do_notify1(nlm_sm_status *, void *, struct svc_req *);
void nlm_do_notify2(nlm_sm_status *, void *, struct svc_req *);
void nlm_do_test(nlm4_testargs *, nlm4_testres *,
    struct svc_req *, nlm_testres_cb);
void nlm_do_lock(nlm4_lockargs *, nlm4_res *, struct svc_req *,
    nlm_reply_cb, nlm_res_cb, nlm_testargs_cb);
void nlm_do_cancel(nlm4_cancargs *, nlm4_res *,
    struct svc_req *, nlm_res_cb);
void nlm_do_unlock(nlm4_unlockargs *, nlm4_res *,
    struct svc_req *, nlm_res_cb);
void nlm_do_granted(nlm4_testargs *, nlm4_res *,
    struct svc_req *, nlm_res_cb);
void nlm_do_share(nlm4_shareargs *, nlm4_shareres *, struct svc_req *);
void nlm_do_unshare(nlm4_shareargs *, nlm4_shareres *, struct svc_req *);
void nlm_do_free_all(nlm4_notify *, void *, struct svc_req *);

#endif	/* _NLM_NLM_H_ */
