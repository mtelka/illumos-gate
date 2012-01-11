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

#ifndef	SEEK_SET
#define	SEEK_SET	0
#endif
#ifndef	SEEK_CUR
#define	SEEK_CUR	1
#endif
#ifndef	SEEK_END
#define	SEEK_END	2
#endif

/*
 * This value is added to host system IDs when recording NFS client
 * locks in the local lock manager.
 */
#define	NLM_SYSID_CLIENT	0x1000000

struct nlm_host;
struct vnode;

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
 * Per-zone NLM debug level.
 * NLM_LL0: no verbose output
 * NLM_LL1: verbose error messages
 * NLM_LL2: verbose debug output in monitor/unmonitor/recovery operations
 * NLM_LL3: verbose debug output in server functions
 *
 * NOTE: log level has sense only when NLM was compiled with DEBUG option.
 */
typedef enum {
	NLM_LL0 = 0,
	NLM_LL1,
	NLM_LL2,
	NLM_LL3,
} nlm_loglevel_t;

/*
 * Data structures
 */

/* XXX: temporary... */
extern zone_key_t nlm_zone_key;
extern clock_t nlm_grace_threshold;

/*
 * Locks:
 * (l)		locked by nh_lock
 * (s)		only accessed via server RPC which is single threaded XXX
 * (g)		locked by nlm_global_lock
 * (c)		const until freeing
 * (a)		modified using atomic ops
 */
/*
 * Debug level passed in from userland.
 */
#ifdef DEBUG
#define NLM_DEBUG(_level, ...)	  \
	do { \
		struct nlm_globals *__g; \
		(__g) = zone_getspecific(nlm_zone_key, curzone); \
		if ((__g)->loglevel >= (_level)) \
			cmn_err(CE_CONT, __VA_ARGS__); \
	} while (0)
#else /* !DEBUG */
#define NLM_DEBUG(_level, ...) ((void)0)
#endif /* DEBUG */

#define	NLM_ERR(...)	\
	cmn_err(CE_NOTE, __VA_ARGS__)

#define NLM_WARN(...) \
	cmn_err(CE_WARN, __VA_ARGS__)

enum {
	NV_JUSTBORN   = 0x01,
	NV_CHECKLOCKS = 0x02
};

/*
 * nlm_vnode structure keep a hold (be VN_HOLD) of active vnodes
 * locked by the client. The tree of vnodes is kept on both client
 * and server sides. Client side keeps a tree of vnodes client
 * locked on given host. Server side keeps a trree of vnodes
 * locked on the host by given client.
 *
 * Server uses nlm_vnodes tree to prevent vnodes to be destroyed
 * by VOP_INACTIVE. Client uses this tree to keep a track of all
 * vnodes it locked to simplify resources cleanup mechanism.
 *
 * struct nlm_vnode:
 *   nv_vp  - A pointer to vnode that is hold by given nlm_vnode
 *   nv_refs - Reference counter.
 *             The _refs member is or active functions calls,
 *             incremented in nlm_vnode_find[_fh]/nlm_vnode_findcreate[_fh]
 *             and decremented nlm_vnode_release.
 *   nv_flags - nlm_vnode ORed flags:
 *     NV_JUSTBORN: nlm_vnode is just born. It's a very first time
 *                  anyone uses it.
 *     NV_CHECKLOCKS: denotes that nlm_vnode_relese() must check whether
 *                    there're any locks in os/flock on given vnode
 *                    taken by given host. If there're no such locks,
 *                    nlm_vnode will be freed and vnode it holds will
 *                    be released.
 *   nv_tree - AVL tree node.
 */
struct nlm_vnode {
	vnode_t    *nv_vp;
	int         nv_refs;
	uint8_t     nv_flags;
	avl_node_t  nv_tree;
};

enum nlm_wait_state {
	NLM_WS_UNKNOWN = 0,
	NLM_WS_BLOCKED,
	NLM_WS_GRANTED,
	NLM_WS_CANCELLED
};

/*
 * A pending client-side lock request (we are the client)
 * stored on the nh_waiting list of the NLM host.
 */
struct nlm_waiting_lock {
	TAILQ_ENTRY(nlm_waiting_lock) nw_link;	/* (l) */
	enum nlm_wait_state	nw_state;	/* (l) */
	kcondvar_t	nw_cond;		/* (l) */
	nlm4_lock	nw_lock;		/* (c) */
	struct netobj	nw_fh;			/* (c) */
	int32_t		nw_sysid;		/* (c) */
	struct nlm_host *nw_host;		/* (c) */
	struct vnode	*nw_vp;			/* (c) */
};
TAILQ_HEAD(nlm_waiting_lock_list, nlm_waiting_lock);


/*
 * A pending server-side asynchronous lock request, stored on the
 * nh_pending list of the NLM host.
 */
struct nlm_async_lock {
	TAILQ_ENTRY(nlm_async_lock) af_link; /* (l) host's list of locks */
	struct nlm_host *af_host;	/* (c) host which is locking */
	struct vnode	*af_vp;		/* (l) vnode to lock */
	struct flock64	af_fl;		/* (c) lock details */
	int		af_flags;	/* (c) FREAD, etc. */
};
TAILQ_HEAD(nlm_async_lock_list, nlm_async_lock);

/*
 * NLM host.
 */
enum nlm_host_state {
	NLM_UNMONITORED,
	NLM_MONITORED,
	NLM_MONITOR_FAILED,
	NLM_RECOVERING
};

typedef struct nlm_rpc {
	CLIENT		*nr_handle;
	rpcvers_t	nr_vers;
	int         nr_sn;
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

typedef union nlm_addr {
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct sockaddr sa;
} nlm_addr_t;

struct nlm_host {
	kmutex_t	nh_lock;
	volatile uint_t	nh_refs;	/* (a) reference count */
	TAILQ_ENTRY(nlm_host) nh_link; /* (z) per-zone list of hosts */
	avl_node_t  nh_tree;
	char		*nh_name;	/* (c) printable name of host */
	char		*nh_netid;	/* TLI binding name */
	struct knetconfig nh_knc;	/* (c) knetconfig for nh_addr */
	nlm_addr_t	nh_addr;	/* (c) remote address of host */
	int32_t		nh_sysid;	/* (c) our allocaed system ID */
	int		nh_state;	/* (s) last seen NSM state of host */
	kcondvar_t nh_rpcb_cv;
	uint16_t nh_rpcb_sn;
	enum clnt_stat nh_rpcb_ustat;
	enum nlm_rpcb_state nh_rpcb_state;
	enum nlm_host_state nh_monstate; /* (l) local NSM monitoring state */
	time_t		nh_idle_timeout; /* (s) Time at which host is idle */
	struct nlm_rpch_list nh_rpchc; /* RPC handles cache */
	avl_tree_t nh_vnodes;
	struct nlm_async_lock_list nh_pending; /* (l) server-side waits */
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
 */
struct nlm_nsm {
	CLIENT *handle;
	ksema_t sem;
	volatile uint_t refcnt;
};

struct nlm_globals {
	kmutex_t lock;
	clock_t grace_threshold;
	pid_t lockd_pid;
	int nsm_state;
	nlm_run_status_t run_status;
	nlm_loglevel_t loglevel; /* Debug loglevel */
	kcondvar_t status_cv;
	struct nlm_nsm *nlm_nsm; /* An RPC client handle that can be used to communicate
		                        with the local NSM. */
	avl_tree_t nlm_hosts_tree;
	mod_hash_t *nlm_hosts_hash;
	struct nlm_host_list nlm_idle_hosts;
	struct nlm_waiting_lock_list nlm_wlocks; /* (l) client-side waiting locks */
	/* options from lockd */
	int cn_idle_tmo;
	int grace_period;
	int retrans_tmo;
};


/*
 * This is what we pass as the "owner handle" for NLM_LOCK.
 * This lets us find the blocked lock in NLM_GRANTED.
 * It also exposes on the wire what we're using as the
 * sysid for any server, which can be very helpful for
 * problem diagnosis.  (Observability is good).
 */
struct nlm_owner_handle {
	int oh_sysid;		/* of remote host */
};

/*
 * Number retries NLM RPC call is repeatead in case of failure.
 * (used in case of conectionless transport).
 */
#define NLM_RPC_RETRIES 5

/*
 * NLM internal functions for initialization.
 */
void nlm_vnodes_init(void);
void nlm_rpc_cache_init(void);
void nlm_rpc_cache_destroy(struct nlm_host *hostp);

/*
 * RPC handles cache: nlm_rpc_handle.c
 */

extern int nlm_host_get_rpc(struct nlm_host *hostp,
    int vers, nlm_rpc_t **rpcpp);
extern void nlm_host_rele_rpc(struct nlm_host *hostp, nlm_rpc_t *rpcp);
extern void nlm_host_invalidate_binding(struct nlm_host *hostp);


/* nlm_client.c */
int nlm_frlock(struct vnode *vp, int cmd, struct flock64 *flkp,
	int flag, u_offset_t offset, struct cred *crp,
	struct netobj *fhp, struct flk_callback *flcb, int vers);
int nlm_shrlock(struct vnode *vp, int cmd, struct shrlock *shr,
	int flag, struct netobj *fh, int vers);
int nlm_safemap(const vnode_t *vp);
int nlm_safelock(vnode_t *vp, const struct flock64 *fl, cred_t *cr);
int nlm_has_sleep(const vnode_t *vp);


/* nlm_rpc_clnt.c */
extern enum clnt_stat
nlm_test_rpc(nlm4_testargs *args, nlm4_testres *res,
    CLIENT *client, rpcvers_t vers);
extern enum clnt_stat
nlm_lock_rpc(nlm4_lockargs *args, nlm4_res *res,
	CLIENT *client, rpcvers_t vers);
extern enum clnt_stat
nlm_cancel_rpc(nlm4_cancargs *args, nlm4_res *res,
	CLIENT *client, rpcvers_t vers);
extern enum clnt_stat
nlm_unlock_rpc(nlm4_unlockargs *args, nlm4_res *res,
	CLIENT *client, rpcvers_t vers);
extern enum clnt_stat
nlm_share_rpc(nlm4_shareargs *args, nlm4_shareres *res,
	CLIENT *client, rpcvers_t vers);
extern enum clnt_stat
nlm_unshare_rpc(nlm4_shareargs *args, nlm4_shareres *res,
	CLIENT *client, rpcvers_t vers);


/*
 * RPC service functions.
 * nlm_dispatch.c
 */
void nlm_prog_2(struct svc_req *rqstp, SVCXPRT *transp);
void nlm_prog_3(struct svc_req *rqstp, SVCXPRT *transp);
void nlm_prog_4(struct svc_req *rqstp, SVCXPRT *transp);



/* New lockd process starting in this zone. */
int nlm_svc_starting(struct nlm_globals *g, struct file *fp,
    const char *netid, struct knetconfig *knc);
void nlm_svc_stopping(struct nlm_globals *g);

/* Start NLM service on the given endpoint. */
int nlm_svc_add_ep(struct nlm_globals *g, struct file *fp,
	const char *netid, struct knetconfig *knc);

/*
 * Copy a struct netobj.
 */
extern void nlm_copy_netobj(struct netobj *dst, struct netobj *src);

/*
 * Functions working with knetconfig
 */
void nlm_netconfigs_init(void);
int nlm_knetconfig_from_netid(const char *netid,
    /* OUT */ struct knetconfig *knc);
const char *nlm_netid_from_knetconfig(struct knetconfig *knc);
int nlm_build_knetconfig(int nfmly, int nproto,
    /* OUT */ struct knetconfig *out_knc);


extern int nlm_host_cmp(const void *p1, const void *p2);
extern struct nlm_host *nlm_host_findcreate(struct nlm_globals *g, char *name,
    const char *netid, struct netbuf *addr);
extern struct nlm_host * nlm_host_find(struct nlm_globals *g,
    const char *netid, struct netbuf *addr);
extern struct nlm_host *nlm_host_find_by_sysid(struct nlm_globals *g,
    int sysid);

/*
 * Register this NLM host with the local NSM so that we can be
 * notified if it reboots.
 */
void nlm_host_monitor(struct nlm_globals *g,
    struct nlm_host *host, int state);
void nlm_host_unmonitor(struct nlm_globals *g, struct nlm_host *host);

/*
 * Decrement the host reference count, freeing resources if the
 * reference count reaches zero.
 */
void nlm_host_release(struct nlm_globals *g, struct nlm_host *host);

void nlm_host_notify_server(struct nlm_host *host, int newstate);
void nlm_host_notify_client(struct nlm_host *host);

/*
 * Return the system ID for a host.
 */
extern int nlm_host_get_sysid(struct nlm_host *host);

/*
 * Return the remote NSM state value for a host.
 */
extern int nlm_host_get_state(struct nlm_host *host);


struct nlm_vnode * nlm_vnode_find(struct nlm_host *hostp,
    vnode_t *vp);
struct nlm_vnode * nlm_vnode_findcreate(struct nlm_host *hostp,
    vnode_t *vp);
struct nlm_vnode *nlm_vnode_find_fh(struct nlm_host *hostp,
	struct netobj *np);
struct nlm_vnode * nlm_vnode_findcreate_fh(struct nlm_host *hostp,
    struct netobj *np);
void nlm_vnode_release(struct nlm_host *hostp,
    struct nlm_vnode *nvp, bool_t check_locks);


/*
 * When sending a blocking lock request, we need to track the request
 * in our waiting lock list. We add an entry to the waiting list
 * before we send the lock RPC so that we can cope with a granted
 * message arriving at any time. Call this function before sending the
 * lock rpc. If the lock succeeds, call nlm_deregister_wait_lock with
 * the handle this function returns, otherwise nlm_wait_lock. Both
 * will remove the entry from the waiting list.
 */
extern void *nlm_register_wait_lock(struct nlm_globals *g,
    struct nlm_host *host, struct nlm4_lock *lock, struct vnode *vp);

/*
 * Deregister a blocking lock request. Call this if the lock succeeded
 * without blocking.
 */
extern void nlm_deregister_wait_lock(struct nlm_globals *g, void *handle);

/*
 * Wait for a granted callback for a blocked lock request, waiting at
 * most timo ticks. If no granted message is received within the
 * timeout, return EWOULDBLOCK. If a signal interrupted the wait,
 * return EINTR - the caller must arrange to send a cancellation to
 * the server. In both cases, the request is removed from the waiting
 * list.
 */
extern int nlm_wait_lock(struct nlm_globals *g,
    void *handle, bool_t is_intr);

int nlm_cancel_async_lock(struct nlm_async_lock *af);
void nlm_free_async_lock(struct nlm_async_lock *af);

/*
 * Called when a host restarts.
 */
void nlm_do_notify1(nlm_sm_status *, void *, struct svc_req *);
void nlm_do_notify2(nlm_sm_status *, void *, struct svc_req *);

/*
 * Implementation for lock testing RPCs. If the request was handled
 * successfully and rpcp is non-NULL, *rpcp is set to an RPC client
 * handle which can be used to send an async rpc reply. Returns zero
 * if the request was handled, or a suitable unix error code
 * otherwise.
 */
void nlm_do_test(nlm4_testargs *, nlm4_testres *,
    struct svc_req *, nlm_testres_cb);

/*
 * Implementation for lock setting RPCs.
 * See above for callback typedefs.
 */
void nlm_do_lock(nlm4_lockargs *, nlm4_res *, struct svc_req *,
    nlm_reply_cb, nlm_res_cb, nlm_testargs_cb);

/*
 * Implementation for cancelling a pending lock request. If the
 * request was handled successfully and rpcp is non-NULL, *rpcp is set
 * to an RPC client handle which can be used to send an async rpc
 * reply. Returns zero if the request was handled, or a suitable unix
 * error code otherwise.
 */
void nlm_do_cancel(nlm4_cancargs *, nlm4_res *,
    struct svc_req *, nlm_res_cb);

/*
 * Implementation for unlocking RPCs. If the request was handled
 * successfully and rpcp is non-NULL, *rpcp is set to an RPC client
 * handle which can be used to send an async rpc reply. Returns zero
 * if the request was handled, or a suitable unix error code
 * otherwise.
 */
void nlm_do_unlock(nlm4_unlockargs *, nlm4_res *,
    struct svc_req *, nlm_res_cb);

/*
 * Implementation for granted RPCs. If the request was handled
 * successfully and rpcp is non-NULL, *rpcp is set to an RPC client
 * handle which can be used to send an async rpc reply. Returns zero
 * if the request was handled, or a suitable unix error code
 * otherwise.
 */
void nlm_do_granted(nlm4_testargs *, nlm4_res *,
    struct svc_req *, nlm_res_cb);

/*
 * Implementation for share/unshare RPCs.
 */
void nlm_do_share(nlm4_shareargs *, nlm4_shareres *, struct svc_req *);
void nlm_do_unshare(nlm4_shareargs *, nlm4_shareres *, struct svc_req *);

/*
 * Free all locks associated with the hostname argp->name.
 */
void nlm_do_free_all(nlm4_notify *, void *, struct svc_req *);

/*
 * Recover client lock state after a server reboot.
 */
typedef void (*recovery_cb)(struct nlm_host *);
extern void nlm_client_recovery(struct nlm_host *);
void nlm_set_recovery_cb(recovery_cb);

/*
 * Interface from NFS client code to the NLM.
 */
struct vop_advlock_args;
struct vop_reclaim_args;
extern int nlm_advlock(struct vop_advlock_args *ap);
extern int nlm_reclaim(struct vop_reclaim_args *ap);

#endif	/* _NLM_NLM_H_ */
