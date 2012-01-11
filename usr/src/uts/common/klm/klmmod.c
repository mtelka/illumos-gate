/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy is of the CDDL is also available via the Internet
 * at http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2010 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * NFS Lock Manager, server-side and common.
 *
 * This file contains all the external entry points of klmmod.
 * Basically, this is the "glue" to the BSD nlm code.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/flock.h>

#include <nfs/nfs.h>
#include <nfs/nfssys.h>
#include <nfs/lm.h>
#include <rpcsvc/nlm_prot.h>
#include "nlm_impl.h"

static struct modlmisc modlmisc = {
	&mod_miscops, "lock mgr common module"
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};

/*
 * Cluster node ID.  Zero unless we're part of a cluster.
 * Set by lm_set_nlmid_flk.  Pass to lm_set_nlm_status.
 * We're not yet doing "clustered" NLM stuff.
 */
int lm_global_nlmid = 0;

/*
 * Call-back hook for clusters: Set lock manager status.
 * If this hook is set, call this instead of the ususal
 * flk_set_lockmgr_status(FLK_LOCKMGR_UP / DOWN);
 */
void (*lm_set_nlm_status)(int nlm_id, flk_nlm_status_t) = NULL;

/*
 * Call-back hook for clusters: Delete all locks held by sysid.
 * Call from code that drops all client locks (for which we're
 * the server) i.e. after the SM tells us a client has crashed.
 */
void (*lm_remove_file_locks)(int) = NULL;

kmutex_t		lm_lck;
zone_key_t		nlm_zone_key;

/*
 * ****************************************************************
 * Stubs called in _init/_fini
 */

/*
 * Init/fini our collection of "sysid" mappings, which are
 * local numeric short-hand identifiers for remote systems
 * for which we're tracking locks.  See lm_get_sysid().
 */
void
lm_sysid_init()
{
}

void
lm_sysid_fini()
{
}

/*
 * Init/fini per-zone stuff for klm
 */
void *
lm_zone_init(zoneid_t zoneid)
{
	struct nlm_globals *g;

	g = kmem_zalloc(sizeof (*g), KM_SLEEP);

	avl_create(&g->nlm_hosts_tree, nlm_host_cmp,
	    sizeof (struct nlm_host),
	    offsetof(struct nlm_host, nh_tree));

	g->nlm_hosts_hash = mod_hash_create_idhash("nlm_host_by_sysid",
	    64, mod_hash_null_valdtor);

	TAILQ_INIT(&g->nlm_idle_hosts);
	TAILQ_INIT(&g->nlm_wlocks);

	mutex_init(&g->lock, NULL, MUTEX_DEFAULT, NULL);
	g->lockd_pid = 0;
	g->run_status = NLM_ST_DOWN;

	return (g);
}

void
lm_zone_fini(zoneid_t zoneid, void *data)
{
	struct nlm_globals *g = data;

	ASSERT(avl_is_empty(&g->nlm_hosts_tree));
	avl_destroy(&g->nlm_hosts_tree);
	mod_hash_destroy_idhash(g->nlm_hosts_hash);
	mutex_destroy(&g->lock);

	kmem_free(g, sizeof (*g));
}



/*
 * ****************************************************************
 * module init, fini, info
 */
int
_init()
{
	int retval;

	mutex_init(&lm_lck, NULL, MUTEX_DEFAULT, NULL);
	zone_key_create(&nlm_zone_key, lm_zone_init, NULL, lm_zone_fini);
	/* Per-zone lockmgr data.  See: os/flock.c */
	zone_key_create(&flock_zone_key, flk_zone_init, NULL, flk_zone_fini);
	lm_sysid_init();

	nlm_vnodes_init();
	nlm_rpc_cache_init();

	retval = mod_install(&modlinkage);
	if (retval == 0)
		return (0);

	/*
	 * mod_install failed! undo above, reverse order
	 */

	lm_sysid_fini();
	(void) zone_key_delete(flock_zone_key);
	flock_zone_key = ZONE_KEY_UNINITIALIZED;
	(void) zone_key_delete(nlm_zone_key);
	mutex_destroy(&lm_lck);

	return (retval);
}

int
_fini()
{
	/* Don't unload. */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/*
 * ****************************************************************
 * Stubs listed in modstubs.s
 */

/*
 * klm system calls.  Start service on some endpoint.
 * Called by nfssys() LM_SVC, from lockd.
 */
int
lm_svc(struct lm_svc_args *args)
{
	struct knetconfig knc;
	const char *netid;
	struct nlm_globals *g;
	struct file *fp = NULL;
	int err = 0;
	bool_t nlm_started = FALSE;

	/* Get our "globals" */
	g = zone_getspecific(nlm_zone_key, curzone);

	/*
	 * Check version of lockd calling.
	 */
	if (args->version != LM_SVC_CUR_VERS) {
		NLM_ERR("lm_svc: Version mismatch (given 0x%x, expected 0x%x)\n",
		    args->version, LM_SVC_CUR_VERS);
		return (EINVAL);
	}

	/*
	 * Validate log level
	 */
	if ((args->debug < NLM_LL0) || (args->debug > NLM_LL3)) {
		NLM_WARN("lm_svc: Unexpected loglevel %d\n", args->debug);
		args->debug = NLM_LL0;
	}

	/*
	 * Build knetconfig, checking arg values.
	 * Also come up with the "netid" string.
	 * (With some knowledge of /etc/netconfig)
	 *
	 * FIXME[DK]: Later we have to decide how to pass
	 * netid/knetconfig arguments from user-space in a better way.
	 * For now we have pre-defined static table of all netid/knetconfigs
	 * KLM can deal with. So I see two ways:
	 * 1) User space passes only netid. Kernel then lookups valid knetconfig
	 *    by given netid.
	 * 2) Kernel builds and dynamically registers all netids/knetconfigs
	 *    user-space passes. In this case we don't need pre-defined knetconfigs
	 *    table in the kernel.
	 */
	bzero(&knc, sizeof (knc));
	switch (args->n_proto) {
	case LM_TCP:
		knc.knc_semantics = NC_TPI_COTS_ORD;
		knc.knc_proto = NC_TCP;
		break;
	case LM_UDP:
		knc.knc_semantics = NC_TPI_CLTS;
		knc.knc_proto = NC_UDP;
		break;
	default:
		NLM_ERR("nlm_build_knetconfig: Unknown "
		    "lm_proto=0x%x\n", args->n_proto);
		return (EINVAL);
	}

	switch (args->n_fmly) {
	case LM_INET:
		knc.knc_protofmly = NC_INET;
		break;
	case LM_INET6:
		knc.knc_protofmly = NC_INET6;
		break;
	case LM_LOOPBACK:
		knc.knc_protofmly = NC_LOOPBACK;
		/* Override what we set above. */
		knc.knc_proto = NC_NOPROTO;
		break;
	default:
		NLM_ERR("nlm_build_knetconfig: Unknown "
		    "lm_fmly=0x%x\n", args->n_fmly);
		return (EINVAL);
	}

	knc.knc_rdev = args->n_rdev;
	netid = nlm_netid_from_knetconfig(&knc);
	if (!netid)
		return (EINVAL);

	/*
	 * Setup service on the passed transport.
	 * NB: must releasef(fp) after this.
	 */
	if ((fp = getf(args->fd)) == NULL)
		return (EBADF);

	mutex_enter(&g->lock);
	/*
	 * Don't try to start while still shutting down,
	 * or lots of things will fail...
	 */
	if (g->run_status == NLM_ST_STOPPING) {
		err = EAGAIN;
		goto out_unlock;
	}

	/*
	 * There is no separate "initialize" sub-call for nfssys,
	 * and we want to do some one-time work when the first
	 * binding comes in.  This is slightly hack-ish, but we
	 * know that lockd binds the loopback transport first,
	 * so we piggy back initializations on that call.
	 */
	if (args->n_fmly == LM_LOOPBACK) {
		if (g->run_status != NLM_ST_DOWN) {
			err = EBUSY;
			goto out_unlock;
		}

		nlm_netconfigs_init(); /* Initialize knetconfig/netid table */
		g->run_status = NLM_ST_STARTING;
		g->lockd_pid = curproc->p_pid;

		/* Save the options. */
		g->cn_idle_tmo  = args->timout;
		g->grace_period = args->grace;
		g->retrans_tmo  = args->retransmittimeout;
		g->loglevel     = args->debug;

		/* See nfs_sys.c (not yet per-zone) */
		if (INGLOBALZONE(curproc)) {
			rfs4_grace_period = args->grace;
			rfs4_lease_time   = args->grace;
		}

		mutex_exit(&g->lock);
		err = nlm_svc_starting(g, fp, netid, &knc);
	} else {
		/*
		 * If KLM is not started and the very first endpoint lockd
		 * tries to add is not a loopback device, report an error.
		 */
		if (g->run_status != NLM_ST_UP) {
			err = ENOTACTIVE;
			goto out_unlock;
		}
		if (g->lockd_pid != curproc->p_pid) {
			/* Check if caller has the same PID lockd does */
			err = EPERM;
			goto out_unlock;
		}

		mutex_exit(&g->lock);
		err = nlm_svc_add_ep(g, fp, netid, &knc);
	}

	releasef(args->fd);
	return (err);

out_unlock:
	mutex_exit(&g->lock);
	if (fp)
		releasef(args->fd);

	return (err);
}

/*
 * klm system calls.  Kill the lock manager.
 * Called by nfssys() KILL_LOCKMGR,
 * liblm:lm_shutdown() <- unused?
 */
int
lm_shutdown(void)
{
	struct nlm_globals *g;
	proc_t *p;
	pid_t pid;
	int err;

	/* Get our "globals" */
	g = zone_getspecific(nlm_zone_key, curzone);

	mutex_enter(&g->lock);
	if (g->run_status != NLM_ST_UP) {
		mutex_exit(&g->lock);
		return (EBUSY);
	}

	g->run_status = NLM_ST_STOPPING;
	pid = g->lockd_pid;
	if (pid == 0) {
		mutex_exit(&g->lock);
		return (ESRCH);
	}

	mutex_exit(&g->lock);
	nlm_svc_stopping(g);

	mutex_enter(&pidlock);
	p = prfind(pid);
	if (p != NULL)
		psignal(p, SIGTERM);
	mutex_exit(&pidlock);

	return (0);
}

/*
 * Cleanup remote locks on FS un-export.
 * See nfs_export.c:unexport()
 */
void
lm_unexport(struct exportinfo *ei)
{
	/* XXX - todo... */
}

/*
 * CPR suspend/resume hooks.
 * See:cpr_suspend, cpr_resume
 *
 * Before suspend, get current state from "statd" on
 * all remote systems for which we have locks.
 *
 * After resume, check with those systems again,
 * and either reclaim locks, or do SIGLOST.
 */
void
lm_cprsuspend(void)
{
}

void
lm_cprresume(void)
{
}

/*
 * Add the nlm_id bits to the sysid (by ref).
 */
void
lm_set_nlmid_flk(int *new_sysid)
{
	if (lm_global_nlmid != 0)
		*new_sysid |= (lm_global_nlmid << BITS_IN_SYSID);
}

/*
 * Called by NFS unmount.  Free the klm netconfig.
 * XXX: Only needed if we store something there.
 */
void
lm_free_config(struct knetconfig *knc)
{
}

/*
 * Called by NFS4 delegation code to check if there are any
 * NFSv2/v3 locks for the file, so it should not delegate.
 */
int
lm_vp_active(const vnode_t *vp)
{
	/* XXX - todo... */
	return (0);
}

/*
 * Find or create a "sysid" for given knc+addr.
 * name is optional.  Sets nc_changed if the
 * found knc_proto is different from passed.
 * Increments the reference count.
 *
 * Called internally, and in nfs4_find_sysid()
 *
 * XXX: struct lm_sysid is like our struct nlm_host.
 */
struct lm_sysid *
lm_get_sysid(struct knetconfig *knc, struct netbuf *addr,
		char *name, bool_t *nc_changed)
{
	/* XXX - todo... */
	return (0);
}

/*
 * Release a reference on a "sysid".
 */
void
lm_rel_sysid(struct lm_sysid *sysid)
{
	/* XXX - todo... */
}

/*
 * Alloc/free a sysid_t (number).
 * Used by NFSv4 rfs4_op_lockt and smbsrv/smb_fsop_frlock,
 * both to represent non-local locks outside of klm.
 */
sysid_t
lm_alloc_sysidt()
{
	return (-1);
}

void
lm_free_sysidt(sysid_t s)
{
	/* XXX - todo... */
}

/* Access private member lms->sysid */
sysid_t
lm_sysidt(struct lm_sysid *lms)
{
	/* XXX - todo... */
	return (-1);
}

/*
 * Called by nfs_frlock to check lock constraints.
 * Return non-zero if the lock request is "safe", i.e.
 * the range is not mapped, not MANDLOCK, etc.
 */
int
lm_safelock(vnode_t *vp, const struct flock64 *fl, cred_t *cr)
{
	int safe;

	safe = nlm_safelock(vp, fl, cr);
	return (safe);
}

/*
 * Called by nfs_lockcompletion to check whether it's "safe"
 * to map the file (and cache it's data).  Walks the list of
 * file locks looking for any that are not "whole file".
 */
int
lm_safemap(const vnode_t *vp)
{
	int safe;

	safe = nlm_safemap(vp);
	return (safe);
}

/*
 * Called by nfs_map() for the MANDLOCK case.
 * Return non-zero if the file has any locks with a
 * blocked request (sleep).
 */
int
lm_has_sleep(const vnode_t *vp)
{
	int has_sleep;

	has_sleep = nlm_has_sleep(vp);
	return (has_sleep);
}

/*
 * ****************************************************************
 * Stuff needed by klmops?
 */
