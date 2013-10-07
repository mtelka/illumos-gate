/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */
/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/mdb_modapi.h>
#include <sys/vnode.h>
#include <stddef.h>
#include <nfs/rnode.h>
#include <limits.h>
#include <nfs/lm.h>
#include <sys/flock_impl.h>
#include <mdb/mdb_ks.h>

#include "nlm.h"
#include "common.h"

struct lm_sysid {
	avl_node_t lsnode;
	int refcnt;
	struct knetconfig config;
	struct netbuf addr;
	char *name;
	sysid_t sysid;
	bool_t sm_client;
	bool_t sm_server;
	bool_t in_recovery;
	int sm_state;
	kmutex_t lock;
	kcondvar_t cv;
};

struct lm_vnode {
	struct vnode *vp;
	int count;
	struct lm_block *blocked;
	struct lm_vnode *next;
	nfs_fhandle fh2;
	nfs_fh3 fh3;
};

/*
 * nlm_sysid dcmd implementation
 */

int
nlm_sysid_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct lm_sysid ls;
	uint_t opt_v = FALSE;
	char s[21];

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("nlm_sysid", "nlm_sysid", argc, argv) == -1) {
			mdb_warn("failed to walk lm_sysids");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&ls, sizeof (ls), addr) == -1) {
		mdb_warn("failed to read lm_sysid");
		return (DCMD_ERR);
	}

	if (mdb_readstr(s, sizeof (s), (uintptr_t)ls.name) == -1) {
		mdb_warn("failed to read name");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<b>%<u>%-?s %-*s%10s %6s reclaim ", "lm_sysid",
		    sizeof (s), "host", "refcnt", "sysid");
		if (!opt_v)
			mdb_printf("%-?s%</u>%</b>\n", "knetconf");
		else
			mdb_printf("notify %-30s%</u>%</b>\n", "knetconfig");
	}

	mdb_printf("%?p %-*s%10i %6hi %7s ", addr, sizeof(s), s,
	    ls.refcnt, ls.sysid, ls.in_recovery == TRUE ? "true" : "false");

	if (!opt_v)
		mdb_printf("%p\n", addr + OFFSETOF(struct lm_sysid, config));
	else {
		mdb_printf("%-6s %u/", ls.sm_client ? "client" :
		    ls.sm_server ? "server" : "none", ls.config.knc_semantics);
		if (mdb_readstr(s, sizeof (s),
		    (uintptr_t)ls.config.knc_protofmly) == -1) {
			mdb_warn("failed to read knc_protofmly");
			return (DCMD_ERR);
		}
		mdb_printf("%s/", s);
		if (mdb_readstr(s, sizeof (s), (uintptr_t)ls.config.knc_proto)
		    == -1) {
			mdb_warn("failed to read knc_proto");
			return (DCMD_ERR);
		}
		mdb_printf("%s/%s\n", s, common_netbuf_str(&ls.addr));
	}

	return (DCMD_OK);
}

void
nlm_sysid_help(void)
{
	mdb_printf("-v       verbose information\n");
}

/*
 * nlm_vnode dcmd implementation
 */

int
nlm_vnode_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct lm_vnode lvn;
	uint_t opt_v = FALSE;
	uintptr_t vp;
	char *s;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("nlm_vnode", "nlm_vnode", argc, argv) == -1) {
			mdb_warn("failed to walk lm_vnodes");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_vread(&lvn, sizeof (lvn), addr) == -1) {
		mdb_warn("failed to read lm_vnode");
		return (DCMD_ERR);
	}

	if (!opt_v) {
		if (DCMD_HDRSPEC(flags)) {
			mdb_printf("%<b>%<u>%-?s %10s %-?s %-?s%</u>%</b>\n",
			    "lm_vnode", "refcnt", "vnode", "lm_block");
		}

		mdb_printf("%?p %10i %?p %?-p\n", addr, lvn.count, lvn.vp,
		    lvn.blocked);

		return (DCMD_OK);
	}

	/* vp = lvn.vp->v_path */
	if (mdb_vread(&vp, sizeof (vp), (uintptr_t)lvn.vp + OFFSETOF(vnode_t,
	    v_path)) == -1) {
		mdb_warn("can't read vnode_t");
		return (DCMD_ERR);
	}

	s = mdb_alloc(PATH_MAX, UM_SLEEP | UM_GC);
	if (mdb_readstr(s, PATH_MAX, vp) == -1) {
		mdb_warn("can't read v_path");
		return (DCMD_ERR);
	}

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<b>%<u>%-?s %10s %-?s %-?s    %-?s %-16s"
		    "%</u>%</b>\n", "lm_vnode", "refcnt", "lm_block", "nfs fh",
		    "vnode", "path");
	}

	mdb_printf("%?p %10i %-?p ", addr, lvn.count, lvn.blocked);
	if (lvn.fh3.fh3_len != 0)
		mdb_printf("v3:%-?p", addr + OFFSETOF(struct lm_vnode, fh3));
	else if(lvn.fh2.fh_len != 0)
		mdb_printf("v2:%-?p", addr + OFFSETOF(struct lm_vnode, fh2));
	else
		mdb_printf("??:%-?s", "<unknown>");
	mdb_printf(" %?p %s\n", lvn.vp, s);

	return (DCMD_OK);
}

void
nlm_vnode_help(void)
{
	mdb_printf("-v       verbose information\n");
}

/*
 * nlm_lockson dcmd implementation
 */

#define	HOST_LEN	16

struct nlm_lockson_arg {
	uint_t opt_v;
	const mdb_arg_t *host;
	const struct lm_sysid *ls;
};

static int
nlm_lockson_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_lockson_arg *arg = cb_data;
	const lock_descriptor_t *ld = data;
	char host[HOST_LEN];
	proc_t p;
	int local;
	char *s;

	if ((ld->l_flock.l_sysid & LM_SYSID_MAX) != arg->ls->sysid)
		return (WALK_NEXT);

	if (mdb_readstr(host, sizeof (host), (uintptr_t)arg->ls->name) == -1) {
		mdb_warn("unable to read sysid name");
		return (WALK_ERR);
	}

	local = ld->l_flock.l_sysid & LM_SYSID_CLIENT;

	mdb_printf("%-*s%?p %5hi(%c) %?p %-6i %-*s ", sizeof (host), host, addr,
	    ld->l_flock.l_sysid & LM_SYSID_MAX, local ? 'L' : 'R', ld->l_vnode,
	    ld->l_flock.l_pid, MAXCOMLEN, ld->l_flock.l_pid == 0 ? "<kernel>"
	    : !local ? "<remote>"
	    : mdb_pid2proc(ld->l_flock.l_pid, &p) == NULL ? "<defunct>"
	    : p.p_user.u_comm);

	if (arg->opt_v) {
		switch(ld->l_status) {
		case FLK_INITIAL_STATE:
			s = "init";
			break;
		case FLK_START_STATE:
			s = "execute";
			break;
		case FLK_ACTIVE_STATE:
			s = "active";
			break;
		case FLK_SLEEPING_STATE:
			s = "blocked";
			break;
		case FLK_GRANTED_STATE:
			s = "granted";
			break;
		case FLK_INTERRUPTED_STATE:
			s = "interrupt";
			break;
		case FLK_CANCELLED_STATE:
			s = "cancel";
			break;
		case FLK_DEAD_STATE:
			s = "done";
			break;
		default:
			s = "??";
			break;
		}
		mdb_printf("%-9s", s);
	} else {
		mdb_printf("%-5i", ld->l_status);
	}

	mdb_printf(" %-2s", ld->l_type == F_RDLCK ? "RD"
	    : ld->l_type == F_WRLCK ? "WR" : "??");

	if (!arg->opt_v) {
		mdb_printf("\n");
		return (WALK_NEXT);
	}

	switch (GET_NLM_STATE(ld)) {
	case FLK_NLM_UP:
		s = "up";
		break;
	case FLK_NLM_SHUTTING_DOWN:
		s = "halting";
		break;
	case FLK_NLM_DOWN:
		s = "down";
		break;
	case FLK_NLM_UNKNOWN:
		s = "unknown";
		break;
	default:
		s = "??";
		break;
	}

	mdb_printf("(%5i:%-5i) %-7s ", ld->l_start, ld->l_len, s);
	s = mdb_alloc(PATH_MAX, UM_SLEEP | UM_GC);
	if (mdb_vnode2path((uintptr_t)ld->l_vnode, s, PATH_MAX) == -1)
		s = "??";
	mdb_printf("%s\n", s);

	return (WALK_NEXT);
}

static int
nlm_lockson_sysid_cb(uintptr_t addr, const void *data, void *cb_data)
{
	struct nlm_lockson_arg *arg = cb_data;

	arg->ls = data;

	if (arg->host) {
		size_t sz;
		char *s;

		switch (arg->host->a_type) {
		case MDB_TYPE_STRING:
			sz = strlen(arg->host->a_un.a_str) + 2;
			s = mdb_alloc(sz, UM_SLEEP | UM_GC);
			if (mdb_readstr(s, sz, (uintptr_t)arg->ls->name)
			    == -1) {
				mdb_warn("unable to read sysid name");
				return (WALK_ERR);
			}
			if (strcmp(arg->host->a_un.a_str, s) != 0)
				return (WALK_NEXT);
			break;
		case MDB_TYPE_IMMEDIATE:
			if (arg->ls->sysid != arg->host->a_un.a_val)
				return (WALK_NEXT);
			break;
		default:
			mdb_warn("invalid host specified\n");
			return (WALK_ERR);
		}
	}

	if (mdb_walk("lock_graph", nlm_lockson_cb, arg) == -1) {
		mdb_warn("failed to walk lock_graph");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nlm_lockson_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct nlm_lockson_arg cb_args = {FALSE, NULL};
	int count;

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	count = mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &cb_args.opt_v, NULL);

	if (argc - count > 1)
		return (DCMD_USAGE);

	if (DCMD_HDRSPEC(flags)) {
		mdb_printf("%<b>%<u>%-*s%-?s %5s(x) %-?s %-6s %-*s %-*s type",
		    HOST_LEN, "host", "lock-addr", "sysid", "vnode", "pid",
		    MAXCOMLEN, "cmd", cb_args.opt_v ? 9 : 5, "state");

		if (cb_args.opt_v)
			mdb_printf("%-11s srvstat %-10s", "(width)", "path");

		mdb_printf("%</u>%</b>\n");
	}

	if (argc > count)
		cb_args.host = &argv[count];

	if (mdb_walk("nlm_sysid", nlm_lockson_sysid_cb, &cb_args) == -1) {
		mdb_warn("failed to walk lm_sysids");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

void
nlm_lockson_help(void)
{
	mdb_printf(
	    "-v       verbose information about the locks\n"
	    "host     limit the output for the host specified\n"
	    "         by either $[sysid] or hostname\n");
}

/*
 * nlm_sysid walker implementation
 */

int
nlm_sysid_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		GElf_Sym sym;

		if (mdb_lookup_by_name("lm_sysids", &sym) == -1) {
			mdb_warn("failed to find 'lm_sysids'");
			return (WALK_ERR);
		}

		wsp->walk_addr = sym.st_value;
	}

	if (mdb_layered_walk("avl", wsp) == -1) {
		mdb_warn("failed to walk 'avl'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nlm_sysid_walk_step(mdb_walk_state_t *wsp)
{
	return (wsp->walk_callback(wsp->walk_addr, wsp->walk_layer,
	    wsp->walk_cbdata));
}

/*
 * nlm_vnode walker implementation
 */

int
nlm_vnode_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL && mdb_readsym(&wsp->walk_addr,
	    sizeof (wsp->walk_addr), "lm_vnodes") == -1) {
		mdb_warn("failed to read 'lm_vnodes'");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nlm_vnode_walk_step(mdb_walk_state_t *wsp)
{
	struct lm_vnode lm_vnode;
	uintptr_t addr = wsp->walk_addr;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&lm_vnode, sizeof (lm_vnode), addr) == -1) {
		mdb_warn("failed to read lm_vnode at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)lm_vnode.next;
	return (wsp->walk_callback(addr, &lm_vnode, wsp->walk_cbdata));
}
