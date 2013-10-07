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
#include <nfs/export.h>
#include <sys/pkp_hash.h>
#include <limits.h>

#include "nfssrv.h"
#include "common.h"

/*
 * nfs_expvis dcmd implementation
 */

static const mdb_bitmask_t sec_flag_bits[] = {
	{"M_RO", M_RO, M_RO},
	{"M_ROL", M_ROL, M_ROL},
	{"M_RW", M_RW, M_RW},
	{"M_RWL", M_RWL, M_RWL},
	{"M_ROOT", M_ROOT, M_ROOT},
	{"M_EXP", M_4SEC_EXPORTED, M_4SEC_EXPORTED},
	{NULL}
};

static int
print_sec(int cnt, uintptr_t addr)
{
	int i;

	if (cnt == 0)
		return (DCMD_OK);

	mdb_printf("Security Flavors :\n");
	mdb_inc_indent(4);

	for (i = 0; i < cnt; i++) {
		struct secinfo si;
		const char *s;

		if (mdb_vread(&si, sizeof (si), addr) == -1) {
			mdb_warn("can't read struct secinfo");
			return (DCMD_ERR);
		}

		switch (si.s_secinfo.sc_nfsnum) {
		case AUTH_NONE:
			s = "none";
			break;
		case AUTH_SYS:
			s = "sys";
			break;
		case AUTH_DH:
			s = "dh";
			break;
		case 390003:
			s = "krb5";
			break;
		case 390004:
			s = "krb5i";
			break;
		case 390005:
			s = "krb5p";
			break;
		default:
			s = "???";
			break;
		}

		mdb_printf("%-8s ref: %-8i flag: %#x (%b)\n", s, si.s_refcnt,
		    si.s_flags, si.s_flags, sec_flag_bits);

		addr = (uintptr_t)((struct secinfo *)addr + 1);
	}

	mdb_dec_indent(4);

	return (DCMD_OK);
}

int
nfs_expvis_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	exp_visible_t expvis;
	uintptr_t vp;
	char *s;
	int status;

	if (argc > 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_vread(&expvis, sizeof (expvis), addr) == -1) {
		mdb_warn("can't read exp_visible_t");
		return (DCMD_ERR);
	}

	/* vp = expvis.vis_vp->v_path */
	if (mdb_vread(&vp, sizeof (vp), (uintptr_t)expvis.vis_vp
	    + OFFSETOF(vnode_t, v_path)) == -1) {
		mdb_warn("can't read vnode_t");
		return (DCMD_ERR);
	}

	s = mdb_alloc(PATH_MAX, UM_SLEEP | UM_GC);
	if (mdb_readstr(s, PATH_MAX, vp) == -1) {
		mdb_warn("can't read v_path");
		return (DCMD_ERR);
	}

	mdb_printf("%s\n", s);

	mdb_inc_indent(4);

	mdb_printf("addr: %?p   exp : %i    ref: %i\n", addr,
	    expvis.vis_exported, expvis.vis_count);
	mdb_printf("vp  : %?p   ino : %llu (%#llx)\n", expvis.vis_vp,
	    expvis.vis_ino, expvis.vis_ino);
	mdb_printf("seci: %?p   nsec: %i\n", expvis.vis_secinfo,
	    expvis.vis_seccnt);

	status = print_sec(expvis.vis_seccnt, (uintptr_t)expvis.vis_secinfo);

	mdb_dec_indent(4);

	return (status);
}


/*
 * nfs_expinfo dcmd implementation
 */

static const mdb_bitmask_t exp_flag_bits[] = {
	{"EX_NOSUID", EX_NOSUID, EX_NOSUID},
	{"EX_ACLOK", EX_ACLOK, EX_ACLOK},
	{"EX_PUBLIC", EX_PUBLIC, EX_PUBLIC},
	{"EX_NOSUB", EX_NOSUB, EX_NOSUB},
	{"EX_INDEX", EX_INDEX, EX_INDEX},
	{"EX_LOG", EX_LOG, EX_LOG},
	{"EX_LOG_ALLOPS", EX_LOG_ALLOPS, EX_LOG_ALLOPS},
	{"EX_PSEUDO", EX_PSEUDO, EX_PSEUDO},
	{NULL}
};

int
nfs_expinfo_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	struct exportinfo exi;
	char *path;
	int status;
	uint_t v_flag;

	if (argc > 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) == 0)
		return (DCMD_USAGE);

	if (mdb_vread(&exi, sizeof (exi), addr) == -1) {
		mdb_warn("can't read struct exportinfo");
		return (DCMD_ERR);
	}

	if (mdb_vread(&v_flag, sizeof (v_flag), (uintptr_t)exi.exi_vp
	    + OFFSETOF(vnode_t, v_flag)) == -1) {
		mdb_warn("can't read v_flag");
		return (DCMD_ERR);
	}

	path = mdb_alloc(exi.exi_export.ex_pathlen + 1, UM_SLEEP | UM_GC);
	if (mdb_readstr(path, exi.exi_export.ex_pathlen + 1,
	    (uintptr_t)exi.exi_export.ex_path) == -1) {
		mdb_warn("can't read ex_path");
		return (DCMD_ERR);
	}

	mdb_printf("\n%s    %p\n", path, addr);

	mdb_inc_indent(4);

	mdb_printf("rtvp: %?p    ref : %-8u flag: %#x (%b)%s\n", exi.exi_vp,
	    exi.exi_count, exi.exi_export.ex_flags, exi.exi_export.ex_flags,
	    exp_flag_bits, v_flag & VROOT ? " VROOT" : "");

	mdb_printf("dvp : %?p    anon: %-8u logb: %p\n", exi.exi_dvp,
	    exi.exi_export.ex_anon, exi.exi_logbuffer);
	mdb_printf("seci: %?p    nsec: %-8i fsid: (%#x %#x)\n",
	    exi.exi_export.ex_secinfo, exi.exi_export.ex_seccnt,
	    exi.exi_fsid.val[0], exi.exi_fsid.val[1]);

	status = print_sec(exi.exi_export.ex_seccnt,
	    (uintptr_t)exi.exi_export.ex_secinfo);
	if (status != DCMD_OK)
		return (status);

	if (exi.exi_visible) {
		mdb_printf("PseudoFS Nodes:\n");
		mdb_inc_indent(4);

		if (mdb_pwalk_dcmd("nfs_expvis", "nfs_expvis", 0, NULL,
			    (uintptr_t)exi.exi_visible) == -1) {
			mdb_warn("walk through exi_visible failed");
			return (DCMD_ERR);
		}

		mdb_dec_indent(4);
	}

	mdb_dec_indent(4);

	return (DCMD_OK);
}

/*
 * nfs_exptable dcmd implementation
 */

int
nfs_exptable_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	if (argc > 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	if (mdb_walk_dcmd("nfs_expinfo", "nfs_expinfo", 0, NULL) == -1) {
		mdb_warn("exptable walk failed");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * nfs_exptable_path dcmd implementation
 */

int
nfs_exptable_path_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	if (argc > 0)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	if (mdb_walk_dcmd("nfs_expinfo_path", "nfs_expinfo", 0, NULL) == -1) {
		mdb_warn("exptable walk failed");
		return (DCMD_ERR);
	}

	return (DCMD_OK);
}

/*
 * nfs_nstree dcmd implementation
 */

static int
print_tree(uintptr_t addr, uint_t opt_v, treenode_t *tn, char *s)
{
	while (addr != NULL) {
		uintptr_t a;

		if (mdb_vread(tn, sizeof (*tn), addr) == -1) {
			mdb_warn("can't read treenode");
			return (DCMD_ERR);
		}

		/* a = tn->tree_exi->exi_vp */
		if (mdb_vread(&a, sizeof (a), (uintptr_t)tn->tree_exi
		    + OFFSETOF(struct exportinfo, exi_vp)) == -1) {
			mdb_warn("can't read exi_vp");
			return (DCMD_ERR);
		}
		/* a = ((vnode_t *)a)->v_path */
		if (mdb_vread(&a, sizeof (a), a + OFFSETOF(vnode_t, v_path)) == -1) {
			mdb_warn("can't read v_path");
			return (DCMD_ERR);
		}
		if (mdb_readstr(s, PATH_MAX, a) == -1) {
			mdb_warn("can't read v_path string");
			return (DCMD_ERR);
		}

		mdb_printf("\n\nTREENODE:\n%s\n", s);

		mdb_inc_indent(2);

		if (opt_v)
			mdb_printf("\nDump treenode:\n\n");

		mdb_printf("addr:             %p\n", addr);
		mdb_printf("tree_parent:      %p\n", tn->tree_parent);
		mdb_printf("tree_child_first: %p\n", tn->tree_child_first);
		mdb_printf("tree_sibling:     %p\n", tn->tree_sibling);
		mdb_printf("tree_exi:         %p\n", tn->tree_exi);
		mdb_printf("tree_vis:         %p\n", tn->tree_vis);

		if (opt_v) {
			mdb_printf("\nDump exportinfo:\n");
			if (mdb_call_dcmd("nfs_expinfo",
			    (uintptr_t)tn->tree_exi, DCMD_ADDRSPEC, 0, NULL)
			    == -1)
				return (DCMD_ERR);

			if (tn->tree_vis) {
				mdb_printf("\nDump exp_visible:\n\n");
				if (mdb_call_dcmd("nfs_expvis",
				    (uintptr_t)tn->tree_vis, DCMD_ADDRSPEC, 0,
				    NULL) == -1)
					return (DCMD_ERR);
			}
		}

		addr = (uintptr_t)tn->tree_sibling;

		if (tn->tree_child_first != NULL) {
			int status;

			mdb_inc_indent(2);
			status = print_tree((uintptr_t)tn->tree_child_first,
			    opt_v, tn, s);
			if (status != DCMD_OK)
				return (status);
			mdb_dec_indent(2);
		}

		mdb_dec_indent(2);
	}

	return (DCMD_OK);
}

int
nfs_nstree_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_v = FALSE;
	treenode_t tn;
	char *s;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	if (mdb_readsym(&addr, sizeof (addr), "ns_root") == -1) {
		mdb_warn("can't readsym %s", "ns_root");
		return (DCMD_ERR);
	}

	s = mdb_alloc(PATH_MAX, UM_SLEEP | UM_GC);

	return (print_tree(addr, opt_v, &tn, s));
}

void
nfs_nstree_help(void)
{
	mdb_printf(
	    "-v       dump also exportinfo and exp_visible structures\n");
}

/*
 * nfs_fid_hashdist dcmd implementation
 */

static int
calc_hashdist(struct exp_walk_arg *arg, uint_t opt_v)
{
	struct exportinfo **table;
	int i;
	u_longlong_t min = 0;
	u_longlong_t max = 0;
	u_longlong_t sum = 0;
	u_longlong_t sum_sqr = 0;

	table = mdb_alloc(arg->size * sizeof (struct exportinfo *),
	    UM_SLEEP | UM_GC);
	if (mdb_readsym(table, arg->size * sizeof (struct exportinfo *),
	    arg->name) == -1) {
		mdb_warn("can't readsym %s", arg->name);
		return (DCMD_ERR);
	}

	for (i = 0; i < arg->size; i++) {
		u_longlong_t len;
		uintptr_t addr;

		for (addr = (uintptr_t)table[i], len = 0; addr; len++)
			if (mdb_vread(&addr, sizeof (addr), addr + arg->offset)
			    == -1) {
				mdb_warn("unable to read pointer to next "
				    "exportinfo struct");
				return (DCMD_ERR);
			}

		if (i == 0 || len < min)
			min = len;
		if (len > max)
			max = len;
		sum += len;
		sum_sqr += len * len;

		if (opt_v)
			mdb_printf("%u\n", len);
	}

	mdb_printf("TABLE: %s\n", arg->name);
	mdb_printf("items/size = %u/%u\n", sum, arg->size);
	mdb_printf("min/avg/max/variance = %u/%u/%u/%u\n", min, sum / arg->size,
	    max, (sum_sqr - (sum * sum) / arg->size) / arg->size);

	return (DCMD_OK);
}

int
nfs_fid_hashdist_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	return (calc_hashdist(&nfs_expinfo_arg, opt_v));
}

void
nfs_hashdist_help(void)
{
	mdb_printf(
	    "-v       displays individual bucket lengths\n");
}

/*
 * nfs_path_hashdist dcmd implementation
 */

int
nfs_path_hashdist_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	uint_t opt_v = FALSE;

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &opt_v, NULL) != argc)
		return (DCMD_USAGE);

	if ((flags & DCMD_ADDRSPEC) != 0)
		return (DCMD_USAGE);

	return (calc_hashdist(&nfs_expinfo_path_arg, opt_v));
}

/*
 * nfs_expinfo/nfs_expinfo_path walkers implementation
 */

struct exp_walk_arg nfs_expinfo_arg = {
	"exptable", EXPTABLESIZE,
	OFFSETOF(struct exportinfo, fid_hash) + OFFSETOF(struct exp_hash, next)
};

struct exp_walk_arg nfs_expinfo_path_arg = {
	"exptable_path_hash", PKP_HASH_SIZE,
	OFFSETOF(struct exportinfo, path_hash) + OFFSETOF(struct exp_hash, next)
};

int
nfs_expinfo_walk_init(mdb_walk_state_t *wsp)
{
	struct exp_walk_arg *exp_arg = wsp->walk_arg;
	hash_table_walk_arg_t *arg;
	int status;
	GElf_Sym sym;

	if (wsp->walk_addr != NULL) {
		mdb_warn("global walks supported only\n");
		return (WALK_ERR);
	}

	if (mdb_lookup_by_name(exp_arg->name, &sym) == -1) {
		mdb_warn("failed to find '%s'", exp_arg->name);
		return (WALK_ERR);
	}

	arg = mdb_alloc(sizeof (hash_table_walk_arg_t), UM_SLEEP);
	arg->array_addr = sym.st_value;
	arg->array_len = exp_arg->size;
	arg->head_size = sizeof (struct exportinfo *);
	arg->first_name = "exportinfo pointer",
	arg->first_offset = 0;
	arg->member_type_name = "struct exportinfo";
	arg->member_size = sizeof (struct exportinfo);
	arg->next_offset = exp_arg->offset;

	wsp->walk_arg = arg;

	status = hash_table_walk_init(wsp);
	if (status != WALK_NEXT)
		mdb_free(wsp->walk_arg, sizeof (hash_table_walk_arg_t));
	return (status);
}

void
nfs_expinfo_walk_fini(mdb_walk_state_t *wsp)
{
	hash_table_walk_fini(wsp);
	mdb_free(wsp->walk_arg, sizeof (hash_table_walk_arg_t));
}

/*
 * nfs_expvis walker implementation
 */

int
nfs_expvis_walk_init(mdb_walk_state_t *wsp)
{
	if (wsp->walk_addr == NULL) {
		mdb_warn("global walk not supported\n");
		return (WALK_ERR);
	}

	return (WALK_NEXT);
}

int
nfs_expvis_walk_step(mdb_walk_state_t *wsp)
{
	exp_visible_t vis;
	uintptr_t addr = wsp->walk_addr;

	if (addr == NULL)
		return (WALK_DONE);

	if (mdb_vread(&vis, sizeof (vis), addr) == -1) {
		mdb_warn("failed to read exp_visible_t at %p", addr);
		return (WALK_ERR);
	}

	wsp->walk_addr = (uintptr_t)vis.vis_next;
	return (wsp->walk_callback(addr, &vis, wsp->walk_cbdata));
}
