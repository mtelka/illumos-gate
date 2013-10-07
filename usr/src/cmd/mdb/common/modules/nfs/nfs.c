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

#include <sys/types.h>
#include <sys/refstr.h>
#include <sys/kstat.h>
#include <sys/refstr_impl.h>
#include <nfs/nfs4_clnt.h>
#include <nfs/nfs_clnt.h>
#include <nfs/nfs4_db_impl.h>
#include <nfs/nfs4.h>
#include <nfs/rnode.h>
#include <nfs/rnode4.h>
#include <rpc/clnt.h>
/* tie vyssie mozno netreba */
#include <sys/mdb_modapi.h>
#include <nfs/nfs4_idmap_impl.h>

#include "svc.h"
#include "rfs4.h"
#include "nfssrv.h"
#include "nlm.h"
#include "idmap.h"
#include "nfs_clnt.h"

typedef struct nfs_rnode_cbdata {
	int printed_hdr;
	uintptr_t vfs_addr;	/* for nfs_rnode4find */
} nfs_rnode_cbdata_t;

static const mdb_bitmask_t vfs_flags[] = {
	{ "VFS_RDONLY",   VFS_RDONLY,   VFS_RDONLY },
	{ "VFS_NOMNTTAB", VFS_NOMNTTAB, VFS_NOMNTTAB },
	{ "VFS_NOSETUID", VFS_NOSETUID, VFS_NOSETUID },
	{ "VFS_REMOUNT",  VFS_REMOUNT,  VFS_REMOUNT },
	{ "VFS_NOTRUNC",  VFS_NOTRUNC,  VFS_NOTRUNC },
	{ "VFS_PXFS",	  VFS_PXFS,	VFS_PXFS },
	{ "VFS_NBMAND",   VFS_NBMAND,   VFS_NBMAND },
	{ "VFS_XATTR",    VFS_XATTR,    VFS_XATTR },
	{ "VFS_NOEXEC",   VFS_NOEXEC,   VFS_NOEXEC },
	{ "VFS_STATS",    VFS_STATS,    VFS_STATS },
	{ "VFS_XID",	  VFS_XID,	VFS_XID },
	{ "VFS_UNLINKABLE", VFS_UNLINKABLE, VFS_UNLINKABLE },
	{ "VFS_UNMOUNTED",  VFS_UNMOUNTED,  VFS_UNMOUNTED },
	{ NULL, 0, 0 }
};

static const mdb_bitmask_t nfs_mi4_flags[] = {
	{ "MI4_HARD",	  MI4_HARD,	MI4_HARD },
	{ "MI4_PRINTED",  MI4_PRINTED,  MI4_PRINTED },
	{ "MI4_INT",	  MI4_INT,	MI4_INT },
	{ "MI4_DOWN",	  MI4_DOWN,	MI4_DOWN },
	{ "MI4_NOAC",	  MI4_NOAC,	MI4_NOAC },
	{ "MI4_NOCTO",    MI4_NOCTO,    MI4_NOCTO },
	{ "MI4_LLOCK",    MI4_LLOCK,    MI4_LLOCK },
	{ "MI4_GRPID",    MI4_GRPID,    MI4_GRPID },
	{ "MI4_SHUTDOWN", MI4_SHUTDOWN, MI4_SHUTDOWN },
	{ "MI4_LINK",	  MI4_LINK,	MI4_LINK },
	{ "MI4_SYMLINK",  MI4_SYMLINK,  MI4_SYMLINK },
	{ "MI4_ACL",	  MI4_ACL,	MI4_ACL },
	{ "MI4_REFERRAL", MI4_REFERRAL, MI4_REFERRAL },
	{ "MI4_NOPRINT",  MI4_NOPRINT,  MI4_NOPRINT },
	{ "MI4_DIRECTIO", MI4_DIRECTIO, MI4_DIRECTIO },
	{ "MI4_PUBLIC",   MI4_PUBLIC,   MI4_PUBLIC },
	{ "MI4_MOUNTING", MI4_MOUNTING, MI4_MOUNTING },
	{ "MI4_DEAD",	  MI4_DEAD,	MI4_DEAD },
	{ "MI4_TIMEDOUT", MI4_TIMEDOUT, MI4_TIMEDOUT },
	{ "MI4_MIRRORMOUNT",  MI4_MIRRORMOUNT, MI4_MIRRORMOUNT },
	{ "MI4_RECOV_ACTIV",  MI4_RECOV_ACTIV, MI4_RECOV_ACTIV },
	{ "MI4_RECOV_FAIL",   MI4_RECOV_FAIL,  MI4_RECOV_FAIL },
	{ "MI4_POSIX_LOCK",   MI4_POSIX_LOCK,  MI4_POSIX_LOCK },
	{ "MI4_LOCK_DEBUG",   MI4_LOCK_DEBUG,  MI4_LOCK_DEBUG },
	{ "MI4_INACTIVE_IDLE",  MI4_INACTIVE_IDLE,  MI4_INACTIVE_IDLE },
	{ "MI4_BADOWNER_DEBUG", MI4_BADOWNER_DEBUG, MI4_BADOWNER_DEBUG },
	{ "MI4_ASYNC_MGR_STOP", MI4_ASYNC_MGR_STOP, MI4_ASYNC_MGR_STOP },
	{ "MI4_EPHEMERAL",	MI4_EPHEMERAL,	    MI4_EPHEMERAL },
	{ "MI4_REMOVE_ON_LAST_CLOSE", MI4_REMOVE_ON_LAST_CLOSE,
	    MI4_REMOVE_ON_LAST_CLOSE },
	{ NULL, 0, 0 }
};

static const mdb_bitmask_t nfs_mi4_recover[] = {
	{ "MI4R_NEED_CLIENTID", MI4R_NEED_CLIENTID, MI4R_NEED_CLIENTID },
	{ "MI4R_REOPEN_FILES",  MI4R_REOPEN_FILES,  MI4R_REOPEN_FILES },
	{ "MI4R_NEED_SECINFO",  MI4R_NEED_SECINFO,  MI4R_NEED_SECINFO },
	{ "MI4R_REOPEN_FILES",  MI4R_REOPEN_FILES,  MI4R_REOPEN_FILES },
	{ "MI4R_SRV_REBOOT",    MI4R_SRV_REBOOT,    MI4R_SRV_REBOOT },
	{ "MI4R_LOST_STATE",    MI4R_LOST_STATE,    MI4R_LOST_STATE },
	{ "MI4R_BAD_SEQID",	MI4R_BAD_SEQID,	    MI4R_BAD_SEQID },
	{ "MI4R_MOVED",		MI4R_MOVED,	    MI4R_MOVED },
	{ "MI4R_NEED_NEW_SERVER", MI4R_NEED_NEW_SERVER, MI4R_NEED_NEW_SERVER },
	{ NULL, 0, 0 }
};

const char *nfs4_tags[] = {
	"TAG_NONE",
	"TAG_ACCESS",
	"TAG_CLOSE",
	"TAG_CLOSE_LOST",
	"TAG_CLOSE_UNDO",
	"TAG_COMMIT",
	"TAG_DELEGRETURN",
	"TAG_FSINFO",
	"TAG_GET_SYMLINK",
	"TAG_GETATTR",
	"TAG_GETATTR_FSLOCATION",
	"TAG_INACTIVE",
	"TAG_LINK",
	"TAG_LOCK",
	"TAG_LOCK_RECLAIM",
	"TAG_LOCK_RESEND",
	"TAG_LOCK_REINSTATE",
	"TAG_LOCK_UNKNOWN",
	"TAG_LOCKT",
	"TAG_LOCKU",
	"TAG_LOCKU_RESEND",
	"TAG_LOCKU_REINSTATE",
	"TAG_LOOKUP",
	"TAG_LOOKUP_PARENT",
	"TAG_LOOKUP_VALID",
	"TAG_LOOKUP_VPARENT",
	"TAG_MKDIR",
	"TAG_MKNOD",
	"TAG_MOUNT",
	"TAG_OPEN",
	"TAG_OPEN_CONFIRM",
	"TAG_OPEN_CONFIRM_LOST",
	"TAG_OPEN_DG",
	"TAG_OPEN_DG_LOST",
	"TAG_OPEN_LOST",
	"TAG_OPENATTR",
	"TAG_PATHCONF",
	"TAG_PUTROOTFH",
	"TAG_READ",
	"TAG_READAHEAD",
	"TAG_READDIR",
	"TAG_READLINK",
	"TAG_RELOCK",
	"TAG_REMAP_LOOKUP",
	"TAG_REMAP_LOOKUP_AD",
	"TAG_REMAP_LOOKUP_NA",
	"TAG_REMAP_MOUNT",
	"TAG_RMDIR",
	"TAG_REMOVE",
	"TAG_RENAME",
	"TAG_RENAME_VFH",
	"TAG_RENEW",
	"TAG_REOPEN",
	"TAG_REOPEN_LOST",
	"TAG_SECINFO",
	"TAG_SETATTR",
	"TAG_SETCLIENTID",
	"TAG_SETCLIENTID_CF",
	"TAG_SYMLINK",
	"TAG_WRITE",
};

#define	nfs4_tags_num	(sizeof (nfs4_tags) / sizeof (nfs4_tags[0]))

const char *nfs4_stat_ext[] = {
	"NFS4ERR_BADHANDLE",
	"Unknown 1002",
	"NFS4ERR_BAD_COOKIE",
	"NFS4ERR_NOTSUPP",
	"NFS4ERR_TOOSMALL",
	"NFS4ERR_SERVERFAULT",
	"NFS4ERR_BADTYPE",
	"NFS4ERR_DELAY",
	"NFS4ERR_SAME",
	"NFS4ERR_DENIED",
	"NFS4ERR_EXPIRED",
	"NFS4ERR_LOCKED",
	"NFS4ERR_GRACE",
	"NFS4ERR_FHEXPIRED",
	"NFS4ERR_SHARE_DENIED",
	"NFS4ERR_WRONGSEC",
	"NFS4ERR_CLID_INUSE",
	"NFS4ERR_RESOURCE",
	"NFS4ERR_MOVED",
	"NFS4ERR_NOFILEHANDLE",
	"NFS4ERR_MINOR_VERS_MISMATCH",
	"NFS4ERR_STALE_CLIENTID",
	"NFS4ERR_STALE_STATEID",
	"NFS4ERR_OLD_STATEID",
	"NFS4ERR_BAD_STATEID",
	"NFS4ERR_BAD_SEQID",
	"NFS4ERR_NOT_SAME",
	"NFS4ERR_LOCK_RANGE",
	"NFS4ERR_SYMLINK",
	"NFS4ERR_RESTOREFH",
	"NFS4ERR_LEASE_MOVED",
	"NFS4ERR_ATTRNOTSUPP",
	"NFS4ERR_NO_GRACE",
	"NFS4ERR_RECLAIM_BAD",
	"NFS4ERR_RECLAIM_CONFLICT",
	"NFS4ERR_BADXDR",
	"NFS4ERR_LOCKS_HELD",
	"NFS4ERR_OPENMODE",
	"NFS4ERR_BADOWNER",
	"NFS4ERR_BADCHAR",
	"NFS4ERR_BADNAME",
	"NFS4ERR_BAD_RANGE",
	"NFS4ERR_LOCK_NOTSUPP",
	"NFS4ERR_OP_ILLEGAL",
	"NFS4ERR_DEADLOCK",
	"NFS4ERR_FILE_OPEN",
	"NFS4ERR_ADMIN_REVOKED",
	"NFS4ERR_CB_PATH_DOWN",
};

#define	nfs4_stat_ext_num   (sizeof (nfs4_stat_ext) / sizeof (nfs4_stat_ext[0]))
#define	nfs4_stat_offset (10001)

const char *nfs4_ops[] = {
	"Unknown1",
	"Unknown2",
	"Unknown3",
	"OP_ACCESS",
	"OP_CLOSE",
	"OP_COMMIT",
	"OP_CREATE",
	"OP_DELEGPURGE",
	"OP_DELEGRETURN",
	"OP_GETATTR",
	"OP_GETFH",
	"OP_LINK",
	"OP_LOCK",
	"OP_LOCKT",
	"OP_LOCKU",
	"OP_LOOKUP",
	"OP_LOOKUPP",
	"OP_NVERIFY",
	"OP_OPEN",
	"OP_OPENATTR",
	"OP_OPEN_CONFIRM",
	"OP_OPEN_DOWNGRADE",
	"OP_PUTFH",
	"OP_PUTPUBFH",
	"OP_PUTROOTFH",
	"OP_READ",
	"OP_READDIR",
	"OP_READLINK",
	"OP_REMOVE",
	"OP_RENAME",
	"OP_RENEW",
	"OP_RESTOREFH",
	"OP_SAVEFH",
	"OP_SECINFO",
	"OP_SETATTR",
	"OP_SETCLIENTID",
	"OP_SETCLIENTID_CONFIRM",
	"OP_VERIFY",
	"OP_WRITE",
	"OP_RELEASE_LOCKOWNER",
};

#define	nfs4_ops_num	(sizeof (nfs4_ops) / sizeof (nfs4_ops[0]))

const char *nfs4_recov[] = {
	"NR_UNUSED",
	"NR_CLIENTID",
	"NR_OPENFILES",
	"NR_FHEXPIRED",
	"NR_FAILOVER",
	"NR_WRONGSEC",
	"NR_EXPIRED",
	"NR_BAD_STATEID",
	"NR_BADHANDLE",
	"NR_BAD_SEQID",
	"NR_OLDSTATEID",
	"NR_GRACE",
	"NR_DELAY",
	"NR_LOST_LOCK",
	"NR_LOST_STATE_RQST",
	"NR_STALE",
	"NR_MOVED",
};

#define	nfs4_recov_num	(sizeof (nfs4_recov) / sizeof (nfs4_recov[0]))


static const char *
nfs4_tag_str(int tag)
{
	if (tag >= 0 && tag < nfs4_tags_num)
		return (nfs4_tags[tag]);
	else
		return ("Undefined");
}

/*
 * Return stringified NFS4 error.
 * Note, it may return pointer to static buffer (in case of unknown error)
 */
static const char *
nfs4_stat_str(nfsstat4 err)
{
	static char str[64];

	if (err < nfs4_stat_offset) {
		switch (err) {
		case NFS4_OK:
			return ("NFS4_OK");
		case NFS4ERR_PERM:
			return ("NFS4ERR_PERM");
		case NFS4ERR_NOENT:
			return ("NFS4ERR_NOENT");
		case NFS4ERR_IO:
			return ("NFS4ERR_IO");
		case NFS4ERR_NXIO:
			return ("NFS4ERR_NXIO");
		case NFS4ERR_ACCESS:
			return ("NFS4ERR_ACCESS");
		case NFS4ERR_EXIST:
			return ("NFS4ERR_EXIST");
		case NFS4ERR_XDEV:
			return ("NFS4ERR_XDEV");
		case NFS4ERR_NOTDIR:
			return ("NFS4ERR_NOTDIR");
		case NFS4ERR_ISDIR:
			return ("NFS4ERR_ISDIR");
		case NFS4ERR_INVAL:
			return ("NFS4ERR_INVAL");
		case NFS4ERR_FBIG:
			return ("NFS4ERR_FBIG");
		case NFS4ERR_NOSPC:
			return ("NFS4ERR_NOSPC");
		case NFS4ERR_ROFS:
			return ("NFS4ERR_ROFS");
		case NFS4ERR_MLINK:
			return ("NFS4ERR_MLINK");
		case NFS4ERR_NAMETOOLONG:
			return ("NFS4ERR_NAMETOOLONG");
		case NFS4ERR_NOTEMPTY:
			return ("NFS4ERR_NOTEMPTY");
		case NFS4ERR_DQUOT:
			return ("NFS4ERR_DQUOT");
		case NFS4ERR_STALE:
			return ("NFS4ERR_STALE");
		default:
			goto out_unknown;
		}
	} else if (err >= nfs4_stat_offset &&
	    err < (nfs4_stat_offset + nfs4_stat_ext_num)) {
		return (nfs4_stat_ext[err - nfs4_stat_offset]);
	}
out_unknown:
	mdb_snprintf(str, sizeof (str), "Unknown %d", err);
	return (str);
}

static const char *
nfs4_op_str(uint_t op)
{
	if (op < nfs4_ops_num)
		return (nfs4_ops[op]);
	else if (op == OP_ILLEGAL)
		return ("OP_ILLEGAL");
	else
		return ("Unknown");
}

static const char *
nfs4_recov_str(uint_t act)
{
	if (act < nfs4_recov_num)
		return (nfs4_recov[act]);
	else
		return ("Unknown");
}

static void
nfs_addr_by_conf(uintptr_t knconf, struct netbuf *addr,
    char *s, size_t nbytes)
{
	struct knetconfig conf;
	char buf[16];

	if (mdb_vread(&conf, sizeof (conf), knconf) == -1) {
		mdb_warn("can't read sv_knconf");
		return;
	}

	if (mdb_readstr(buf, sizeof (buf),
	    (uintptr_t)conf.knc_protofmly) == -1) {
		mdb_warn("can't read knc_protofmly");
		return;
	}
	/* Support only IPv4 addresses */
/* TODO
	if (strcmp(NC_INET, buf) == 0)
		common_netbuf_str(PF_INET, addr, s, nbytes);
*/
}

/*
 * Get IPv4 string address by servinfo4_t
 *
 * in case of error does not modify 's'
 */
static void
nfs_addr_by_servinfo4(uintptr_t addr, char *s, size_t nbytes)
{
	struct servinfo4 *si;

	si = mdb_alloc(sizeof (*si), UM_SLEEP | UM_GC);
	if (mdb_vread(si, sizeof (*si),	addr) == -1) {
		mdb_warn("can't read servinfo4");
		return;
	}

	nfs_addr_by_conf((uintptr_t)si->sv_knconf, &si->sv_addr,
	    s, nbytes);
}


/*
 * Get IPv4 string address by servinfo_t
 *
 * in case of error does not modify 's'
 */
static void
nfs_addr_by_servinfo(uintptr_t addr, char *s, size_t nbytes)
{
	struct servinfo *si;

	si = mdb_alloc(sizeof (*si), UM_SLEEP | UM_GC);
	if (mdb_vread(si, sizeof (*si),	addr) == -1) {
		mdb_warn("can't read servinfo");
		return;
	}

	nfs_addr_by_conf((uintptr_t)si->sv_knconf, &si->sv_addr,
	    s, nbytes);
}

static void
nfs_queue_show_event(const nfs4_debug_msg_t *msg)
{
	const nfs4_revent_t *re;
	time_t time;
	char *re_char1 = "", *re_char2 = "";

	re = &msg->rmsg_u.msg_event;
	time = msg->msg_time.tv_sec;

	if (re->re_char1 != NULL) {
		char *s;

		s = mdb_alloc(MAXPATHLEN, UM_SLEEP | UM_GC);
		if (mdb_readstr(s, MAXPATHLEN, (uintptr_t)re->re_char1) != -1)
			re_char1 = s;
		else
			mdb_warn("can't read re_char1");
	}

	if (re->re_char2 != NULL) {
		char *s;

		s = mdb_alloc(MAXPATHLEN, UM_SLEEP | UM_GC);

		if (mdb_readstr(s, MAXPATHLEN, (uintptr_t)re->re_char2) != -1)
			re_char2 = s;
		else
			mdb_warn("can't read re_char2");
	}

	switch (re->re_type) {
	case RE_BAD_SEQID:
		mdb_printf("[NFS4]%Y: Op %s for file %s rnode_pt %p\n"
		    "pid %d using seqid %d got %s. Last good seqid was %d "
		    "for operation %s\n",
		    time, nfs4_tag_str(re->re_tag1), re->re_char1, re->re_rp1,
		    re->re_pid, re->re_seqid1, nfs4_stat_str(re->re_stat4),
		    re->re_seqid2, nfs4_tag_str(re->re_tag2));
		break;
	case RE_BADHANDLE:
		mdb_printf("[NFS4]%Y: server said filehandle was "
		    "invalid for file: %s rnode_pt 0x%p\n", time,
		    re_char1, re->re_rp1);
		break;
	case RE_CLIENTID:
		mdb_printf("[NFS4]%Y: Can't recover clientid on mountpoint %s\n"
		    "mi %p due to error %d (%s). Marking file system "
		    "file system as unusable\n", time,
		    re->re_mi, re->re_uint, nfs4_stat_str(re->re_stat4));
		break;
	case RE_DEAD_FILE:
		mdb_printf("[NFS4]%Y: File: %s rnode_pt: %p was closed on NFS\n"
		    "recovery error [%s %s]\n", time, re_char1, re->re_rp1,
		    re_char2, nfs4_stat_str(re->re_stat4));
		break;
	case RE_END:
		mdb_printf("[NFS4]%Y: NFS Recovery done for mi %p "
		    "rnode_pt1 %s (%p), rnode_pt2 %s (%p)\n", time, re->re_mi,
		    re_char1, re->re_rp1, re_char2, re->re_rp2);
		break;

	case RE_FAIL_RELOCK:
		mdb_printf("[NFS4]%Y: Couldn't reclaim lock for pid %d for\n"
		    "file %s (rnode_pt %p) error %d\n", time, re->re_pid,
		    re_char1, re->re_rp1,
		    re->re_uint ? re->re_uint : re->re_stat4);
		break;
	case RE_FAIL_REMAP_LEN:
		mdb_printf("[NFS4]%Y: remap_lookup: returned bad\n"
		    "fhandle length %d\n", time, re->re_uint);
		break;
	case RE_FAIL_REMAP_OP:
		mdb_printf("[NFS4]%Y: remap_lookup: didn't get expected "
		    " OP_GETFH\n", time);
		break;
	case RE_FAILOVER:
		mdb_printf("[NFS4]%Y: failing over to %s\n", time, re_char1);
		break;

	case RE_FILE_DIFF:
		mdb_printf("[NFS4]%Y: File %s rnode_pt: %p was closed\n"
		    "and failed attempted failover since its is different\n"
		    "than the original file\n", time, re_char1, re->re_rp1);
		break;

	case RE_LOST_STATE:
		mdb_printf("[NFS4]%Y: Lost %s request file %s\n"
		    "rnode_pt: %p, dir %s (%p)\n", time,
		    nfs4_op_str(re->re_uint), re_char1,
		    re->re_rp1, re_char2, re->re_rp2);
		break;
	case RE_OPENS_CHANGED:
		mdb_printf("[NFS4]%Y: The number of open files to reopen\n"
		    "changed for mount %s mi %p old %d, new %d\n", time,
		    re->re_mi, re->re_uint, re->re_pid);
		break;
	case RE_SIGLOST:
	case RE_SIGLOST_NO_DUMP:
		mdb_printf("[NFS4]%Y: Process %d lost its locks on file %s\n"
		    "rnode_pt: %p due to NFS recovery error (%d:%s)\n",
		    time, re->re_pid, re_char1,
		    re->re_rp1, re->re_uint, nfs4_stat_str(re->re_stat4));
		break;
	case RE_START:
		mdb_printf("[NFS4]%Y: NFS Starting recovery for\n"
		    "mi %p mi_recovflags [0x%x] rnode_pt1 %s %p "
		    "rnode_pt2 %s %p\n", time,
		    re->re_mi, re->re_uint, re_char1, re->re_rp1,
		    re_char2, re->re_rp2);
		break;
	case RE_UNEXPECTED_ACTION:
		mdb_printf("[NFS4]%Y: NFS recovery: unexpected action %s\n",
		    time, nfs4_recov_str(re->re_uint));
		break;
	case RE_UNEXPECTED_ERRNO:
		mdb_printf("[NFS4]%Y: NFS recovery: unexpected errno %d\n",
		    time, re->re_uint);
		break;
	case RE_UNEXPECTED_STATUS:
		mdb_printf("[NFS4]%Y: NFS recovery: unexpected status"
		    "code (%s)\n", time, nfs4_stat_str(re->re_stat4));
		break;
	case RE_WRONGSEC:
		mdb_printf("[NFS4]%Y: NFS can't recover from NFS4ERR_WRONGSEC\n"
		    "error %d rnode_pt1 %s (%p) rnode_pt2 %s (0x%p)\n", time,
		    re->re_uint, re_char1, re->re_rp1, re_char2, re->re_rp2);
		break;
	case RE_LOST_STATE_BAD_OP:
		mdb_printf("[NFS4]%Y: NFS lost state with unrecognized op %d\n"
		    "fs %s, pid %d, file %s (rnode_pt: %p) dir %s (%p)\n",
		    time, re->re_uint, re->re_pid, re_char1, re->re_rp1,
		    re_char2, re->re_rp2);
		break;
	case RE_REFERRAL:
		mdb_printf("[NFS4]%Y: being referred to %s\n",
		    time, re_char1);
		break;
	default:
		mdb_printf("illegal event %d\n", re->re_type);
		break;
	}
}

static void
nfs_queue_show_fact(const nfs4_debug_msg_t *msg)
{
	time_t time;
	const nfs4_rfact_t *rf;
	char *rf_char1 = "";

	rf = &msg->rmsg_u.msg_fact;
	time = msg->msg_time.tv_sec;

	if (rf->rf_char1 != NULL) {
		char *s;

		s = mdb_alloc(MAXPATHLEN, UM_SLEEP | UM_GC);
		if (mdb_readstr(s, MAXPATHLEN, (uintptr_t)rf->rf_char1) != -1)
			rf_char1 = s;
		else
			mdb_warn("can't read rf_char1");
	}

	switch (rf->rf_type) {
	case RF_ERR:
		mdb_printf("[NFS4]%Y: NFS op %s got "
		    "error %s:%d causing recovery action %s.%s\n",
		    time, nfs4_op_str(rf->rf_op),
		    rf->rf_error ? "" : nfs4_stat_str(rf->rf_stat4),
		    rf->rf_error,
		    nfs4_recov_str(rf->rf_action),
		    rf->rf_reboot ?
		    "  Client also suspects that the server rebooted,"
		    " or experienced a network partition." : "");
		break;
	case RF_RENEW_EXPIRED:
		mdb_printf("[NFS4]%Y: NFS4 renew thread detected client's "
		    "lease has expired. Current open files/locks/IO may fail\n",
		    time);
		break;
	case RF_SRV_NOT_RESPOND:
		mdb_printf("[NFS4]%Y: NFS server not responding;"
		    "still trying\n", time);
		break;
	case RF_SRV_OK:
		mdb_printf("[NFS4]%Y: NFS server ok\n", time);
		break;
	case RF_SRVS_NOT_RESPOND:
		mdb_printf("[NFS4]%Y: NFS servers not responding; "
		    "still trying\n", time);
		break;
	case RF_SRVS_OK:
		mdb_printf("[NFS4]%Y: NFS servers ok\n", time);
		break;
	case RF_DELMAP_CB_ERR:
		mdb_printf("[NFS4]%Y: NFS op %s got error %s when executing "
		    "delmap on file %s rnode_pt %p\n", time,
		    nfs4_op_str(rf->rf_op), nfs4_stat_str(rf->rf_stat4),
		    rf_char1, rf->rf_rp1);
		break;
	case RF_SENDQ_FULL:
		mdb_printf("[NFS4]%Y: sending queue to NFS server is full; "
		    "still trying\n", time);
		break;

	default:
		mdb_printf("queue_print_fact: illegal fact %d\n", rf->rf_type);
	}
}

static int
nfs4_show_message(uintptr_t addr, const void *arg, void *data)
{
/*
	nfs4_debug_msg_t msg;

	if (msg.msg_type == RM_EVENT)
		nfs_queue_show_event(&msg);
	else if (msg.msg_type == RM_FACT)
		nfs_queue_show_fact(&msg);
	else
		mdb_printf("Wrong msg_type %d\n", msg.msg_type);
*/
	return (WALK_NEXT);
}

static void
nfs4_print_messages(uintptr_t head)
{
	mdb_printf("-----------------------------\n");
	mdb_printf("Messages queued:\n");
	mdb_inc_indent(2);
	mdb_pwalk("list", nfs4_show_message, NULL, (uintptr_t)head);
	mdb_dec_indent(2);
	mdb_printf("-----------------------------\n");
}


static void
nfs_print_mi4(uintptr_t miaddr, int verbose)
{
	mntinfo4_t *mi;
	char str[sizeof ("255.255.255.255:65535")] = "";

	mi = mdb_alloc(sizeof (*mi), UM_SLEEP | UM_GC);
	if (mdb_vread(mi, sizeof (*mi), miaddr) == -1) {
		mdb_warn("can't read mntinfo");
		return;
	}

	mdb_printf("mntinfo4_t:    %p\n", miaddr);
	mdb_printf("NFS Version:   4\n");
	mdb_printf("mi_flags:      %b\n", mi->mi_flags, nfs_mi4_flags);
	mdb_printf("mi_error:      %x\n", mi->mi_error);
	mdb_printf("mi_open_files: %d\n", mi->mi_open_files);
	mdb_printf("mi_msg_count:  %d\n", mi->mi_msg_count);
	mdb_printf("mi_recovflags: %b\n", mi->mi_recovflags,
	    nfs_mi4_recover);
	mdb_printf("mi_recovthread: %p\n", mi->mi_recovthread);
	mdb_printf("mi_in_recovery: %d\n", mi->mi_in_recovery);

	if (verbose == 0)
		return;

	mdb_printf("mi_zone:     %p\n", mi->mi_zone);
	mdb_printf("mi_curread:  %d\n", mi->mi_curread);
	mdb_printf("mi_curwrite: %d\n", mi->mi_curwrite);
	mdb_printf("mi_retrans:  %d\n", mi->mi_retrans);
	mdb_printf("mi_timeo:    %d\n", mi->mi_timeo);
	mdb_printf("mi_acregmin: %llu\n", mi->mi_acregmin);
	mdb_printf("mi_acregmax: %llu\n", mi->mi_acregmax);
	mdb_printf("mi_acdirmin: %llu\n", mi->mi_acdirmin);
	mdb_printf("mi_acdirmax: %llu\n", mi->mi_acdirmax);
	mdb_printf("mi_count:    %u\n", mi->mi_count);
	mdb_printf("\nServer list: %p\n", mi->mi_servers);
	nfs_addr_by_servinfo4((uintptr_t)mi->mi_curr_serv, str, sizeof (str));
	mdb_printf("Curr Server: %p %s\n", mi->mi_curr_serv, str);
	mdb_printf("Total:\n");
	mdb_inc_indent(2);
	mdb_printf("Server Non-responses: %u\n", mi->mi_noresponse);
	mdb_printf("Server Failovers:     %u\n\n", mi->mi_failover);
	mdb_dec_indent(2);

/*
	if (mi->mi_io_kstats != NULL)
		nfs_print_io_stat((uintptr_t)mi->mi_io_kstats);
*/

	mdb_printf("\nAsync Request queue:\n");
	mdb_inc_indent(2);
	mdb_printf("max threads:     %u\n", mi->mi_max_threads);
	mdb_printf("active threads:  %u\n", mi->mi_threads[NFS_ASYNC_QUEUE]);
	mdb_dec_indent(2);

	nfs4_print_messages(miaddr + OFFSETOF(mntinfo4_t, mi_msg_list));
}

static void
nfs_print_mi(uintptr_t miaddr, uint_t vers)
{
	mntinfo_t *mi;
	char str[sizeof ("255.255.255.255:65535")] = "";

	mi = mdb_alloc(sizeof (*mi), UM_SLEEP | UM_GC);
	if (mdb_vread(mi, sizeof (*mi), miaddr) == -1) {
		mdb_warn("can't read mntinfo");
		return;
	}

	mdb_printf("\nServer list: %p\n", mi->mi_servers);
	nfs_addr_by_servinfo((uintptr_t)mi->mi_curr_serv, str, sizeof (str));
	mdb_printf("Curr Server: %p %s\n", mi->mi_curr_serv, str);
	mdb_printf("Total:\n");
	mdb_inc_indent(2);
	mdb_printf("Server Non-responses: %u\n", mi->mi_noresponse);
	mdb_printf("Server Failovers:     %u\n\n", mi->mi_failover);
	mdb_dec_indent(2);

/*
	if (mi->mi_io_kstats != NULL)
		nfs_print_io_stat((uintptr_t)mi->mi_io_kstats);
*/

	mdb_printf("\nAsync Request queue:\n");
	mdb_inc_indent(2);
	mdb_printf("max threads:     %u\n", mi->mi_max_threads);
	mdb_printf("active threads:  %u\n", mi->mi_threads[NFS_ASYNC_QUEUE]);
	mdb_dec_indent(2);
}

static int
nfs_vfs_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	vfs_t *vfs;
	char buf[MAXNAMELEN];
	int verbose = 0;

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("nfs_vfs", "nfs_vfs", argc, argv) == -1) {
			mdb_warn("failed to walk nfs_vfs");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	if (mdb_getopts(argc, argv,
	    'v', MDB_OPT_SETBITS, TRUE, &verbose, NULL) != argc)
		return (DCMD_USAGE);

	vfs = mdb_alloc(sizeof (*vfs), UM_SLEEP | UM_GC);

	if (mdb_vread(vfs, sizeof (*vfs), addr) == -1) {
		mdb_warn("failed to read vfs");
		return (DCMD_ERR);
	}

	mdb_printf("vfs_t->%p, data = %p, ops = %p\n",
	    addr, vfs->vfs_data, vfs->vfs_op);

	/* do not need do vread for vfs_mntpt because take address */
	if (mdb_readstr(buf, MAXNAMELEN,
	    (uintptr_t)&vfs->vfs_mntpt->rs_string) == -1)
		return (DCMD_ERR);

	mdb_inc_indent(2);

	mdb_printf("mount point: %s\n", buf);
	if (mdb_readstr(buf, MAXNAMELEN,
	    (uintptr_t)&vfs->vfs_resource->rs_string) == -1) {
		mdb_warn("can't read rs_string");
		goto err;
	}
	mdb_printf("mount  from: %s\n", buf);

	if (verbose) {
		uintptr_t nfs4_ops;
		mntopt_t m;
		uint_t i;

		mdb_printf("vfs_flags:  %b\n", vfs->vfs_flag, vfs_flags);
		mdb_printf("mount opts: ");
		for (i = 0; i < vfs->vfs_mntopts.mo_count; i++) {
			uintptr_t a = (uintptr_t)(vfs->vfs_mntopts.mo_list + i);

			if (mdb_vread(&m, sizeof (m), a) == -1) {
				mdb_warn("can't read mntopt");
				continue;
			}
			if (m.mo_flags & MO_EMPTY)
				continue;

			if (mdb_readstr(buf, sizeof (buf),
			    (uintptr_t)m.mo_name) == -1) {
				mdb_warn("can't read mo_name");
				continue;
			}
			if (m.mo_flags & MO_HASVALUE) {
				char val[64];

				if (mdb_readstr(val, sizeof (val),
				    (uintptr_t)m.mo_arg) == -1) {
					mdb_warn("can't read mo_arg");
					continue;
				}
				mdb_printf("%s(%s), ", buf, val);
			} else
				mdb_printf("%s, ", buf);
		}
		mdb_printf("\n+--------------------------------------+\n");

		if (mdb_readvar(&nfs4_ops, "nfs4_vfsops") == -1) {
			mdb_warn("failed read %s", "nfs4_vfsops");
			goto err;
		}
		if (nfs4_ops == (uintptr_t)vfs->vfs_op) {
			nfs_print_mi4((uintptr_t)VFTOMI4(vfs), 1);
		} else {
			int vers = 3;
			uintptr_t nfs3_ops;

			if (mdb_readvar(&nfs3_ops, "nfs3_vfsops") == -1) {
				mdb_warn("failed read %s", "nfs3_vfsops");
				goto err;
			}
			if (nfs3_ops != (uintptr_t)vfs->vfs_op)
				vers = 2;

			nfs_print_mi((uintptr_t)VFTOMI(vfs), vers);
		}
	}
	mdb_dec_indent(2);
	mdb_printf("\n");
	return (DCMD_OK);
err:
	mdb_dec_indent(2);
	mdb_printf("\n");
	return (DCMD_ERR);
}


static int
nfs4_diag_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	mntinfo4_t *mi;
	vfs_t *vfs;
	char buf[MAXNAMELEN];

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk_dcmd("nfs4_mnt", "nfs4_diag", argc,
		    argv) == -1) {
			mdb_warn("failed to walk nfs4_mnt");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	mi = mdb_alloc(sizeof (*mi), UM_SLEEP | UM_GC);
	if (mdb_vread(mi, sizeof (*mi), addr) == -1) {
		mdb_warn("can't read mntinfo4");
		return (WALK_ERR);
	}

	vfs = mdb_alloc(sizeof (*vfs), UM_SLEEP | UM_GC);
	if (mdb_vread(vfs, sizeof (*vfs), (uintptr_t)mi->mi_vfsp) == -1) {
		mdb_warn("failed to read vfs");
		return (DCMD_ERR);
	}

	mdb_printf("****************************************\n");
	mdb_printf("vfs: %-16p mi: %-16p\n", mi->mi_vfsp, addr);

	if (mdb_readstr(buf, MAXNAMELEN,
	    (uintptr_t)&vfs->vfs_mntpt->rs_string) == -1)
		return (DCMD_ERR);

	mdb_inc_indent(2);
	mdb_printf("mount point:   %s\n", buf);
	if (mdb_readstr(buf, MAXNAMELEN,
	    (uintptr_t)&vfs->vfs_resource->rs_string) == -1) {
		mdb_warn("can't read rs_string");
		mdb_dec_indent(2);
		return (DCMD_ERR);
	}
	mdb_printf("mount  from:   %s\n", buf);
	nfs4_print_messages(addr + OFFSETOF(mntinfo4_t, mi_msg_list));
	mdb_dec_indent(2);
	mdb_printf("\n");
	return (DCMD_OK);
}

static void
nfs4_diag_help(void)
{
	mdb_printf(" <mntinfo4_t>::nfs4_diag <-s>\n"
	    "      -> assumes client is Solaris NFSv4 client\n");
}

static int
nfs_rnode4_cb(uintptr_t addr, const void *data, void *arg)
{
	const rnode4_t *rp = data;
	nfs_rnode_cbdata_t *cbd = arg;
	vnode_t *vp;

	if (addr == NULL)
		return (WALK_DONE);

	vp = mdb_alloc(sizeof (*vp), UM_SLEEP | UM_GC);
	if (mdb_vread(vp, sizeof (*vp), (uintptr_t)rp->r_vnode) == -1) {
		mdb_warn("can't read vnode_t %p\n", (uintptr_t)rp->r_vnode);
		return (WALK_ERR);
	}

	if (cbd->vfs_addr != NULL && cbd->vfs_addr != (uintptr_t)vp->v_vfsp)
		return (WALK_NEXT);

	if (cbd->printed_hdr == 0) {
		mdb_printf("%-16s %-16s %-16s %-8s\n"
		    "%-16s %-8s %-8s %s\n",
		    "Address", "r_vnode", "vfsp", "r_fh",
		    "r_server", "r_error", "r_flags", "r_count");
		cbd->printed_hdr = 1;
	}

	mdb_printf("%p %-8p %-8p %-8p\n"
	    "%-16p %-8u %-8x  %u\n",
	    addr, rp->r_vnode, vp->v_vfsp, rp->r_fh,
	    rp->r_server, (int)rp->r_error, rp->r_flags, rp->r_count);

	return (WALK_NEXT);
}

static int
nfs_rnode4_dcmd(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	nfs_rnode_cbdata_t *cbd;
	rnode4_t *rp;

	cbd = mdb_zalloc(sizeof (*cbd),  UM_SLEEP | UM_GC);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		if (mdb_walk("nfs_rtable4", nfs_rnode4_cb, cbd) == -1) {
			mdb_warn("failed to walk nfs_rnode4");
			return (DCMD_ERR);
		}
		return (DCMD_OK);
	}

	/* address was specified */
	rp = mdb_alloc(sizeof (*rp), UM_SLEEP | UM_GC);
	if (mdb_vread(rp, sizeof (*rp), addr) == -1) {
		mdb_warn("can't read rnode4_t\n");
		return (DCMD_ERR);
	}

	nfs_rnode4_cb(addr, rp, cbd);
	return (DCMD_OK);
}

static void
nfs_rnode4_help(void)
{
	mdb_printf("<rnode4 addr>::nfs_rnode4\n\n"
	    "This prints NFSv4 rnode at address specified. If address\n"
	    "is not specified, walks entire NFSv4 rnode table.\n");
}

static int
nfs_rnode4find_dcmd(uintptr_t addr, uint_t flags, int argc,
    const mdb_arg_t *argv)
{
	nfs_rnode_cbdata_t *cbd;

	cbd = mdb_zalloc(sizeof (*cbd),  UM_SLEEP | UM_GC);

	if ((flags & DCMD_ADDRSPEC) == 0) {
		mdb_printf("mdb: no address specified\n");
		return (DCMD_USAGE);
	}

	cbd->vfs_addr = addr;
	if (mdb_walk("nfs_rtable4", nfs_rnode4_cb, cbd) == -1) {
		mdb_warn("failed to walk nfs_rnode4");
		return (DCMD_ERR);
	}
	return (DCMD_OK);
}

static void
nfs_rnode4find_help(void)
{
	mdb_printf("<vfs addr>::nfs_rnode4find\n\n"
	    "This prints all NFSv4 rnodes that belong to\n"
	    "the VFS address specified\n");
}

/* TODO: remove */
static int
placeholder(uintptr_t addr, uint_t flags, int argc, const mdb_arg_t *argv)
{
	return (DCMD_USAGE);
}


static const mdb_dcmd_t dcmds[] = {
	/* svc */
	{
		"svc_pool", "?[-v] [poolid ...]",
		"display SVCPOOL information",
		svc_pool_dcmd, svc_pool_help
	},
	{
		"svc_mxprt", ":[-w]",
		"display master xprt struct info",
		svc_mxprt_dcmd, svc_mxprt_help
	},
	/* rfs4 */
	{
		"rfs4_db", "?",
		"dump NFSv4 server database",
		rfs4_db_dcmd
	},
	{
		"rfs4_tbl", ":[-vw]",
		"dump NFSv4 server table",
		rfs4_tbl_dcmd, rfs4_tbl_help
	},
	{
		"rfs4_idx", ":[-w]",
		"dump NFSv4 server index",
		rfs4_idx_dcmd, rfs4_idx_help
	},
	{
		"rfs4_bkt", ":",
		"dump NFSv4 server index buckets",
		rfs4_bkt_dcmd
	},
	{
		"rfs4_oo", "?",
		"dump NFSv4 rfs4_openowner_t structures",
		rfs4_oo_dcmd
	},
	{
		"rfs4_osid", "?[-v]",
		"dump NFSv4 rfs4_state_t structures",
		rfs4_osid_dcmd
	},
	{
		"rfs4_file", "?[-v]",
		"dump NFSv4 rfs4_file_t structures",
		rfs4_file_dcmd
	},
	{
		"rfs4_deleg", "?[-v]",
		"dump NFSv4 rfs4_deleg_state_t structures",
		rfs4_deleg_dcmd
	},
	{
		"rfs4_lo", "?",
		"dump NFSv4 rfs4_lockowner_t structures",
		rfs4_lo_dcmd
	},
	{
		"rfs4_lsid", "?[-v]",
		"dump NFSv4 rfs4_lo_state_t structures",
		rfs4_lsid_dcmd
	},
	{
		"rfs4_client", "?[-c <clientid>]",
		"dump NFSv4 rfs4_client_t structures",
		rfs4_client_dcmd, rfs4_client_help
	},
	/* NFS server */
	{
		"nfs_expvis", ":",
		"dump exp_visible_t structure",
		nfs_expvis_dcmd
	},
	{
		"nfs_expinfo", ":",
		"dump exportinfo structure",
		nfs_expinfo_dcmd
	},
	{
		"nfs_exptable", "",
		"dump exportinfo structures from the exptable",
		nfs_exptable_dcmd
	},
	{
		"nfs_exptable_path", "",
		"dump exportinfo structures from the exptable_path_hash",
		nfs_exptable_path_dcmd
	},
	{
		"nfs_nstree", "[-v]",
		"dump NFS server pseudo namespace tree",
		nfs_nstree_dcmd, nfs_nstree_help
	},
	{
		"nfs_fid_hashdist", "[-v]",
		"show fid hash distribution of the exportinfo table",
		nfs_fid_hashdist_dcmd, nfs_hashdist_help
	},
	{
		"nfs_path_hashdist", "[-v]",
		"show path hash distribution of the exportinfo table",
		nfs_path_hashdist_dcmd, nfs_hashdist_help
	},
	/* NLM */
	{
		"nlm_sysid", "?[-v]",
		"dump lm_sysid structures",
		nlm_sysid_dcmd, nlm_sysid_help
	},
	{
		"nlm_vnode", "?[-v]",
		"dump lm_vnode structures",
		nlm_vnode_dcmd, nlm_vnode_help
	},
	{
		"nlm_lockson", "[-v] [host]",
		"dump NLM locks",
		nlm_lockson_dcmd, nlm_lockson_help
	},
	/* NFSv4 idmap */
	{
		"nfs4_idmap", ":",
		"dump nfsidmap_t",
		nfs4_idmap_dcmd
	},
	{
		"nfs4_idmap_info", "?[u2s | g2s | s2u | s2g ...]",
		"dump NFSv4 idmap information for given zone",
		nfs4_idmap_info_dcmd, nfs4_idmap_info_help
	},
	/* NFS client */
	{
		"nfs_mntinfo", "?[-v]",
		"print mntinfo_t information",
		nfs_mntinfo_dcmd, nfs_mntinfo_help
	},
	{
		"nfs_servinfo", ":[-v]",
		"print servinfo_t information",
		nfs_servinfo_dcmd, nfs_servinfo_help
	},
	/* WIP */
	{
		"nfs4_mntinfo", "?[-mv]",
		"print mntinfo4_t information",
		nfs4_mntinfo_dcmd, nfs4_mntinfo_help
	},
	{
		"nfs4_servinfo", ":[-v]",
		"print servinfo4_t information",
		nfs4_servinfo_dcmd, nfs4_servinfo_help
	},
	{
		"nfs4_server_info", "?[-cs]",
		"print nfs4_server_t information",
		nfs4_server_info_dcmd, nfs4_server_info_help
	},
	/* WIP */
	{
		"nfs4_mimsg", ":[-s]",
		"print queued messages for given address of mi_msg_list",
		nfs4_mimsg_dcmd, nfs4_mimsg_help
	},
	{
		"nfs4_fname", ":",
		"print path name of nfs4_fname_t specified",
		nfs4_fname_dcmd
	},
	{
		"nfs4_svnode", ":",
		"print svnode_t info at specified address",
		nfs4_svnode_dcmd
	},







/* NFSv2/3/4 clnt */
	{
		"nfs_vfs", "?[-v]",
		"CHECK: print all nfs vfs struct (-v for mntinfo)",
		nfs_vfs_dcmd
	},





/* NFSv4 clnt */
	{
		"nfs_rnode4", "?",
		"CHECK: dump NFSv4 rnodes",
		nfs_rnode4_dcmd, nfs_rnode4_help
	},
	{
		"nfs4_diag", "?[-s]",
		"CHECK: print queued recovery messages for NFSv4 client",
		nfs4_diag_dcmd, nfs4_diag_help
	},
	{
		"nfs_rnode4find", ":",
		"CHECK: dump NFSv4 rnodes for given vfsp",
		nfs_rnode4find_dcmd, nfs_rnode4find_help
	},
	{"nfs4_foo", "?[-v]", "TODO", placeholder},
	{"nfs4_oob", "?[-v]", "TODO", placeholder},
	{"nfs4_os", "?[-v]", "TODO", placeholder},


/* generic commands */
	{"nfs_stat", "?[-csb][-234][-anr] | $[count]", "TODO", placeholder},
	{
		"nfs_set", "?[-csvw]",
		"TODO",
		placeholder
	},
	{"nfs_help", "[-dw]", "TODO", placeholder},


	{NULL}
};

/* TODO: remove */
static int
placeholder_walk(mdb_walk_state_t *wsp)
{
	return (WALK_ERR);
}

static const mdb_walker_t walkers[] = {
	/* svc */
	{
		"svc_pool", "walk SVCPOOL structs for given zone",
		svc_pool_walk_init, svc_pool_walk_step
	},
	{
		"svc_mxprt", "walk master xprts",
		svc_mxprt_walk_init, svc_mxprt_walk_step
	},
	/* rfs4 */
	{
		"rfs4_db_tbl", "walk NFSv4 server rfs4_table_t structs",
		rfs4_db_tbl_walk_init, rfs4_db_tbl_walk_step
	},
	{
		"rfs4_db_idx", "walk NFSv4 server rfs4_index_t structs",
		rfs4_db_idx_walk_init, rfs4_db_idx_walk_step
	},
	{
		"rfs4_db_bkt", "walk NFSv4 server buckets for given index",
		rfs4_db_bkt_walk_init, rfs4_db_bkt_walk_step,
		rfs4_db_bkt_walk_fini
	},
	/* NFS server */
	{
		"nfs_expinfo", "walk exportinfo structures from the exptable",
		nfs_expinfo_walk_init, hash_table_walk_step,
		nfs_expinfo_walk_fini, &nfs_expinfo_arg
	},
	{
		"nfs_expinfo_path",
		"walk exportinfo structures from the exptable_path_hash",
		nfs_expinfo_walk_init, hash_table_walk_step,
		nfs_expinfo_walk_fini, &nfs_expinfo_path_arg
	},
	{
		"nfs_expvis", "walk list of exp_visible structs",
		nfs_expvis_walk_init, nfs_expvis_walk_step
	},
	/* NLM */
	{
		"nlm_sysid", "lm_sysid walker",
		nlm_sysid_walk_init, nlm_sysid_walk_step
	},
	{
		"nlm_vnode", "lm_vnode walker",
		nlm_vnode_walk_init, nlm_vnode_walk_step
	},
	/* NFSv4 idmap */
	{
		"nfs4_u2s", "walk uid-to-string idmap cache for given zone",
		nfs4_idmap_walk_init, hash_table_walk_step, nfs4_idmap_walk_fini,
		(void *)OFFSETOF(struct nfsidmap_globals, u2s_ci)
	},
	{
		"nfs4_s2u", "walk string-to-uid idmap cache for given zone",
		nfs4_idmap_walk_init, hash_table_walk_step, nfs4_idmap_walk_fini,
		(void *)OFFSETOF(struct nfsidmap_globals, s2u_ci)
	},
	{
		"nfs4_g2s", "walk gid-to-string idmap cache for given zone",
		nfs4_idmap_walk_init, hash_table_walk_step, nfs4_idmap_walk_fini,
		(void *)OFFSETOF(struct nfsidmap_globals, g2s_ci)
	},
	{
		"nfs4_s2g", "walk string-to-gid idmap cache for given zone",
		nfs4_idmap_walk_init, hash_table_walk_step, nfs4_idmap_walk_fini,
		(void *)OFFSETOF(struct nfsidmap_globals, s2g_ci)
	},
	/* NFS client */
	{
		"nfs_rtable", "walk rnodes in rtable cache",
		nfs_rtable_walk_init, hash_table_walk_step,
		hash_table_walk_fini, &nfs_rtable_arg
	},
	{
		"nfs_rtable4", "walk rnode4s in rtable4 cache",
		nfs_rtable4_walk_init, hash_table_walk_step,
		hash_table_walk_fini, &nfs_rtable4_arg
	},
	{
		"nfs_vfs", "walk NFS-mounted vfs structs",
		nfs_vfs_walk_init, nfs_vfs_walk_step, nfs_vfs_walk_fini
	},
	{
		"nfs_mnt", "walk NFSv2/3-mounted vfs structs, pass mntinfo",
		nfs_mnt_walk_init, nfs_mnt_walk_step, nfs_mnt_walk_fini
	},
	{
		"nfs4_mnt", "walk NFSv4-mounted vfs structs, pass mntinfo4",
		nfs4_mnt_walk_init, nfs4_mnt_walk_step, nfs4_mnt_walk_fini
	},
	{
		"nfs_serv", "walk linkedlist of servinfo structs",
		nfs_serv_walk_init, nfs_serv_walk_step
	},
	{
		"nfs4_serv", "walk linkedlist of servinfo4 structs",
		nfs4_serv_walk_init, nfs4_serv_walk_step
	},
	{
		"nfs4_svnode", "walk svnode list at given svnode address",
		nfs4_svnode_walk_init, nfs4_svnode_walk_step
	},
	{
		"nfs4_server", "walk nfs4_server_t structs",
		nfs4_server_walk_init, nfs4_server_walk_step
	},
	{
		"nfs_async", "walk list of async requests",
		nfs_async_walk_init, nfs_async_walk_step
	},
	{
		"nfs4_async", "walk list of NFSv4 async requests",
		nfs4_async_walk_init, nfs4_async_walk_step
	},
	{
		"nfs_acache_rnode", "walk acache entries for a given rnode",
		nfs_acache_rnode_walk_init, nfs_acache_rnode_walk_step
	},
	{
		"nfs_acache", "walk entire nfs_access_cache",
		nfs_acache_walk_init, hash_table_walk_step, nfs_acache_walk_fini
	},
	{
		"nfs_acache4_rnode", "walk acache4 entries for a given NFSv4 rnode",
		nfs_acache4_rnode_walk_init, nfs_acache4_rnode_walk_step
	},
	{
		"nfs_acache4", "walk entire nfs4_access_cache",
		nfs_acache4_walk_init, hash_table_walk_step, nfs_acache4_walk_fini
	},











/* NFSv4 clnt */
	{"nfs_deleg_rnode4", "TODO", NULL, placeholder_walk},


	{NULL}
};

static const mdb_modinfo_t modinfo = {
	MDB_API_VERSION,
	dcmds,
	walkers
};

const mdb_modinfo_t *
_mdb_init(void)
{
	return (&modinfo);
}
