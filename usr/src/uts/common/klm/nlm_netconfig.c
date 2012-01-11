#include <sys/param.h>
#include <sys/systm.h>
#include <sys/netconfig.h>
#include <sys/ddi.h>
#include <rpc/rpc.h>

#include <nfs/nfssys.h>
#include <nfs/nfs.h>
#include <nfs/lm.h>
#include <rpcsvc/nlm_prot.h>
#include "nlm_impl.h"

/*
 * nlm_netconfig structure describes particular knetconfig
 * and a pair netid/device corresponding to given knetconfig.
 * We need this structure to have a set of associations
 * netid <-> knetconfig
 */
struct nlm_netconfig {
	struct knetconfig knc;
	const char *netid;
};

/*
 * Static table of all netid/knetconfig network
 * lock manager can work with. nlm_netconfigs table
 * is used when we need to get valid knetconfig by
 * netid and vice versa.
 * NOTE: there should be the almost the same table
 * defined in user-space lockd daemon.
 *
 * FIXME: there're several places in the kernel code
 * that have to build almost similar static table
 * with netid <-> knetconfig relationship. May be it'd
 * be suitable to have one such table in the kernel and
 * some API that performs lookup logic.
 */
static struct nlm_netconfig nlm_netconfigs[] = {
	/* UDP */
	{
		{ NC_TPI_CLTS, NC_INET, NC_UDP, NODEV },
		"udp",
	},
	/* TCP */
	{
		{ NC_TPI_COTS_ORD, NC_INET, NC_TCP, NODEV },
		"tcp",
	},
	/* UDP over IPv6 */
	{
		{ NC_TPI_CLTS, NC_INET6, NC_UDP, NODEV },
		"udp6",
	},
	/* TCP over IPv6 */
	{
		{ NC_TPI_COTS_ORD, NC_INET6, NC_TCP, NODEV },
		"tcp6",
	},
	/* ticlts (loopback over UDP) */
	{
		{ NC_TPI_CLTS, NC_LOOPBACK, NC_NOPROTO, NODEV },
		"ticlts",
	},
	/* ticotsord (loopback over TCP) */
	{
		{ NC_TPI_COTS_ORD, NC_LOOPBACK, NC_NOPROTO, NODEV },
		"ticotsord",
	},
};

#define NLM_NUM_NETCONFIGS \
	(sizeof(nlm_netconfigs) / sizeof(nlm_netconfigs[0]))

/*
 * Initialize NLM netconfigs table.
 */
void
nlm_netconfigs_init(void)
{
	int i;

	for (i = 0; i < NLM_NUM_NETCONFIGS; i++) {
		nlm_netconfigs[i].knc.knc_rdev =
			makedevice(clone_major,
			    ddi_name_to_major((char *)nlm_netconfigs[i].netid));
	}
}

/*
 * Lookup knetconfig from one of our service bindings,
 * and copy it to *knc, or return EINVAL.
 */
int
nlm_knetconfig_from_netid(const char *netid,
    /* OUT */ struct knetconfig *knc)
{
	int i, ret = ENOENT;

	for (i = 0; i < NLM_NUM_NETCONFIGS; i++) {
		if (!strcmp(nlm_netconfigs[i].netid, netid)) {
			ret = 0;
			*knc = nlm_netconfigs[i].knc;
			break;
		}
	}

	return (ret);
}

/*
 * Figure out what "netid" we want, given a knetconfig.
 * This "knows" a bit about what bindings lockd will
 * normally register, but oh well.  This is called with
 * NFS knetconfigs, which may have types we don't know.
 */
const char *
nlm_netid_from_knetconfig(struct knetconfig *knc)
{
	int i;
	struct knetconfig *knc_iter;

	for (i = 0; i < NLM_NUM_NETCONFIGS; i++) {
		knc_iter = &nlm_netconfigs[i].knc;
		if ((knc_iter->knc_semantics == knc->knc_semantics) &&
		    !strcmp(knc_iter->knc_protofmly, knc->knc_protofmly))
			return nlm_netconfigs[i].netid;
	}

	return (NULL);
}

/*
 * nlm_build_knetconfig fills knetconfig structure
 * using given protocol family and protocol specifications.
 */
int
nlm_build_knetconfig(int nfmly, int nproto,
    /* OUT */ struct knetconfig *out_knc)
{
	switch (nproto) {
	case LM_TCP:
		out_knc->knc_semantics = NC_TPI_COTS_ORD;
		out_knc->knc_proto = NC_TCP;
		break;
	case LM_UDP:
		out_knc->knc_semantics = NC_TPI_CLTS;
		out_knc->knc_proto = NC_UDP;
		break;
	default:
		NLM_ERR("nlm_build_knetconfig: Unknown lm_proto=0x%x\n", nproto);
		return (EINVAL);
	}

	switch (nfmly) {
	case LM_INET:
		out_knc->knc_protofmly = NC_INET;
		break;
	case LM_INET6:
		out_knc->knc_protofmly = NC_INET6;
		break;
	case LM_LOOPBACK:
		out_knc->knc_protofmly = NC_LOOPBACK;
		/* Override what we set above. */
		out_knc->knc_proto = NC_NOPROTO;
		break;
	default:
		NLM_ERR("nlm_build_knetconfig: Unknown lm_fmly=0x%x\n", nfmly);
		return (EINVAL);
	}

	return (0);
}
