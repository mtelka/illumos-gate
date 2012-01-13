/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * pmap_prot.c
 * XDR routines for portmapper version 2.
 */

#include <rpc/rpc.h>
#include <rpc/types.h>
#include <rpc/xdr.h>
#include <rpc/pmap_prot.h>

bool_t
xdr_pmap(XDR *xdrs, PMAP *objp)
{
	if (!xdr_rpcprog(xdrs, &objp->pm_prog))
		return (FALSE);
	if (!xdr_rpcvers(xdrs, &objp->pm_vers))
		return (FALSE);
	if (!xdr_rpcprot(xdrs, &objp->pm_prot))
		return (FALSE);
	if (!xdr_u_int(xdrs, &objp->pm_port))
		return (FALSE);

	return (TRUE);
}
