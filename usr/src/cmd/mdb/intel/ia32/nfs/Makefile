#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#
# Copyright 2012 Nexenta Systems, Inc.  All rights reserved.

MDBTGT		= kvm
MODULE		= nfs.so
MODSRCS_DIR	= ../../../common/modules/nfs
MODSRCS		= nfs.c svc.c common.c

include ../../../../Makefile.cmd
include ../../Makefile.ia32

# To /usr/kernel/kmdb
ROOTKMOD = $(ROOT)/usr/kernel/kmdb

include ../../../Makefile.module

CPPFLAGS	+= -I$(SRC)/uts/common

C99MODE=	$(C99_ENABLE)

# maybe not the best place for this, but
# we need to create this directory.
$(ROOTKMOD):
	$(INS.dir)
