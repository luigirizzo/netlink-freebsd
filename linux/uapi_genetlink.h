/*
 * Copyright (C) 2014 Daniele Di Proietto, Luigi Rizzo,
 *	Universita` di Pisa. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above copyright
 *      notice, this list of conditions and the following disclaimer in the
 *      documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * $FreeBSD$
 *
 * The user-visible API for genetlink sockets.
 * These definitions are visible to userspace and kernel.
 * In linux similar content is in uapi/linux/genetlink.h,
 * copied to /usr/include/linux/genetlink.h with guard changed.
 * For simplicity, in FreeBSD we install both uapi_genetlink.h and genetlink.h
 * and kernel and userspace both include the latter.
 */

#ifndef _UAPI_LINUX_GENETLINK_H
#define _UAPI_LINUX_GENETLINK_H

#include <linux/netlink.h>	/* nested include as in linux */

#define GENL_ID_CTRL		0x10

#define GENL_NAMSIZ		16      /* length of family name */

#define GENL_ID_GENERATE        0

struct genlmsghdr {
	uint8_t  cmd;
	uint8_t  version;
	uint16_t reserved;
};

#define GENL_HDRLEN		NLMSG_ALIGN(sizeof(struct genlmsghdr))

/**************************************************************************
 * Controller
 **************************************************************************/

enum {
	CTRL_CMD_UNSPEC,
	CTRL_CMD_NEWFAMILY,
	CTRL_CMD_DELFAMILY,
	CTRL_CMD_GETFAMILY,
	CTRL_CMD_NEWOPS,
	CTRL_CMD_DELOPS,
	CTRL_CMD_GETOPS,
	CTRL_CMD_NEWMCAST_GRP,
	CTRL_CMD_DELMCAST_GRP,
	CTRL_CMD_GETMCAST_GRP, /* unused */
	__CTRL_CMD_MAX,
};

#define CTRL_CMD_MAX		(__CTRL_CMD_MAX - 1)

enum {
	CTRL_ATTR_UNSPEC,
	CTRL_ATTR_FAMILY_ID,
	CTRL_ATTR_FAMILY_NAME,
	CTRL_ATTR_VERSION,
	CTRL_ATTR_HDRSIZE,
	CTRL_ATTR_MAXATTR,
	CTRL_ATTR_OPS,
	CTRL_ATTR_MCAST_GROUPS,
	__CTRL_ATTR_MAX,
};

#define CTRL_ATTR_MAX		(__CTRL_ATTR_MAX - 1)

enum {
	CTRL_ATTR_OP_UNSPEC,
	CTRL_ATTR_OP_ID,
	CTRL_ATTR_OP_FLAGS,
	__CTRL_ATTR_OP_MAX,
};

#define CTRL_ATTR_OP_MAX	(__CTRL_ATTR_OP_MAX - 1)

enum {
	CTRL_ATTR_MCAST_GRP_UNSPEC,
	CTRL_ATTR_MCAST_GRP_NAME,
	CTRL_ATTR_MCAST_GRP_ID,
	__CTRL_ATTR_MCAST_GRP_MAX,
};

#define CTRL_ATTR_MCAST_GRP_MAX	(__CTRL_ATTR_MCAST_GRP_MAX - 1)


#endif /* _UAPI_LINUX_GENETLINK_H */
