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

#ifndef _UAPI_LINUX_NETLINK_H
#define _UAPI_LINUX_NETLINK_H

/*
 * $FreeBSD$
 *
 * The user-visible API for netlink sockets.
 * These definitions are visible to userspace and kernel.
 * In linux similar content is in uapi/linux/netlink.h,
 * copied to /usr/include/linux/netlink.h with guard changed.
 * For simplicity, in FreeBSD we install both uapi_netlink.h and netlink.h
 * and kernel and userspace both include the latter.
 */

#include <sys/types.h>
#include <sys/socket.h>

/*
 * AF_NETLINK and PF_NETLINK should go in sys/sys/socket.h.
 * We replicate them here for convenience, but eventually should go away.
 */
#ifndef AF_NETLINK
#define AF_NETLINK 	38
#define PF_NETLINK 	38
#endif /* !AF_NETLINK */

/* XXX Make sure that SOL_NETLINK != SOL_SOCKET */
#define SOL_NETLINK 270	/* in linux it is in linux/socket.h */

/*
 * NETLINK_ROUTE is not implemented now.
 */
#define NETLINK_ROUTE		0	/* not implemented */
#define NETLINK_GENERIC		16
#define MAX_LINKS		32	/* how many netlink protocols ? */

/*
 * On FreeBSD, sa_family_t is 8 bit, on linux it is 16.
 * All sockets on FreeBSD start with an 8-bit len field which we add for
 * compatibility here (but probably should not check because linux sw
 * will not set it).
 * There is no good way to make the two formats binary compatible given
 * the endianness.
 */
struct sockaddr_nl {
	uint8_t		nl_len;		/* FreeBSD SPECIFIC */
	sa_family_t	nl_family;	/* AF_NETLINK */
	uint16_t	nl_pad;		/* keep it zero */
	uint32_t	nl_pid;		/* port ID. */
	uint32_t	nl_groups;	/* multicast groups mask */
};

/*
 * Messages have this 16-byte header, in host order.
 */
struct nlmsghdr {
	uint32_t	nlmsg_len;	/* total length including header */
	uint16_t	nlmsg_type;	/* type of content */
	uint16_t	nlmsg_flags;	/* additional flags */
	uint32_t	nlmsg_seq;	/* sequence number */
	uint32_t	nlmsg_pid;	/* sender port ID */
};


/* Flags for nlmsg_flags */

#define NLM_F_REQUEST	0x1	/* request message */
#define NLM_F_MULTI	0x2	/* multipart message, ends with NLMSG_DONE */
#define NLM_F_ACK	0x4	/* reply with ack, with zero or error code */
#define NLM_F_ECHO	0x8	/* echo this request */
#define NLM_F_DUMP_INTR	0x10	/* dump inconsistent due to sequence change */

/* Modifiers to GET request */
#define NLM_F_ROOT	0x100	/* specify tree root */
#define NLM_F_MATCH	0x200	/* return all matching */
#define NLM_F_ATOMIC	0x400	/* atomic GET */
#define NLM_F_DUMP	(NLM_F_ROOT|NLM_F_MATCH)

/* Modifiers to NEW request */
#define NLM_F_REPLACE	0x100	/* override existing */
#define NLM_F_EXCL	0x200	/* do not touch, if it exists */
#define NLM_F_CREATE	0x400	/* create, if it does not exist */
#define NLM_F_APPEND	0x800	/* add to end of list */

/*
 * Both header and body are padded to the next 4 byte boundary.
 * (the header is already 16 so there is no real header padding).
 *
 * When reading the message, we only fetch the useful payload
 * (i.e. sizeof(struct nlmsghdr) and NLMSG_LENGTH().
 * The padding is accessed/skipped only if there is a following block.
 */
#define NLMSG_ALIGNTO	4U
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )

/*
 * Use a compile time assert to check that we do not need header padding,
 * and do not bother with complications in the code.
 */
#define NLMSG_HDRLEN	((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))

#ifdef CTASSERT
CTASSERT(NLMSG_HDRLEN == sizeof(struct nlmsghdr));
#endif

/*
 * NLMSG_LENGTH() is what we need to read, NLMSG_SPACE() is the
 * space taken if we have a subsequent part.
 * Note that NLMSG_ALIGN(NLMSG_HDRLEN) is pointless as the argument
 * is already aligned.
 */
#define NLMSG_LENGTH(len)	((len) + NLMSG_HDRLEN)
#define NLMSG_SPACE(len)	NLMSG_ALIGN(NLMSG_LENGTH(len))

#if 0 /* unused macros */
/* returns a pointer to the payload of the message */
#define NLMSG_DATA(nlh)		( (void *)((char *)(nlh) + NLMSG_HDRLEN) )

/*
 * helper macro, apparently unused.
 */
#define NLMSG_NEXT(nlh, len)	((len) -= NLMSG_ALIGN((nlh)->nlmsg_len), \
	(struct nlmsghdr*)(((char *)(nlh)) + NLMSG_ALIGN((nlh)->nlmsg_len)))

/*
 * Returns true if len is >= the message size. Can be used to validate
 * the messages.
 */
#define NLMSG_OK(nlh, len)	((len) >= (int)sizeof(struct nlmsghdr) && \
	(nlh)->nlmsg_len >= sizeof(struct nlmsghdr) && \
	(nlh)->nlmsg_len <= (len))

/*
 * How much space is left after a header of length 'len'
 */
#define NLMSG_PAYLOAD(nlh, len)	((nlh)->nlmsg_len - NLMSG_SPACE((len)))

#endif /* unused macros */

#define NLMSG_NOOP		0x1	/* Nothing.             */
#define NLMSG_ERROR		0x2	/* Error                */
#define NLMSG_DONE		0x3	/* End of a dump        */
#define NLMSG_OVERRUN		0x4	/* Data lost            */

#define NLMSG_MIN_TYPE		0x10

struct nlmsgerr {
	int error;
	struct nlmsghdr msg;
};

#define NETLINK_ADD_MEMBERSHIP	1
#define NETLINK_DROP_MEMBERSHIP	2
/* there are others which we do not support */

/*
 * nlattr is TLV encoded message
 * The two high bits of the type encode info.
 * The NESTED and BYTEORDER bits are mutually exclusive.
 */
struct nlattr {
	uint16_t        nla_len;
	uint16_t        nla_type;
};

/* attributes use the high 2 bits of nla_type for nested and byteorder */
#define NLA_F_NESTED		(1 << 15)	/* nested attributes */
#define NLA_F_NET_BYTEORDER	(1 << 14)	/* set if data in net order */
#define NLA_TYPE_MASK		~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)

#define NLA_ALIGNTO		4U
#define NLA_ALIGN(len)          (((len) + NLA_ALIGNTO - 1) & ~(NLA_ALIGNTO - 1))
#define NLA_HDRLEN              ((int) NLA_ALIGN(sizeof(struct nlattr)))

#define MAX_LINKS 32

#define _SC_UIO_MAXIOV	_SC_IOV_MAX
#define SO_RCVBUFFORCE SO_RCVBUF

#endif /* _UAPI_LINUX_NETLINK_H */
