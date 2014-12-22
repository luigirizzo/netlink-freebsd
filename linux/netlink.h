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
 * The netlink API (both userspace and kernel).
 * For compatibility with linux, the user API part is in a separate file.
 * Both need to be installed in the headers for building user apps.
 */

#ifndef _LINUX_NETLINK_H
#define _LINUX_NETLINK_H

#include <linux/uapi_netlink.h>

#ifdef _KERNEL
/*
 * Kernel-specific netlink api
 */

/*---- start debugging macros --- luigi */
#define ND(format, ...)
#define D(format, ...)                                          \
        do {                                                    \
                struct timeval __xxts;                          \
                microtime(&__xxts);                             \
                printf("%03d.%06d [%4d] %-25s " format "\n",    \
                (int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, \
                __LINE__, __FUNCTION__, ##__VA_ARGS__);         \
        } while (0)

/* rate limited, lps indicates how many per second */
#define RD(lps, format, ...)                                    \
        do {                                                    \
                static int t0, __cnt;                           \
                if (t0 != time_second) {                        \
                        t0 = time_second;                       \
                        __cnt = 0;                              \
                }                                               \
                if (__cnt++ < lps)                              \
                        D(format, ##__VA_ARGS__);               \
        } while (0)
/* XXX 32-bit pointers */
#define _P32(x) ((void *)( \
	((uintptr_t)x & 0x8fffffff) | (((uintptr_t)x >> 32) & 0x80000000) ) )


/*---- end debugging macros --- luigi */

#ifdef __COMPAT_MBUF_TYPE
/*
 * native linux kernel code has sk_buff * as first argument to netlink calls.
 * Our code handles both mbufs and skbufs, but we want to avoid errors
 * on the prototype, so linux-derived code can #define __COMPAT_MBUF_TYPE
 * to sk_buff so the compiler gets the correct prototypes.
 * The definition is only used within the headers.
 */
#define mbuf __COMPAT_MBUF_TYPE
#endif /* __COMPAT_MBUF_TYPE */

struct socket;
struct mbuf;	/* we must be compilable with an opaque type */

/*
 * Some mbuf pkthdr fields have special meaning when used with netlink:
 *
 *	FIELD	MACRO		DESCRIPTION
 *
 * 	rcvif	_MA()		linear buffer, possibly external
 *	fibnum	_ML()		linear buffer length
 *	len	--		current write offset
 *	flowid	NETLINK_CB()	src_portid, 32 bit
 *	rsstype	_MP()		protocol (NETLINK_GENERIC etc.)
 *
 * In more detail:
 *
 * 1. netlink messages are built incrementally in a linear buffer of
 * predefined size. This is a poor match with mbuf chains,
 * which may be split and have no predefined size.
 * Hence we use two mbuf fields (see above, _MA() and _ML() )
 * for the linear buffer pointer and max len,
 * and use m_pkthdr.len to record the space used so far
 * (remember of course to copy back and fix things before sending).
 * These are abstracted by the three macros _MA)(), _ML() and _MC()
 * _MA() and _ML() are cleared when passing the buffer back to the kernel
 *
 * 2. The protocol is mapped through _MP(m) into rsstype, and is used
 * in netlink_input()
 *
 * 3. sk_buff have a 48-byte "control buffer" (cb) to carry aux info.
 * In netlink this is wrapped by NETLINK_CB() into a pointer to a
 * struct netlink_skb_parms.
 * We need at least the portid, the source port for
 * messages coming from userspace, which in turn is used to locate the
 * destination socket when building a reply.
 * Netlink messages do not need flowid, so we store the portid there.
 * 
 */

#ifndef __COMPAT_MBUF_TYPE /* mappings only work in native systems */

#define _MA(m)  (m)->m_pkthdr.rcvif   /* linear buffer pointer */
#define _ML(m)  ((m)->m_pkthdr.fibnum)  /* max length, 16 bit */
#define _MC(m)  ((char *)_MA(m) + (m)->m_pkthdr.len) /* cur data ptr */

#define _MP(m)  ((m)->m_pkthdr.rsstype)  /* netlink proto, 8 bit */

#define NETLINK_CB(_m)	(*(struct netlink_skb_parms*)&((_m)->m_pkthdr.flowid))

#else /* __COMPAT_MBUF_TYPE */	/* mbufs are remapped XXX */
/* returns a readonly object */
struct netlink_skb_parms NETLINK_CB(struct mbuf *);
#endif /* !__COMPAT_MBUF_TYPE */

struct netlink_skb_parms { /* XXX needs work */
#if 0
	struct scm_creds	creds; /* skb credentials      */
#endif
	uint32_t		portid;
#if 0
	uint32_t		dst_group;
	uint32_t		flags;
	struct sock		*ssk;
#endif
};

CTASSERT(sizeof(struct netlink_skb_parms) <= sizeof(uint32_t));


/* TODO: this function is not really remapped.
 * It is just a stub that logs the error
 */
#include <sys/syslog.h> /* LOG_INFO */
static inline void
netlink_set_err(void *sock, uint32_t pid, uint32_t group, int err)
{
	log(LOG_INFO, "Netlink set err, func:%s\n", __func__);
}

/*
 * Linux uses 8192 as a limit, but probably we can go down to 4k
 */
// #define NLMSG_DEFAULT_SIZE (8192 - NLMSG_HDRLEN)
#define NLMSG_DEFAULT_SIZE (4096 - NLMSG_HDRLEN)

#undef mbuf /* XXX see __COMPAT_MBUF_TYPE */

#endif /* _KERNEL */

#endif /* _LINUX_NETLINK_H */
