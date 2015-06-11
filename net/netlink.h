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
 * Extended kernel netlink APIs
 * Has nested include for linux/netlink.h
 */

#ifndef _NET_NETLINK_H
#define _NET_NETLINK_H

#ifndef _KERNEL
#error this is a kernel-only file
#endif

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/syslog.h>

#include <linux/netlink.h>

#ifdef __COMPAT_MBUF_TYPE
#define mbuf __COMPAT_MBUF_TYPE
#endif /* __COMPAT_MBUF_TYPE */

/*
 * support for registering NETLINK protocols.
 * bsd_nl_fn is the protocol descriptor, bsd_nl_proto_reg() registers it.
 * We do not support unloading.
 */
struct bsd_nl_fn { /* protocol descriptors */
	uint32_t id; /* protocol id */
	int (*rx)(char *data);
};

/* register a protocol */
int bsd_nl_proto_reg(struct bsd_nl_fn *);
/* EINVAL for bad proto numbers, EAFNOSUPPORT if not set, 0 if ok */
int bsd_nl_proto_check(int proto);

/* these are FreeBSD internal APIs */
int bsd_netlink_send_msg(struct socket *so, struct mbuf *m);
int netlink_receive_packet(struct mbuf *, struct socket *, int);

#define M_NETLINK_MULTICAST	M_PROTO1
#define M_NEGATIVE_ERROR	M_PROTO2

#define	nl_src_portid	so_fibnum
#define	nl_dst_portid	so_user_cookie


/*
 * netlink attribute types.
 */
enum {
	NLA_UNSPEC,
	NLA_U8,
	NLA_U16,
	NLA_U32,
	NLA_U64,
	NLA_STRING,
	NLA_FLAG,
	NLA_MSECS,
	NLA_NESTED,
	NLA_NESTED_COMPAT,
	NLA_NUL_STRING,
	NLA_BINARY,
	NLA_S8,
	NLA_S16,
	NLA_S32,
	NLA_S64,
	__NLA_TYPE_MAX,
};

#define NLA_TYPE_MAX (__NLA_TYPE_MAX - 1)

struct nla_policy {
	uint16_t        type;
	uint16_t        len;
};

static inline int
nlmsg_msg_size(int payload_size)
{
	return NLMSG_HDRLEN + payload_size;
}

/*
 * create a new mbuf for a netlink msg.
 * Flags includes M_NEGATIVE_ERROR to indicate how we want nla_put()
 * to return errors (linux clients need negative error values).
 */
struct mbuf *nlmsg_new(size_t payload, int flags);

static inline void *
nlmsg_data(const struct nlmsghdr *nlh)
{
	return (unsigned char *)(uintptr_t) nlh + NLMSG_HDRLEN;
}

void nlmsg_trim(struct mbuf *m, const void *mark); /* in netlink.c */

static inline void
nlmsg_cancel(struct mbuf *m, struct nlmsghdr *nlh)
{
	nlmsg_trim(m, nlh);
}

int nlmsg_end(struct mbuf *m, struct nlmsghdr *nlh);

struct nlmsghdr *nlmsg_put(struct mbuf *m, uint32_t portid,
	uint32_t seq, int type, int payload, int flags);

struct genl_info; // XXX
int nlmsg_reply(struct mbuf *m, struct genl_info *info);


/*
 * kernel routines to manipulate netlink attributes (nla_*)
 */

/*
 * nla_put() and __nla_put() append data to a nlmsg.
 * __nla_put() does not check for space.
 * Return 0 if ok, EMSGSIZE on error
 */
int nla_put(struct mbuf *m, int attrtype, int attrlen, const void *data);
#define __nla_put nla_put

static inline int
nla_put_u8(struct mbuf *m, int attrtype, uint8_t value)
{
	return nla_put(m, attrtype, sizeof(uint8_t), &value);
}

static inline int
nla_put_u16(struct mbuf *m, int attrtype, uint16_t value)
{
        return nla_put(m, attrtype, sizeof(uint16_t), &value);
}

static inline int
nla_put_u32(struct mbuf *m, int attrtype, uint32_t value)
{
	return nla_put(m, attrtype, sizeof(uint32_t), &value);
}

static inline int
nla_put_u64(struct mbuf *m, int attrtype, uint64_t value)
{
	return nla_put(m, attrtype, sizeof(uint64_t), &value);
}

static inline int
nla_put_flag(struct mbuf *m, int attrtype)
{
	return nla_put(m, attrtype, 0, NULL);
}

static inline int
nla_put_string(struct mbuf *m, int attrtype,
					const char *str)
{
	return nla_put(m, attrtype, strlen(str) + 1, str);
}

/* note we de-const the argument */
static inline void *
nla_data(const struct nlattr *nla)
{
	return (char *)(uintptr_t) nla + NLA_HDRLEN;
}

static inline uint8_t
nla_get_u8(const struct nlattr *nla)
{
	return *(const uint8_t *) nla_data(nla);
}

static inline uint16_t
nla_get_u16(const struct nlattr *nla)
{
	return *(const uint16_t *) nla_data(nla);
}

static inline uint32_t
nla_get_u32(const struct nlattr *nla)
{
	return *(const uint32_t *) nla_data(nla);
}

static inline uint64_t nla_get_u64(const struct nlattr *nla)
{
	/* TODO: in linux this is done differently. why? */
	return *(const uint64_t *) nla_data(nla);
}

struct nlattr *nla_nest_start(struct mbuf *m, int attrtype);
int nla_nest_end(struct mbuf *m, struct nlattr *start);
static inline void
nla_nest_cancel(struct mbuf *m, struct nlattr* start)
{
	nlmsg_trim(m, start);
}

struct nlattr * nla_reserve(struct mbuf *m, int attrtype, int attrlen);
#define __nla_reserve nla_reserve

/**
 * nla_attr_size - length of attribute not including padding
 * @payload: length of payload
 */
static inline int
nla_attr_size(int payload)
{
	return NLA_HDRLEN + payload;
}

/**
 * nla_total_size - total length of attribute including padding
 * @payload: length of payload
 */
static inline int
nla_total_size(int payload)
{
	return NLA_ALIGN(nla_attr_size(payload));
}



static inline int
nla_ok(const struct nlattr *nla, int remaining)
{
	return remaining >= (int) sizeof(*nla) &&
		nla->nla_len >= sizeof(*nla) &&
		nla->nla_len <= remaining;
}

static inline struct nlattr *
nla_next(const struct nlattr *nla, int *remaining)
{
	int totlen = NLA_ALIGN(nla->nla_len);

	*remaining -= totlen;
	return (struct nlattr *) ((char *) (uintptr_t)nla + totlen);
}

static inline int
nla_is_last(const struct nlattr *nla, int rem)
{
        return nla->nla_len == rem;
}

/*
 * NOTE: this should return unsigned, not signed, because the underlying
 * nla->nla_type is unsigned. Unfortunately also on linux the function
 * returns a signed value.
 */
static inline int
nla_type(const struct nlattr *nla)
{
	return nla->nla_type & NLA_TYPE_MASK;
}

static inline int
nla_len(const struct nlattr *nla)
{
	return nla->nla_len - NLA_HDRLEN;
}

static inline int
nla_padlen(int payload)
{
	return nla_total_size(payload) - nla_attr_size(payload);
}


#define nla_for_each_attr(pos, head, len, rem) \
	for (pos = head, rem = len; \
		nla_ok(pos, rem); \
		pos = nla_next(pos, &(rem)))

#define nla_for_each_nested(pos, nla, rem) \
        nla_for_each_attr(pos, nla_data(nla), nla_len(nla), rem)

#define nla_put_be64 nla_put_u64
#define nla_put_be32 nla_put_u32
#define nla_put_be16 nla_put_u16
#define nla_get_be16 nla_get_u16
#define nla_get_be32 nla_get_u32
#define nla_get_be64 nla_get_u64

/*
 * nla_parse*() should return a negative error on linux,
 * but we have no way to discriminate the caller.
 * XXX perhaps introduce bsd_nla_parse*() with the bsd return values.
 */
int bsd_nla_parse(struct nlattr **tb, int maxtype, const struct nlattr *head,
		int len, const struct nla_policy *policy);

static inline int
bsd_nla_parse_nested(struct nlattr *tb[], int maxtype,
	const struct nlattr *nla, const struct nla_policy *policy)
{
	return bsd_nla_parse(tb, maxtype, nla_data(nla), nla_len(nla), policy);
}

static inline int
nla_parse(struct nlattr **tb, int maxtype, const struct nlattr *head,
		int len, const struct nla_policy *policy)
{
	return -nla_parse(tb, maxtype, head, len, policy);
}

static inline int
nla_parse_nested(struct nlattr *tb[], int maxtype,
	const struct nlattr *nla, const struct nla_policy *policy)
{
	return -bsd_nla_parse_nested(tb, maxtype, nla, policy);
}


#define nla_memcpy(dest, src, len) \
	memcpy(dest, nla_data(src), min(len,nla_len(src)))

#undef mbuf /* XXX see __COMPAT_MBUF_TYPE */

#endif /* _NET_NETLINK_H */
