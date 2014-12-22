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
 */
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/libkern.h>
#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>

#include <net/netlink.h>

MALLOC_DEFINE(M_NETLINK, "netlink", "Memory used for netlink packets");

/*
 * dispatch table for various netlink handlers
 */
struct bsd_nl_fn nlp[MAX_LINKS];

int
bsd_nl_proto_check(int proto)
{
	if (proto < 0 || proto >= MAX_LINKS)
		return EINVAL;
	return (nlp[proto].rx == NULL) ? EAFNOSUPPORT : 0;
}

/* register a new netlink family */
int
bsd_nl_proto_reg(struct bsd_nl_fn *x)
{
	uint32_t id;

	if (x == NULL) {
		printf("cannot register NULL netlink proto\n");
		return EINVAL;
	}
	id = x->id;
	if (id >= MAX_LINKS) {
		printf("netlink proto %d too high\n", id);
		return EINVAL;
	}
	if (x->rx == NULL) {
		printf("netlink rx fn for proto %d missing\n", id);
		return EINVAL;
	}
	if (nlp[id].rx != NULL) {
		printf("netlink proto %d already registered\n", id);
	}
	nlp[id].rx = x->rx;
	nlp[id].id = id;
	return 0;
}

// XXX compare with linux validate_nla
/*
 * Minimum length of various netlink attribute types.
 * The number of types is small so we can use this array
 * (ideally we could even go down to uint8_t, no attribute
 * is longer than 16 bytes apparently.
 */
static const uint16_t nla_attr_minlen[NLA_TYPE_MAX+1] = {
        [NLA_U8]        = sizeof(uint8_t),
        [NLA_U16]       = sizeof(uint16_t),
        [NLA_U32]       = sizeof(uint32_t),
        [NLA_U64]       = sizeof(uint64_t),
        [NLA_MSECS]     = sizeof(uint64_t),
        [NLA_NESTED]    = NLA_HDRLEN,
        [NLA_S8]        = sizeof(int8_t),
        [NLA_S16]       = sizeof(int16_t),
        [NLA_S32]       = sizeof(int32_t),
        [NLA_S64]       = sizeof(int64_t),
};

/*
 * These validate functions return a negative error number because
 * the nla_parse(), a linux API, does so.
 * XXX nla_type() is really a sequence number in the policy definition.
 */
static int
validate_nla(const struct nlattr *nla, int maxtype,
	const struct nla_policy *policy)
{
	const struct nla_policy *pt;
	uint16_t alen = (uint16_t)nla_len(nla);
	/* len excluding header, caller guarantees alen >= 0 */
	uint16_t i, plen, atype = (uint16_t)nla_type(nla);
	/* we need to cast atype due to a buggy definition of nla_type() */
	const uint8_t *data = nla_data(nla);

	if (atype > maxtype)
		return 0; /* invalid fields are skipped */

	pt = &policy[atype];
	if (pt->type > NLA_TYPE_MAX) /* error in the policy! */
		return -EINVAL;

	plen = pt->len; /* how much space is allowed by policy ? */
        switch (pt->type) {
	case NLA_FLAG:
		return (alen != 0) ? -ERANGE : 0; /* nla error */

	case NLA_NUL_STRING: /* plen excludes the NUL */
		/*
		 * if plen>0, that is the limit (excluding NUL),
		 * but never more than alen.
		 */
		if (plen && plen+1 < alen)
			alen = plen + 1;
		if (alen == 0)
			return -EINVAL;

		/* Search for NUL termination */
		for (i = 0; i < alen; i++) {
			if (data[i] == 0)
				return 0; /* all fine */
		}
		return -EINVAL; /* missing terminator */

	case NLA_STRING: /* non terminated strings */
		if (alen == 0) /* empty strings not allowed */
			return -ERANGE;
		if (plen) { /* check the limit */
			if (data[alen - 1] == 0)
				alen--;
			if (alen > plen)
				return -ERANGE;
		}
		return 0;

	case NLA_BINARY:
		return (plen && alen > plen) ? -ERANGE : 0;

	case NLA_NESTED_COMPAT:
		/* plen indicates minimum alen */
		if (alen < plen) /* too short */
			return -ERANGE;
		if (alen < NLA_ALIGN(plen)) /* ok (including padding */
			break;
		/* if alen >= plen we need another header */
		if (alen < NLA_ALIGN(plen) + NLA_HDRLEN)
			return -ERANGE;
		nla = (const struct nlattr *)(data + NLA_ALIGN(plen));
		if (alen < NLA_ALIGN(plen) + NLA_HDRLEN + nla_len(nla))
			return -ERANGE;
		break;

	case NLA_NESTED:
		/* a nested attributes is allowed to be empty; if it is not,
		 * it must have a size of at least NLA_HDRLEN.
		 * plen is not used.
		 */
		if (alen == 0)
			break;
		/* fallthrough */
	default:
		if (plen) {
			if (alen < plen)
				return -ERANGE;
		} else if (pt->type != NLA_UNSPEC) {
			if (alen < nla_attr_minlen[pt->type])
				return -ERANGE;
		} /* else pass */
        }

	return 0;
}


/*
 * XXX return a negative value on error as on linux.
 * XXX check structure
 * Parse a sequence of attributes, storing results into tb[].
 * We accept one attribute per type (overwring tb[t] in case
 * of duplicates (note that the type-space is 2^14)
 */
int
nla_parse(struct nlattr **tb, int maxtype,
	const struct nlattr *head, int len, const struct nla_policy *policy)
{
	/* XXX: parse attributes carefully using policy */
	const struct nlattr * nla;
	int err;

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	for (nla = head; (const char *)nla < (const char *)head + len &&
		nla->nla_len >= sizeof(*nla);
	     nla = (const struct nlattr *)((const char *)nla + NLMSG_ALIGN(nla->nla_len))) {
		uint16_t t = (uint16_t)nla_type(nla); /* cast is safe */
		if (t <= maxtype) {
			if (policy) {
				err = validate_nla(nla, maxtype, policy);
				if (err != 0)
					return err;
			}
			tb[t] = (struct nlattr *)(uintptr_t)nla;
		}
	}

	return 0;
}

/*
 * Messages are created incrementally, and a lot of routines
 * assume contiguos buffers which are a bad fit for mbufs.
 *
 * Hence we build them this way:
 * - always make sure a contiguous buffer is available,
 *   pointed by _MA(m) (m->m_pkthdr.rcvif)
 *   and of length _ML(m)  (m->m_pkthdr.flowid)
 * - if possible make the contiguous buffer part of the existing
 *   mbuf so we do not need extra allocations.
 * - if the buffer is externally allocated, at the end
 *   it must be copied and freed.
 * - we track the used space in m_pkthdr.len
 */


/*
 * nlmsg_new() is part of the public API for netlink.
 * on linux it is just alloc_skb()
 *
 * Can be called with M_NOWAIT or M_WAITOK so we handle failures.
 *
 * Here we call m_getm() and if the buffer is not contiguous (only happens
 * when it is too large) we allocate an external buffer.
 * In all case set _ML(m) to the requested capacity.
 *
 * The 'put' messages always update m->m_pkthdr.len
 */
struct mbuf *
nlmsg_new(size_t payload, int flags)
{
	uint32_t l = NLMSG_SPACE(payload);
	struct mbuf *m = m_getm(NULL, l, flags, MT_DATA);
	/* XXX could use M_TRAILINGSPACE(m) ? */
	int space = (m->m_flags & M_EXT) ? m->m_ext.ext_size :
                        ((m->m_flags & M_PKTHDR) ? MHLEN : MLEN);

	D("got %d bytes space %d at %p", l, space, _P32(m));
	if (m) {
		/* we really want a contiguous buffer,
		 * so if we have some odd length we allocate one
		 * and store the pointer in rcvif
		 */
		_MA(m) = (l <= space) ? mtod(m, void *) :
			malloc(l, M_NETLINK, flags|M_ZERO);
		if (_MA(m)) {
			_ML(m) = l;
		} else {
			m_freem(m);
			m = NULL;
		}
	}
	return m;
}

/*
 * create a msg with nlmsghdr; nlmsgerr; error
 * in case of error
 */
static void
netlink_ack(uint8_t proto, uint32_t portid, struct nlmsghdr * nlmsg, int err)
{
	struct mbuf *m;
	struct nlmsghdr * repnlh;

	struct nlmsgerr *errmsg;
	int payloadsize = sizeof(*errmsg);

	if (err)
		payloadsize += nlmsg->nlmsg_len;

	D("starting, err %d len %d", err, payloadsize);
	m = nlmsg_new(payloadsize, M_WAITOK);
	_MP(m) = proto; /* this is used later in netlink_input() */
	/* XXX we don't set NETLINK_CB() */

	// XXX nlmsg_put()
	repnlh = (struct nlmsghdr *)_MC(m);
	repnlh->nlmsg_type = NLMSG_ERROR;
	repnlh->nlmsg_flags = 0;
	repnlh->nlmsg_seq = nlmsg->nlmsg_seq;
	repnlh->nlmsg_pid = portid;
	m->m_pkthdr.len += NLMSG_HDRLEN;

	// XXX unclear how much i should copy
	errmsg = (struct nlmsgerr *)_MC(m);
	errmsg->error = err;
#if 0 // XXX check
	m->m_pkthdr.len +=
		NLMSG_ALIGN(err ?
		nlmsg->nlmsg_len + sizeof(*errmsg) - sizeof(*nlmsg):
		sizeof(*errmsg));
	/* In case of error copy the whole message */
	memcpy(&errmsg->msg, nlmsg, err ? nlmsg->nlmsg_len : sizeof(*nlmsg));
#endif

	nlmsg_end(m, repnlh);

	/* I should call unicast, but it's the same */
	nlmsg_reply(m, NULL);
}

/*
 * message from a netlink socket (coming from userspace)
 */
int
netlink_receive_packet(struct mbuf *m, struct socket *so, int proto)
{
	char *buf = NULL;
	int datalen = 0, ofs = 0;
	int pktlen = m_length(m, NULL);
	int (*cb)(char *data) = nlp[proto].rx;

	/*
	 * Since we don't have a guaranteed linear buffer, we copy to
	 * a locally allocared one.
	 */
	while (ofs + NLMSG_HDRLEN <= pktlen) {
		struct nlmsghdr hdr, *h = &hdr;
		int l, err = 0;
		/* Copy the header */
		m_copydata(m, ofs, sizeof(hdr), (caddr_t)h);

		/* exit if msg too small or exceeds the packet length */
		l = h->nlmsg_len;
		D("ofs %d read %d, msglen %d", ofs, NLMSG_HDRLEN, l);
		if (l < NLMSG_HDRLEN || ofs + l > pktlen) {
			D("bad len %d ofs %d pktlen %d", l, ofs, pktlen);
			break; /* also free if needed */
		}
		if (l > datalen) { /* must reallocate */
			int old_l = datalen;
			(void)old_l;
			datalen = (l + 0x3ff) & ~0x3ff; /* round to 1k */
			ND("reallocate buffer %d -> %d [%d]",
				old_l, l, datalen);
			if (buf != NULL) {
				free(buf, M_NETLINK);
			}
			// XXX can i use M_WAIT ?
			buf = malloc(datalen, M_NETLINK, M_NOWAIT|M_ZERO);
			if (buf == NULL) /* just return, already freed */ {
				D("malloc failed, exit");
				return ENOMEM;
			}
		}
		ND("Copy the whole message");
		m_copydata(m, ofs, l, buf);
		h = (struct nlmsghdr *)buf;
		if (h->nlmsg_flags & NLM_F_REQUEST &&
		    h->nlmsg_type >= NLMSG_MIN_TYPE) {
			D("process the callback");
			err = cb((void *)h);
			D("callback returns %d", err);
		}

		if (err != EINTR && (h->nlmsg_flags & NLM_F_ACK || err != 0))
			netlink_ack(_MP(m), NETLINK_CB(m).portid, h, err);

		ofs += NLMSG_ALIGN(l);
		D("ack done, now moving to %d/%d", ofs, pktlen);
	}
	D("done, freeing %p", _P32(buf));
	if (buf != NULL)
		free(buf, M_NETLINK);
	return 0;
}


int
nla_put(struct mbuf *m, int attrtype, int attrlen, const void *data)
{
	struct nlattr *nla;
	size_t totlen = NLMSG_ALIGN(NLA_HDRLEN + attrlen);
	size_t need = NLMSG_ALIGN(totlen);

	if (m->m_pkthdr.len + need > _ML(m))
		return -EMSGSIZE;
	nla = (struct nlattr *)_MC(m);
	bzero(nla, NLA_HDRLEN);
	nla->nla_len = totlen;
	nla->nla_type = attrtype;
	m->m_pkthdr.len += NLA_HDRLEN;
	if (attrlen > 0) {
		uint32_t pad = need - totlen;
		bcopy(data, _MC(m), attrlen);
		m->m_pkthdr.len += attrlen;
		if (pad) { /* add padding */
			bzero(_MC(m), pad);
			m->m_pkthdr.len += pad;
		}
	}
	return 0;
}

struct nlattr *
nla_nest_start(struct mbuf *m, int attrtype)
{
	// XXX we should return the starting of the attribute after
	// possibly moving
	struct nlattr *start = (struct nlattr *)_MC(m);

	if (nla_put(m, attrtype, 0, NULL) < 0)
		return NULL;

	return start;
}

int
nla_nest_end(struct mbuf *m, struct nlattr *start)
{
	start->nla_len = _MC(m) - (char *)start;
	return m->m_pkthdr.len; // XXX
}

void
nla_nest_cancel(struct mbuf *m, struct nlattr* start)
{
	m->m_pkthdr.len = (char *)start - (char *)_MA(m);
}

/*
 * copy initial part of the attributes, reserve space
 */
struct
nlattr *nla_reserve(struct mbuf *m, int attrtype, int attrlen)
{
	size_t totlen = NLA_HDRLEN + attrlen;
	struct nlattr * nla;
	int space = _ML(m) - m->m_pkthdr.len;
	int want = NLMSG_ALIGN(totlen);

	if (space < want)
		return NULL;

	nla = (struct nlattr *)((char *)_MA(m) + m->m_pkthdr.len);
	nla->nla_len = totlen;
	nla->nla_type = attrtype;

	memset((char *) nla + totlen, 0, want - totlen);

	m->m_pkthdr.len += want;

	return nla;
}

/*
 * update the total message length
 * Note, the copy from the external buffer is done in nlmsg_reply()
 */
int
nlmsg_end(struct mbuf *m, struct nlmsghdr *nlh)
{
	nlh->nlmsg_len = _MC(m) - (char *)nlh;
	return m->m_pkthdr.len;
}

// XXX why do we ignore the info ?
int
nlmsg_reply(struct mbuf *m, struct genl_info *info)
{
	int l = m->m_pkthdr.len;

	D("have %d bytes out of %d", l, _ML(m));
	if ((char *)_MA(m) == mtod(m, char *)) { /* simple, plain mbuf */
		m->m_len = l; /* update this mbuf's len */
	} else { /* external buffer */
		m_copyback(m, 0, l, (char *)_MA(m));
		D("copy data from external buffer, plen %d len %d",
			m->m_pkthdr.len, m->m_len);
		free(_MA(m), M_NETLINK);
	};
	/* clear extra fields */
	_MA(m) = NULL;
	_ML(m) = 0;
	/* XXX we still need MP() */
	return bsd_netlink_send_msg(NULL, m);
}
