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
 * Kernel-private header for genetlink.
 * Has nested includes for the whole netlink kernel API
 */

#ifndef _NET_GENETLINK_H
#define _NET_GENETLINK_H

#include <linux/genetlink.h>
#include <net/netlink.h>

#ifdef __COMPAT_MBUF_TYPE
#define mbuf __COMPAT_MBUF_TYPE
#endif /* __COMPAT_MBUF_TYPE */

#define GENL_HDRLEN NLMSG_ALIGN(sizeof(struct genlmsghdr))

#define GENL_ADMIN_PERM         0x01
#define GENL_CMD_CAP_DO         0x02
#define GENL_CMD_CAP_DUMP       0x04
#define GENL_CMD_CAP_HASPOL     0x08

struct genl_info;
struct mbuf;	/* we must be compilable with an opaque type */
struct netlink_callback;
struct net;

struct genl_multicast_group;

struct genl_family {
	unsigned int            id;
	unsigned int            hdrsize;
	char                    name[GENL_NAMSIZ];
	unsigned int            version;
	unsigned int            maxattr;
	bool                    netnsok;
	bool                    parallel_ops;
#if 0 /* XXX TODO:restore it */
	int                     (*pre_doit)(struct genl_ops *ops,
			struct mbuf *m,
			struct genl_info *info);
	void                    (*post_doit)(struct genl_ops *ops,
			struct mbuf *m,
			struct genl_info *info);
	struct nlattr **        attrbuf;        /* private */

	
	struct list_head        ops_list;       /* private */
	struct list_head        family_list;    /* private */
	struct list_head        mcast_groups;   /* private */
#endif
	LIST_ENTRY(genl_family) family_list;
	const struct genl_ops *ops; // XXX was ops_list;
	/* TODO: only one possible group per family */
	const struct genl_multicast_group *mcgrps; // XXX was  mcast_group;
	unsigned int n_ops;	// XXX was size_t ops_num;
	unsigned int n_mcgrps;
	unsigned int mcgrp_offset; // from 3.13
};

struct genl_multicast_group {
	struct genl_family *    family;        /* private */
	char                    name[GENL_NAMSIZ];
	uint32_t                id;
};

struct genl_ops {
	uint8_t                 cmd;
	uint8_t                 internal_flags;
	unsigned int            flags;
	const struct nla_policy *policy;
	int                    (*doit)(struct mbuf *m,
			struct genl_info *info);
	int                    (*dumpit)(struct mbuf *m,
			struct netlink_callback *cb);
	#if 0
	/* TODO: fields not used by openvswitch */
	int                    (*done)(struct netlink_callback *cb);
	struct list_head        ops_list;
	#endif
};

struct genl_info {
	uint32_t                snd_seq;
	uint32_t                snd_portid;
	struct nlmsghdr *       nlhdr;
	struct genlmsghdr *     genlhdr;
	void *                  userhdr;
	struct nlattr **        attrs;
#if 0 // XXX check
#ifdef CONFIG_NET_NS
	struct net *            _net;
#endif
	void *                  user_ptr[2];
#endif
};

struct netlink_callback {
	struct mbuf          *skb; /* linux calls this this way */
	const struct nlmsghdr   *nlh;
#if 0
	int                     (*dump)(struct mbuf * m,
			struct netlink_callback *cb);
	int                     (*done)(struct netlink_callback *cb);
	void                    *data;
	/* the module that dump function belong to */
	struct module           *module;
	u16                     family;
	u16                     min_dump_alloc;
	unsigned int            prev_seq, seq;
#endif
	long                    args[6];
};



int genl_register_family_with_ops(struct genl_family *family,
					struct genl_ops *ops, size_t n_ops);
static inline int
genl_register_family(struct genl_family *family)
{
	return genl_register_family_with_ops(family, NULL, 0);
}

int genl_unregister_family(struct genl_family *family);

/*
 * XXX incomplete
 */
static inline int
genl_set_err(struct genl_family *fam, struct net *net,
	uint32_t portid, uint32_t group, uint32_t code)
{
	if (group >= fam->mcgrp_offset)
		return -EINVAL;
	group += fam->mcgrp_offset;
	/* we do not support namespaces yet */
	netlink_set_err(NULL /* net->genl_sock */, portid, group, code);
	return 0;
}

/**
 * genlmsg_msg_size - length of genetlink message not including padding
 * @payload: length of message payload
 */
static inline int
genlmsg_msg_size(int payload)
{
	return GENL_HDRLEN + payload;
}

/**
 * genlmsg_total_size - length of genetlink message including padding
 * @payload: length of message payload
 */
static inline int
genlmsg_total_size(int payload)
{
	return NLMSG_ALIGN(genlmsg_msg_size(payload));
}

static inline void *
genlmsg_data(const struct genlmsghdr *gnlh)
{
        return ((unsigned char *) (uintptr_t)gnlh + GENL_HDRLEN);
}

/**
 * genlmsg_new - Allocate a new generic netlink message
 * @payload: size of the message payload
 * @flags: the type of memory to allocate.
 */
static inline struct mbuf *
genlmsg_new(size_t payload, int flags)
{
	return nlmsg_new(genlmsg_total_size(payload), flags);
}

static inline void
genlmsg_cancel(struct mbuf *m, void *hdr)
{
}

void *genlmsg_put(struct mbuf *m, uint32_t portid, uint32_t seq,
			struct genl_family *family, int flags, uint8_t cmd);
int genlmsg_end(struct mbuf *m, void *hdr);
int genlmsg_reply(struct mbuf *m, struct genl_info *info);
void genl_notify(struct genl_family *f,
	struct mbuf *m, struct net *net, uint32_t portid, uint32_t group,
			struct nlmsghdr *nlh, int flags);
int genlmsg_multicast(struct genl_family *family,
	struct mbuf *m, uint32_t portid, unsigned int group, int flags);
/* TODO: net namespace not implemented */
#define genlmsg_multicast_netns(f, net,a,b,c,d) genlmsg_multicast(f, a,b,c,d)
int genl_register_mc_group(struct genl_family *family,
				struct genl_multicast_group *grp);
int genlmsg_unicast(struct net *net, struct mbuf *m, uint32_t portid);

/* TODO: net namespace not implemented */
#define genl_info_net(info) NULL

#undef mbuf // just in case, see __COMPAT_MBUF_TYPE

#endif /* _NET_GENETLINK_H */
