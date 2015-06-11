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
 * genetlink-specific functions
 */

#include <sys/param.h>
#include <sys/lock.h>
#include <sys/mutex.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/priv.h>
#include <sys/mbuf.h>
#include <sys/queue.h>

#include <net/genetlink.h> /* full genetlink and netlink APIs */

static LIST_HEAD(, genl_family) genl_family_list =
         LIST_HEAD_INITIALIZER(genl_family_list);

static int
genl_ctrl_lookup_family(struct mbuf *m, struct genl_info * info);

static struct genl_ops genl_ctrl_ops = {
	.cmd = CTRL_CMD_GETFAMILY,
	.doit = genl_ctrl_lookup_family,
	/* TODO: dumpit and policy */
};

static struct genl_family genl_ctrl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "GENL_CTRL",
	.version = 0,
	.maxattr = CTRL_ATTR_MAX,
};

static int cur_max_genl_family;

static struct mtx genl_mutex;
MTX_SYSINIT(genl_mutex, &genl_mutex, "", MTX_DEF);

static void
genl_lock(void)
{
	mtx_lock(&genl_mutex);
}

static void
genl_unlock(void)
{
	mtx_unlock(&genl_mutex);
}

// XXX clean
int
genl_register_family_with_ops(struct genl_family *family,
	struct genl_ops *ops, size_t n_ops)
{
	/* TODO: should check family name collision */

	int idfamily = family->id;

	/*
	 * TODO: family id could be != GENL_ID_GENERATE. In this case we
	 * should try assign that as family id
	 */
	if (idfamily != GENL_ID_GENERATE)
		return EEXIST;
	/* TODO: id generation should be done better */
	idfamily = atomic_fetchadd_int(&cur_max_genl_family, 1);

	LIST_INSERT_HEAD(&genl_family_list, family, family_list);
	family->ops = ops;
	family->n_ops = n_ops;
	family->id = idfamily;

	return 0;
}

int
genl_unregister_family(struct genl_family *family)
{
	LIST_REMOVE(family, family_list);

	return 0;
}

int
genl_register_mc_group(struct genl_family *family,
	struct genl_multicast_group *grp)
{
	/* TODO: only one multicast supported per family */
	grp->id = family->id;
	grp->family = family;
	family->mcgrps = grp;

	/* TODO: notify userspace about this */
	return 0;
}

static int
genl_parse_info(char * data, const struct genl_family *family,
	const struct nla_policy *policy, struct genl_info *info)
{
	struct nlmsghdr *nlmsg = (struct nlmsghdr *)data;
	struct genlmsghdr *genlmsg =
		(struct genlmsghdr *)(data + NLMSG_HDRLEN);
	size_t datalen = nlmsg->nlmsg_len;
	const int ll = NLMSG_ALIGN(family->hdrsize);

	info->snd_seq = nlmsg->nlmsg_seq;
	info->snd_portid = nlmsg->nlmsg_pid;
	info->nlhdr = nlmsg;
	info->genlhdr = genlmsg;
	info->userhdr = (void *)((char *) genlmsg + GENL_HDRLEN);

	/*XXX/TODO: check that datalen > NLMSG_HDRLEN + GENL_HDRLEN + ll */

	return nla_parse(info->attrs, family->maxattr,
		  (struct nlattr *)((char *)info->userhdr + ll),
		  datalen - (NLMSG_HDRLEN + GENL_HDRLEN + ll), policy);
}

/*
 * put a message, return a pointer to the info
 */
void *
genlmsg_put(struct mbuf *m, uint32_t portid, uint32_t seq,
	struct genl_family *family, int flags, uint8_t cmd)
{
	struct nlmsghdr *nlh;
	struct genlmsghdr *g;

	nlh = nlmsg_put(m, portid, seq, family->id,
		GENL_HDRLEN + family->hdrsize, flags);
	if (nlh == NULL)
		return nlh; /* no space */
	g = nlmsg_data(nlh);
	g->cmd = cmd;
	g->version = family->version;
	g->reserved = 0;

	return g;
}

// XXX check
static int
genetlink_call_op_dumpit(const struct genl_ops *curop,
	struct nlmsghdr * nlmsg, struct genl_info *pinfo)
{
	int res, * pres;
	struct netlink_callback cb;
	struct mbuf *m;
	struct nlmsghdr * repnlh;

	memset(&cb, 0, sizeof(cb));

	genl_lock();
	do {
		m = nlmsg_new(NLMSG_DEFAULT_SIZE, M_WAITOK);
		/* TODO: real skb */
// XXX		NETLINK_CB(&skbforcallback).portid = nlmsg->nlmsg_pid;
		cb.skb = m;
		cb.nlh = nlmsg;

		res = curop->dumpit(m, &cb);
		if (res <= 0) {
			m_freem(m);
			break;
		}

		repnlh = mtod(m, struct nlmsghdr *);
		repnlh->nlmsg_flags |= NLM_F_MULTI;
		/* I should call unicast, but it's the same */
		genlmsg_reply(m, NULL);
	} while (res > 0);

	m = nlmsg_new(sizeof(res), M_WAITOK);


	repnlh = mtod(m, struct nlmsghdr *);
	repnlh->nlmsg_type = NLMSG_DONE;
	repnlh->nlmsg_flags = NLM_F_MULTI;
	repnlh->nlmsg_seq = nlmsg->nlmsg_seq;
	repnlh->nlmsg_pid = nlmsg->nlmsg_pid;
	m->m_len += NLMSG_HDRLEN;

	pres = mtod(m, int *);
	*pres = res;
	m->m_len += NLMSG_ALIGN(sizeof(res));

	nlmsg_end(m, repnlh);

	/* I should call unicast, but it's the same */
	genlmsg_reply(m, NULL);

	genl_unlock();

	/* If no error avoid ack */
	return (res == 0) ? EINTR : res;
}

static int
genetlink_call_op_doit(const struct genl_ops *curop,
	struct nlmsghdr *nlmsg, struct genl_info *pinfo)
{
	int err;

	genl_lock();
	/* TODO: Should pass an mbuf as first parameter, but it is unused */
	err = curop->doit(NULL, pinfo);

	genl_unlock();

	return err;
}

/*
 * never called with a NULL argument
 */
static int
genetlink_receive_message(char *data)
{
	struct nlmsghdr *nlmsg = (struct nlmsghdr *) data;
	struct genlmsghdr *genlmsg;
	struct genl_family *curfamily;
	const struct genl_ops *curop, *ops;
	struct genl_info info;
	int err = 0;
	int idfamily = nlmsg->nlmsg_type;
	int numop, i;
	/*
	 * maxattr is typically in the 10-15 range so we allocate a fixed
	 * number of entries and check later if we have enough space
	 */
#define _GNL_MAX_ATTR	32 /* don't want too much stack usage */
	struct nlattr *attrs[_GNL_MAX_ATTR];


	/* This should be in a function genl_family_find_byid */
	LIST_FOREACH(curfamily, &genl_family_list, family_list) {
		if (curfamily->id == idfamily)
			break;
	}

	D("process family %d %p", idfamily, curfamily);

	if (curfamily == NULL)
		return ENOENT;

	/* check if we have space */
	if (curfamily->maxattr + 1 > _GNL_MAX_ATTR) {
		D("no space to process attributes");
		return ENOMEM;
	}

	ops = curfamily->ops;

	genlmsg = (struct genlmsghdr *)(data + NLMSG_HDRLEN);
	numop = genlmsg->cmd;
	D("cmd is %d look into %d options", numop, curfamily->n_ops);
	for (i = 0; i < curfamily->n_ops; ++i) {
		if (ops[i].cmd == numop)
			break;
	}

	if (i >= curfamily->n_ops) {
		return EOPNOTSUPP;
	}

	curop = &(curfamily->ops[i]);

	/*
	 * Check that the caller has the appropriate permission
	 * for the operation:
	 * if the operation has the GENL_ADMIN_PERM flag,
	 * it cannot be executed by a user without CAP_NET_ADMIN
	 * privilege on Linux (PRIV_NET_ROUTE on FreeBSD)
	 */

	if (curop->flags & GENL_ADMIN_PERM &&
	    (err = priv_check(curthread, PRIV_NET_ROUTE)) != 0)
		return -err;

	info.attrs = attrs;
	err = genl_parse_info(data, curfamily, curop->policy, &info);
	if (err) {
		D("genl_parse_info returns error %d", err);
		return err;
	}

	/* XXX remove this log */
	log(LOG_INFO, "myhandler:idfamily:%d, numop%d %s\n",
		idfamily, numop,
		((nlmsg->nlmsg_flags & NLM_F_DUMP)?" (dump)":" ") );

	if (nlmsg->nlmsg_flags & NLM_F_DUMP && curop->dumpit) {
		err = genetlink_call_op_dumpit(curop, nlmsg, &info);
	} else if(!(nlmsg->nlmsg_flags & NLM_F_DUMP) && curop->doit) {
		err = genetlink_call_op_doit(curop, nlmsg, &info);
	} else {
		return EOPNOTSUPP;
	}

	return err;
}

int
genlmsg_end(struct mbuf *m, void *hdr)
{
	return nlmsg_end(m, (struct nlmsghdr *)
			 ((char *)hdr - (GENL_HDRLEN + NLMSG_HDRLEN)));
}

int
genlmsg_reply(struct mbuf *m, struct genl_info *info)
{
	return bsd_netlink_send_msg(NULL, m);
}

int
genlmsg_unicast(struct net *net, struct mbuf *m, uint32_t portid)
{
	struct nlmsghdr * nlmsg = mtod(m, struct nlmsghdr *);

	nlmsg->nlmsg_pid = portid;
	return bsd_netlink_send_msg(NULL, m);
}

static int
internal_genlmsg_multicast(struct mbuf *m)
{
	m->m_flags |= M_NETLINK_MULTICAST; /* XXX should be set already ? */
	return bsd_netlink_send_msg(NULL, m);
}

int
genlmsg_multicast(struct genl_family *fam,
	struct mbuf *m, uint32_t portid, unsigned int group, int flags)
{
	return internal_genlmsg_multicast(m);
}

/* XXX check this one, probably incorrect */
void
genl_notify(struct genl_family *f,
	struct mbuf *m, struct net *net, uint32_t portid,
	uint32_t group, struct nlmsghdr *nlh, int flags)
{
#if 0
	if (nlh) report = nlmsg_report(nlh);
	nlmsg_notify(..) {
		if (group) nlmsg_multicast...);
		if (report) nlmsg_unicast(...);
	}
#endif
	D("portid %d group %d", portid, group);
	internal_genlmsg_multicast(m);

	if (nlh && nlh->nlmsg_flags & NLM_F_ECHO)
		genlmsg_reply(m, NULL);
	else
		m_freem(m);
}

static int
genl_ctrl_lookup_family(struct mbuf *m, struct genl_info * info)
{
	struct genl_family * family;
	struct nlattr * nlaname = info->attrs[CTRL_ATTR_FAMILY_NAME];
	char * familyname = (char *)(nlaname + 1);
	struct mbuf * reply;
	void * hdr;

	/* TODO:implement also lookup by id */
	if (nlaname == NULL)
		return EINVAL;

	LIST_FOREACH(family, &genl_family_list, family_list) {
		if (strncmp(family->name, familyname, GENL_NAMSIZ) == 0)
			break;
	}

	if (family == NULL)
		return ENOENT;

	/* Family found!! */
	reply = nlmsg_new(NLMSG_DEFAULT_SIZE, M_WAITOK);
	hdr = genlmsg_put(reply, info->snd_portid, info->snd_seq,
				&genl_ctrl_family, 0,
				CTRL_CMD_GETFAMILY);
	nla_put_u16(reply, CTRL_ATTR_FAMILY_ID, family->id);

	if (family->mcgrps) {
		struct nlattr * nla_grps, * nest;
		const struct genl_multicast_group * grp = family->mcgrps;

		nla_grps = nla_nest_start(reply,
						CTRL_ATTR_MCAST_GROUPS);
		nest = nla_nest_start(reply, 1);
		nla_put_u32(reply, CTRL_ATTR_MCAST_GRP_ID, grp->id);
		nla_put_string(reply, CTRL_ATTR_MCAST_GRP_NAME,
				grp->name);
		nla_nest_end(reply, nest);
		nla_nest_end(reply, nla_grps);
	}

	genlmsg_end(reply, hdr);
	return genlmsg_reply(reply, info);
}

static struct bsd_nl_fn _me = {
	.id = NETLINK_GENERIC,
	.rx = genetlink_receive_message
};

static void
genetlinkload(void *u __unused)
{
	LIST_INIT(&genl_family_list);
	cur_max_genl_family = GENL_ID_CTRL;
	bsd_nl_proto_reg(&_me); /* register with parent */
	genl_register_family_with_ops(&genl_ctrl_family, &genl_ctrl_ops, 1);
}

static void
genetlinkunload(void *u __unused)
{
}

SYSINIT(genetlinkload, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, genetlinkload, NULL);
SYSINIT(genetlinkunload, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, genetlinkunload, NULL);
