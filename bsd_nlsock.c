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
 * netlink socket dispatcher for FreeBSD
 * This file is derived from net/rtsock.c
 */

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/jail.h>
#include <sys/kernel.h>
#include <sys/domain.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/rwlock.h>
#include <sys/signalvar.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/systm.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/netisr.h>
#include <net/vnet.h>
#include <net/raw_cb.h>
#include <net/route.h>

#include <net/netlink.h> /* kernel netlink definitions */

SYSCTL_NODE(_net, OID_AUTO, netlink, CTLFLAG_RD, 0, "");

static void	netlink_input(struct mbuf *m);

#include <sys/types.h>
#include <sys/syslog.h>

#define NETISR_NETLINK	15	// XXX hack, must be unused and < 16

/*
 * bsd_netlink_send_msg() is used externally, defined here because they
 * use the netisr mechanism. After the netisr_queue, the message
 * is passed to netlink_input.
 * If M_NETLINK_MULTICAST then it is dispatched as multicast
 *
 * XXX can be used by native linux code, so we may want a negative retval
 */
int
bsd_netlink_send_msg(struct socket *so, struct mbuf *m)
{
	D("m %p proto %d pid %d plen %d so %p", _P32(m),
		_MP(m), NETLINK_CB(m).portid, m->m_pkthdr.len, _P32(so));
	return netisr_queue(NETISR_NETLINK, m);
}


//----------------------------


struct netisr_handler netlink_nh = {
	.nh_name = "nlsock",
	.nh_handler = netlink_input,
	.nh_proto = NETISR_NETLINK,
	.nh_policy = NETISR_POLICY_SOURCE,
};

static int
sysctl_netlink_netisr_maxqlen(SYSCTL_HANDLER_ARGS)
{
	int error, qlimit;

	netisr_getqlimit(&netlink_nh, &qlimit);
	error = sysctl_handle_int(oidp, &qlimit, 0, req);
	if (error || !req->newptr)
		return (error);
	if (qlimit < 1)
		return (EINVAL);
	return (netisr_setqlimit(&netlink_nh, qlimit));
}

SYSCTL_PROC(_net_netlink, OID_AUTO, netisr_maxqlen, CTLTYPE_INT|CTLFLAG_RW,
    0, 0, sysctl_netlink_netisr_maxqlen, "I",
    "maximum netlink socket dispatch queue length");

static void
netlink_init(void)
{
	int tmp;

	if (TUNABLE_INT_FETCH("net.netlink.netisr_maxqlen", &tmp))
		netlink_nh.nh_qlimit = tmp;
	netisr_register(&netlink_nh);
	log(LOG_INFO, "registered netlink netisr\n");
}
SYSINIT(nlsock, SI_SUB_PROTO_DOMAIN, SI_ORDER_THIRD, netlink_init, 0);

/*
 * callback for raw_input_ext() to match a message with a socket.
 * Unicast messages must match nlmsg_pid, multicast match nlmsg_type,
 * in both cases against the socket's so->nl_src_portid
 */
static int
raw_input_netlink_cb(struct mbuf *m, struct sockproto *proto,
    struct sockaddr *src, struct rawcb *rp)
{
	struct socket *so;
	uint32_t key, so_key;
	struct nlmsghdr *msg;

	KASSERT(m != NULL, ("%s: m is NULL", __func__));
	KASSERT(proto != NULL, ("%s: proto is NULL", __func__));
	KASSERT(rp != NULL, ("%s: rp is NULL", __func__));

	so = rp->rcb_socket;
	key = so->nl_src_portid;
	msg = mtod(m, struct nlmsghdr *);

	D("m %p proto %d src_portid %d dst_portid %d ty %d so_portid %d len %d so %p",
		_P32(m), _MP(m), NETLINK_CB(m).portid,
		msg->nlmsg_pid, msg->nlmsg_type,
		key, m->m_pkthdr.len, _P32(so));
	/* return 0 on match, 1 on fail */

	so_key = (m->m_flags & M_NETLINK_MULTICAST) ? msg->nlmsg_type : msg->nlmsg_pid;
	D("%s match msg key %d =?= socket yey %d -> %d",
		(m->m_flags & M_NETLINK_MULTICAST) ? "multicast" : "unicast",
		key, so_key, so_key == key);
	return so_key == key;
}

/*
 * dispatcher for input (from kernel) netlink messages.
 */
static void
netlink_input(struct mbuf *m)
{
	/* dummy argument for raw_input_ext.
	 * messages come from the kernel so we always use the same source.
	 */
	static struct sockaddr_nl nl_src = {
		.nl_len = sizeof(nl_src),
		.nl_family = PF_NETLINK,
		.nl_pid = 0  /* comes from the kernel */ };
	struct sockproto nl_proto = {
		.sp_family = PF_NETLINK, .sp_protocol = _MP(m)};

	D("m %p proto %d src_portid %d len %d",
		_P32(m), _MP(m), NETLINK_CB(m).portid, m->m_pkthdr.len);
	_MP(m) = 0; // clear protocol in case it is not zero
	D("calling input proto");
	/* the dispatcher matches sockets using raw_input_netlink_cb(),
	 * and replicates messages as needed.
	 */
	raw_input_ext(m, &nl_proto, (struct sockaddr *)&nl_src, raw_input_netlink_cb);
}

/* (comment below from rtsock.c):
 * It really doesn't make any sense at all for this code to share much
 * with raw_usrreq.c, since its functionality is so restricted.  XXX
 */

/* called on socket creation */
static int
netlink_attach(struct socket *so, int proto, struct thread *td)
{
	struct rawcb *rp;
	int error;

	D("so %p thread %p", _P32(so), _P32(td));
	KASSERT(so->so_pcb == NULL, ("netlink_attach: so_pcb != NULL"));

	error = bsd_nl_proto_check(proto);
	if (error)
		return error;

	rp = malloc(sizeof *rp, M_PCB, M_WAITOK | M_ZERO);

	so->so_pcb = (caddr_t)rp;

	error = raw_attach(so, proto);	/* fill up the rawcb */
	if (error) { /* only if soreserve() in raw_attach() fails */
		so->so_pcb = NULL;
		free(rp, M_PCB);
		return error;
	}
	so->so_options |= SO_USELOOPBACK;
	return 0;
}

/*
 * XXX do we need bind for this socket ?
 */
static int
netlink_bind(struct socket *so, struct sockaddr *nam, struct thread *td)
{

	D("");
	return EINVAL;
}

/*
 * We need a new src_portid when a socket is bound. Since we do not
 * implement bind(), we do it here.
 * At the moment we just cycle through a 2^32 counter,
 * XXX this should be fixed later to make sure it is unique.
 *
 * Also so_pcb is only a rawcb so we do not have room to store the
 * dst_portid and src_pid so we store them into socket fields.
 * XXX should make sure this is unique.
 *
 * so->so_pcb is a pointer to internal state.
 */
static int
netlink_connect(struct socket *so, struct sockaddr *nam, struct thread *td)
{
	static uint32_t netlinkpids = 1; // XXX see above
	struct sockaddr_nl *nla = (struct sockaddr_nl *)nam;
	/* nam->sa_len is updated with the actual length in the syscall */

	if (nla->nl_len != sizeof(*nla))
		return EINVAL;

	so->nl_src_portid = atomic_fetchadd_32(&netlinkpids, 1);
	so->nl_dst_portid = nla->nl_pid; /* not used */

	D("src_portid %d dst_portid %d", so->nl_src_portid, so->nl_dst_portid);
	soisconnected(so);

	return 0;
}


static void
netlink_detach(struct socket *so)
{
	struct rawcb *rp = sotorawcb(so);
	(void)rp;

	D("so %p rp %p", _P32(so), _P32(rp));
	KASSERT(rp != NULL, ("netlink_detach: rp == NULL"));

	raw_usrreqs.pru_detach(so);	// raw_detach(rp);
}

static int
netlink_disconnect(struct socket *so)
{

	return ENOTCONN; // XXX why ?
}


static int
netlink_peeraddr(struct socket *so, struct sockaddr **nam)
{

	D("");
	return ENOTCONN;
}

/*
 * netlink_output is varargs on newer FreeBSD
 */
#if __FreeBSD_version > 1100028
#define NLO_EXTRA , ...
#else
#define NLO_EXTRA
#endif /* newer freebsd */

static int
netlink_output(struct mbuf *m, struct socket *so NLO_EXTRA );

/*
 * send*() from userspace to a netlink socket
 */
static int
netlink_send(struct socket *so, int flags, struct mbuf *m, struct sockaddr *nam,
	 struct mbuf *control, struct thread *td)
{
	return netlink_output(m, so);
}

static int
netlink_shutdown(struct socket *so)
{

	D("");
	return (raw_usrreqs.pru_shutdown(so));
}

static int
netlink_sockaddr(struct socket *so, struct sockaddr **nam)
{
	struct sockaddr_nl *snl;

	snl = malloc(sizeof *snl, M_SONAME, M_WAITOK | M_ZERO);
	D("socket %p", so);
	/* TODO: set other fields */
	snl->nl_pid = so->so_fibnum;
	snl->nl_len = sizeof(*snl);
	snl->nl_family = AF_NETLINK;

	*nam = (struct sockaddr *) snl;

	return 0;
}

static struct pr_usrreqs netlink_usrreqs = {
	.pru_abort =		soisdisconnected,
	/* pru_accept is EOPNOTSUPP */
	.pru_attach =		netlink_attach,
	.pru_bind =		netlink_bind,	// EINVAL
	.pru_connect =		netlink_connect,	// EINVAL
	/* pru_connect2 is EOPNOTSUPP */
	/* pru_control is EOPNOTSUPP */
	.pru_detach =		netlink_detach,
	.pru_disconnect =	netlink_disconnect,
	/* pru_listen is EOPNOTSUPP */
	.pru_peeraddr =		netlink_peeraddr,	// ENOTCONN
	/* pru_rcvd is EOPNOTSUPP */
	/* pru_rcvoob is EOPNOTSUPP */
	.pru_send =		netlink_send,
	/* pru_sense is NULL */
	.pru_shutdown =		netlink_shutdown,
	/* pru_flush ? */
	.pru_sockaddr =		netlink_sockaddr,
	/* pru_sosend ? */
	/* pru_soreceive ? */
	/* pru_sopoll ? */
	/* pru_sosetlabel ? */
	.pru_close =		soisdisconnected
	/* pru_bindat ? */
	/* pru_connectat */
};


static int
netlink_output(struct mbuf *m, struct socket *so NLO_EXTRA )
{
	int ret;
	struct rawcb *rp;
	int proto;

	if (m == NULL || ((m->m_len < sizeof(long)) &&
		       (m = m_pullup(m, sizeof(long))) == NULL))
		return (ENOBUFS);
	rp = sotorawcb(so);
	proto = rp->rcb_proto.sp_protocol;
	/* save protocol and portid into the mbuf */
	_MP(m) = proto;
	NETLINK_CB(m).portid = so->nl_src_portid;
	D("so %p m %p m_portid %d m_proto %d plen %d len %d",
		_P32(so), _P32(m), NETLINK_CB(m).portid, _MP(m),
		m->m_pkthdr.len, m->m_len);
	ret = netlink_receive_packet(m, so, proto);
	D("returns %d", ret);
	return ret;
}

/* Accept options from setsockoptions.
 * It is necessary to tag a multicast socket
 * the userspace uses setsockopt(sock, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP...)
 */
static int
netlink_ctloutput(struct socket *so, struct sockopt *sopt)
{
	uint32_t mgrp;

	D("dir 0x%x name 0x%x", sopt->sopt_dir, sopt->sopt_name);
	switch (sopt->sopt_dir) {
	case SOPT_SET:
		switch (sopt->sopt_name) {
		case NETLINK_ADD_MEMBERSHIP:
			sooptcopyin(sopt, &mgrp, sizeof mgrp, sizeof mgrp);

			D("/* Tag the socket as netlink multicast */");
			so->so_fibnum = mgrp;

			return 0;
		default:
			D("bad option name 0x%x", sopt->sopt_name);
			return 0; // XXX hack EINVAL;
		}
	default:
		D("bad option");
		return ENOPROTOOPT;
	}
}

static int
netlink_modevent(struct module *inModule, int inEvent, void* inArg)
{
	int ret = 0;

	switch(inEvent) {
	case MOD_LOAD:
		break;

	case MOD_UNLOAD:
		break;

	default:
		ret = EOPNOTSUPP;
		break;
	}

	return ret;
}

static moduledata_t netlink_mod = {
	"netlink",
	netlink_modevent,
	NULL
};

DECLARE_MODULE(netlink_disc, netlink_mod, SI_SUB_PSEUDO, SI_ORDER_ANY);
MODULE_VERSION(netlink, 1);


/*
 * Definitions of protocols supported in the NETLINK domain.
 */

static struct domain netlinkdomain; /* cross linked to netlinksw */

/*
 * XXX not sure how much of the protosw we are using
 */
static struct protosw netlinksw[] = {
{
	.pr_type =		SOCK_RAW,
	.pr_domain =		&netlinkdomain,
	.pr_flags =		PR_ATOMIC|PR_ADDR,
	.pr_output =		netlink_output,
	.pr_ctlinput =		raw_ctlinput,
	.pr_ctloutput =         netlink_ctloutput,
	.pr_init =		raw_init,
	.pr_usrreqs =		&netlink_usrreqs
}
};

static struct domain netlinkdomain = {
	.dom_family =		PF_NETLINK,
	.dom_name =		 "netlink",
	.dom_protosw =		netlinksw,
	.dom_protoswNPROTOSW =	&netlinksw[sizeof(netlinksw)/sizeof(netlinksw[0])]
};

VNET_DOMAIN_SET(netlink);
