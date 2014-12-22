/*
 * netlink test program
 * Simple commands (command line arguments)
 *  o N		open netlink protocol n
 *  r N		read N bytes
 *  w N		write N bytes
 *  c		close
 * Starts with a GENETLINK socket open
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>	/* bzero */
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <linux/netlink.h>

/*---- start debugging macros --- luigi */
#define ND(format, ...)
#define D(format, ...)                                          \
        do {                                                    \
                struct timeval __xxts;                          \
                gettimeofday(&__xxts, NULL);                    \
                printf("%03d.%06d [%4d] %-25s " format "\n",    \
                (int)__xxts.tv_sec % 1000, (int)__xxts.tv_usec, \
                __LINE__, __FUNCTION__, ##__VA_ARGS__);         \
        } while (0)

/*
 * open the netlink socket
 */
static int
do_open(int proto)
{
	struct sockaddr_nl a = { AF_NETLINK, 0 };
	int i, s = socket(AF_NETLINK, SOCK_RAW, proto);
	if (s < 0) {
		D("open %d fails with error %d", proto, errno);
		return s;
	}
	i = connect(s, (struct sockaddr *)&a, sizeof(a));
	D("connect returns %d pid %d", i, a.nl_pid);
	return s;
}

char buf[65536];

static int
do_read(int s, int l)
{
	int ret;
	socklen_t srclen;
	struct sockaddr_nl src;
	if (s < 0 || l < 1 || l > sizeof(buf)) {
		D("wrong arguments s %d len %d", s, l);
		return -1;
	}
	srclen = sizeof(src);
	bzero(&src, sizeof(src));
	ret = recvfrom(s, buf, l, 0, (struct sockaddr *)&src, &srclen);
	D("recvfrom %d returns %d from sa_len %d family %d pid %d",
		l, ret, srclen, src.nl_len, src.nl_pid);
	return ret;
}

static int
do_write(int s, int l)
{
	struct nlmsghdr *n;

	int ret;
	if (s < 0 || l < 1 || l > sizeof(buf)) {
		D("wrong arguments s %d len %d", s, l);
		return -1;
	}

	n = (struct nlmsghdr *)buf;
	n->nlmsg_len = l;
	n->nlmsg_flags |= NLM_F_REQUEST | NLM_F_ACK;
	n->nlmsg_type = NLMSG_MIN_TYPE; // force callback
	ret = send(s, buf, l, 0);
	D("send returns %d", ret);
	return ret;
}

int
main(int argc, char *argv[])
{
	int s;
	int x = NETLINK_GENERIC;
	int i = 1; /* argument pointer */

	if (0 && argc > 1) {
		x = atoi(argv[1]);
		i++;
	}
	s = do_open(x);
	D("socket returns %d", s);

	for (; i < argc; i++) {
		switch (*argv[i]) {
		case 'r': /* read */
			do_read(s, atoi(argv[++i]));
			break;
		case 'w': /* write */
			do_write(s, atoi(argv[++i]));
			break;
		case 'c': /* close */
			close(s);
			s = -1;
			break;
		case 'o': /* open */
			s = do_open(atoi(argv[++i]));
			break;
		}
	}

	return 0;
}
