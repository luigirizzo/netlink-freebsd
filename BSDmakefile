# to be put in sys/modules/netlink/Makefile
#
# gcc honors -Wmissing-include-dirs
.if ${.CURDIR:H:T} == modules
  _MYPATH=${.CURDIR}/../../netlink
.else
  _MYPATH=${.CURDIR}
.endif

.PATH: ${_MYPATH}

KMOD =	netlink

SRCS =	bsd_nlsock.c \
	genetlink.c \
	netlink.c

CFLAGS += -I${_MYPATH}

.include <bsd.kmod.mk>
