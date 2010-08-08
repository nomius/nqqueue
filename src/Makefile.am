sbin_PROGRAMS = NQqueue

NQqueue_SOURCES = general.c cfg.c delivery.c nqqueue.c
AM_CFLAGS = -rdynamic -DPLUGINS_LOCATION=\"$(libdir)/nqqueue/plugins\"
include_HEADERS = nqqueue.h

SUBDIRS = plugins

install-exec-hook:
	mkdir -p $(DESTDIR)$(NQQUEUE_HOME)/queue
	chown $(QMAILDUID):$(NOFILESGID) $(DESTDIR)$(NQQUEUE_HOME)/queue

