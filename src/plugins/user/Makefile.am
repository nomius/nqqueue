plugindir = $(libdir)/nqqueue/plugins/user

plugin_LTLIBRARIES =

general_CFLAGS = -I$(top_srcdir)/src
general_LDFLAGS = -module -avoid-version

if BUILD_DSPAM
plugin_LTLIBRARIES += dspam.la
dspam_la_CFLAGS = $(general_CFLAGS)
dspam_la_LDFLAGS = $(general_LDFLAGS)
dspam_la_SOURCES = dspam.c
endif

if BUILD_SPAMASSASSIN
plugin_LTLIBRARIES += spamassassin.la
spamassassin_la_CFLAGS = $(general_CFLAGS)
spamassassin_la_LDFLAGS = $(general_LDFLAGS)
spamassassin_la_SOURCES = spamassassin.c
endif

if BUILD_QUARANTINE
plugin_LTLIBRARIES += quarantine.la
quarantine_la_CFLAGS = $(general_CFLAGS) -DVQUAD_BINARY=\"$(libexecdir)/vquad\"
quarantine_la_LDFLAGS = $(general_LDFLAGS)
quarantine_la_SOURCES = quarantine.c
if BUILD_VQUAD
libexec_PROGRAMS = vquad
vquad_CFLAGS  = $(VPOPMAIL_CFLAGS) -DHAVE_VPOPMAIL
vquad_LDFLAGS = -lcrypt $(VPOPMAIL_LIBS)
end_vquad:
	@test `id -u` -eq 0 && chown root:$(NOFILESGID) $(DESTDIR)$(libexecdir)/vquad && chmod 4700 $(DESTDIR)$(libexecdir)/vquad || echo -e "\n..........................................................................\n.                                                                        .\n. Remember to excecute chmod u+s $(DESTDIR)$(libexec)/vquad as root .\n.                                                                        .\n..........................................................................\n"
else
end_vquad:
endif
end_quarantine:
	mkdir -p $(DESTDIR)$(NQQUEUE_HOME)/quarantine
	chown qmaild:nofiles $(DESTDIR)$(NQQUEUE_HOME)/quarantine
	chmod 4750 $(DESTDIR)$(NQQUEUE_HOME)/quarantine
else
end_vquad:
end_quarantine:
endif

install-exec-hook: end_quarantine end_vquad
