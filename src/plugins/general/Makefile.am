plugindir = $(libdir)/nqqueue/plugins/general

plugin_LTLIBRARIES =

general_CFLAGS = -I$(top_srcdir)/src
general_LDFLAGS = -module -avoid-version

if BUILD_BLACK
plugin_LTLIBRARIES += black.la
black_la_CFLAGS = $(general_CFLAGS)
black_la_LDFLAGS = $(general_LDFLAGS)
black_la_SOURCES = black.c
endif

if BUILD_CLAMAV
plugin_LTLIBRARIES += clamav.la
clamav_la_CFLAGS = $(general_CFLAGS)
clamav_la_LDFLAGS = $(general_LDFLAGS)
clamav_la_SOURCES = clamav.c
endif
