## Process this file with automake to produce Makefile.in

bin_PROGRAMS = zops_sender

zops_sender_SOURCES = \
	zabbix_sender.c

zops_sender_LDADD = \
	$(top_builddir)/src/libs/zbxjson/libzbxjson.a \
	$(top_builddir)/src/libs/zbxalgo/libzbxalgo.a \
	$(top_builddir)/src/libs/zbxregexp/libzbxregexp.a \
	$(top_builddir)/src/libs/zbxcommshigh/libzbxcommshigh.a \
	$(top_builddir)/src/libs/zbxcomms/libzbxcomms.a \
	$(top_builddir)/src/libs/zbxcrypto/libzbxcrypto.a \
	$(top_builddir)/src/libs/zbxxml/libzbxxml.a \
	$(top_builddir)/src/libs/zbxvariant/libzbxvariant.a \
	$(top_builddir)/src/libs/zbxcommon/libzbxcommon.a \
	$(top_builddir)/src/libs/zbxgetopt/libzbxgetopt.a \
	$(top_builddir)/src/libs/zbxlog/libzbxlog.a \
	$(top_builddir)/src/libs/zbxthreads/libzbxthreads.a \
	$(top_builddir)/src/libs/zbxmutexs/libzbxmutexs.a \
	$(top_builddir)/src/libs/zbxprof/libzbxprof.a \
	$(top_builddir)/src/libs/zbxnix/libzbxnix.a \
	$(top_builddir)/src/libs/zbxhash/libzbxhash.a \
	$(top_builddir)/src/libs/zbxconf/libzbxconf.a \
	$(top_builddir)/src/libs/zbxcompress/libzbxcompress.a \
	$(top_builddir)/src/libs/zbxnum/libzbxnum.a \
	$(top_builddir)/src/libs/zbxstr/libzbxstr.a \
	$(top_builddir)/src/libs/zbxtime/libzbxtime.a \
	$(top_builddir)/src/libs/zbxip/libzbxip.a \
	$(SENDER_LIBS)

zops_sender_LDFLAGS = $(SENDER_LDFLAGS)

zops_sender_CFLAGS = $(TLS_CFLAGS)

EXTRA_DIST = win32
