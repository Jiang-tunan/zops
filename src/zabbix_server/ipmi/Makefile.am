## Process this file with automake to produce Makefile.in

noinst_LIBRARIES = libipmi.a

libipmi_a_SOURCES = \
	checks_ipmi.c \
	checks_ipmi.h \
	ipmi.c \
	ipmi.h \
	ipmi_manager.c \
	ipmi_manager.h \
	ipmi_poller.c \
	ipmi_poller.h \
	ipmi_protocol.c \
	ipmi_protocol.h \
	ipmi_discovery.h \
	ipmi_discovery.c

libipmi_a_CFLAGS = \
	$(OPENIPMI_CFLAGS) \
	$(TLS_CFLAGS)
