## Process this file with automake to produce Makefile.in

noinst_LIBRARIES = libzbxdiscoverer.a

libzbxdiscoverer_a_SOURCES = \
	discoverer_comm.c \
	discoverer_comm.h \
	user_discoverer.c \
	user_discoverer.h \
	discoverer.c \
	discoverer.h \
	discoverer_manager.c \
	discoverer_manager.h \
	discoverer_protocol.c \
	discoverer_protocol.h \
	discoverer_single.c \
	discoverer_single.h \
	discoverer_vmware.c \
	discoverer_vmware.h \
	discoverer_nutanix.c \
	discoverer_nutanix.h \
	discoverer_kubernetes.c \
	discoverer_kubernetes.h

libzbxdiscoverer_a_CFLAGS = \
	$(TLS_CFLAGS)
