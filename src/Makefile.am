AUTOMAKE_OPTIONS = foreign

SRC = mod_authnz_ibmdb2.c caching.c mod_authnz_ibmdb2.h caching.h sha2.h

all: module

module: $(SRC)
	$(APXS) $(MOD_CFLAGS) $(MOD_LDFLAGS) $(DB2_LDFLAGS) $(EXTRA_LDFLAGS) $(LIBS) -c mod_authnz_ibmdb2.c caching.c

install-exec-local: module
	$(APXS) -i $(ACTIVATE) mod_authnz_ibmdb2.la

EXTRA_DIST = $(SRC)

CLEANFILES = *.la *.lo *.o *.so *.slo .libs/*
DISTCLEANFILES = config.h
