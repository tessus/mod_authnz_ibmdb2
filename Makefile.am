AUTOMAKE_OPTIONS = foreign
SUBDIRS = src man

EXTRA_DIST = ChangeLog INSTALL README

install-man:
	cd man && make install-man

dist-sign:
	gpg -ba $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz
