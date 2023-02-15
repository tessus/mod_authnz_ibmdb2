AUTOMAKE_OPTIONS = foreign
SUBDIRS = src man

EXTRA_DIST = ChangeLog INSTALL README LICENSE

install-man:
	cd man && make install-man

dist-sign:
	gpg -ba $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz

.PHONY: dist-all
dist-all: dist dist-sign

dist-all-clean:
	rm -f $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz
	rm -f $(PACKAGE_NAME)-$(PACKAGE_VERSION).tar.gz.asc
