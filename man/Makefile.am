man8_MANS = apr_crypt.8 apr_md5.8 apr_sha1.8 apr_sha256.8 bcrypt.8 db2-hash-routines.8 mod_authnz_ibmdb2.8 php_md5.8 sha256.8 sha512.8 sha1_hex.8 sha256_hex.8 validate_pw.8

html: html-man

html-man: man-html

man-html:
	./create_html.sh

if NO_MAN_PAGES
install:
endif

EXTRA_DIST = $(man8_MANS) create_html.sh

CLEANFILES = html/*
