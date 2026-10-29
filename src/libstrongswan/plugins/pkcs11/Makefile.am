AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

# these files are also used by the tests, we can't directly refer to them
# because of the subdirectory, which would cause distclean to fail
noinst_LTLIBRARIES = libpkcs11.la
libpkcs11_la_SOURCES = \
	pkcs11.h pkcs11_uri.h pkcs11_uri.c

if MONOLITHIC
noinst_LTLIBRARIES += libstrongswan-pkcs11.la
else
plugin_LTLIBRARIES = libstrongswan-pkcs11.la
endif

libstrongswan_pkcs11_la_LIBADD = libpkcs11.la

libstrongswan_pkcs11_la_SOURCES = \
	pkcs11_plugin.h pkcs11_plugin.c \
	pkcs11_library.h pkcs11_library.c \
	pkcs11_creds.h pkcs11_creds.c \
	pkcs11_private_key.h pkcs11_private_key.c \
	pkcs11_public_key.h pkcs11_public_key.c \
	pkcs11_hasher.h pkcs11_hasher.c \
	pkcs11_rng.h pkcs11_rng.c \
	pkcs11_dh.h pkcs11_dh.c \
	pkcs11_manager.h pkcs11_manager.c

libstrongswan_pkcs11_la_LDFLAGS = -module -avoid-version
