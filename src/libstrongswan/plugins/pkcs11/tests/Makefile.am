TESTS = pkcs11_tests

check_PROGRAMS = $(TESTS)

pkcs11_tests_SOURCES = \
	tests.h tests.c \
	suites/test_uri.c

pkcs11_tests_CFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libstrongswan/tests \
	-I$(top_srcdir)/src/libstrongswan/plugins/pkcs11 \
	@COVERAGE_CFLAGS@

pkcs11_tests_LDFLAGS = @COVERAGE_LDFLAGS@
pkcs11_tests_LDADD = \
	../libpkcs11.la \
	$(top_builddir)/src/libstrongswan/tests/libtest.la \
	$(top_builddir)/src/libstrongswan/libstrongswan.la
