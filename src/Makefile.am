include $(top_srcdir)/common.mk

lib_LTLIBRARIES = libaiwendb.la

libaiwendb_la_SOURCES = aiwendb.c aiwendb-compat-util.h \
	data-pool.c data-pool.h
libaiwendb_la_LDFLAGS = -version-info 0:7:0 -export-symbols-regex '^AWDB_.*'
include_HEADERS = $(top_srcdir)/include/aiwendb.h

pkgconfig_DATA = libaiwendb.pc

TESTS = test-data-pool

check_PROGRAMS = test-data-pool

test_data_pool_SOURCES = data-pool.c data-pool.h
test_data_pool_CPPFLAGS = $(AM_CPPFLAGS) -I$(top_srcdir)/t -DTEST_DATA_POOL
test_data_pool_LDADD = $(top_srcdir)/t/libmmdbtest.la \
	$(top_srcdir)/t/libtap/libtap.a

$(top_srcdir)/t/libmmdbtest.la:
	$(MAKE) -C $(top_srcdir)/t libmmdbtest.la

$(top_srcdir)/t/libtap/libtap.a:
	$(MAKE) -C $(top_srcdir)/t/libtap libtap.a
