# Makefile.am - for the KSBA ASN.1 and X.509 library
#       Copyright (C) 2001, 2002, 2004, 2005, 2007 g10 Code GmbH
#
# This file is part of KSBA.
#
# KSBA is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# KSBA is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

## Process this file with automake to produce Makefile.in

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = ksba.pc

asn1_modules = tmttv2.asn cms.asn

buildtool_src = asn1-gentables.c gen-help.c gen-help.h
EXTRA_DIST = ksba.h.in ksba-config.in $(asn1_modules) ksba.m4 \
             libksba.vers libksba.def \
	     asn1-parse.c asn1-tables.c $(buildtool_src) ksba.pc.in
BUILT_SOURCES = asn1-parse.c asn1-tables.c
if USE_GPGRT_CONFIG
noinst_SCRIPTS = ksba-config
else
bin_SCRIPTS = ksba-config
endif
nodist_include_HEADERS = ksba.h
lib_LTLIBRARIES = libksba.la
noinst_PROGRAMS = ber-dump

m4datadir = $(datadir)/aclocal
m4data_DATA = ksba.m4

CLEANFILES = asn1-gentables
DISTCLEANFILES = asn1-tables.c

AM_CPPFLAGS =  -I$(top_builddir)/gl -I$(top_srcdir)/gl
AM_CFLAGS = $(GPG_ERROR_CFLAGS) $(COVERAGE_CFLAGS)


if HAVE_LD_VERSION_SCRIPT
  libksba_version_script_cmd = -Wl,--version-script=$(srcdir)/libksba.vers
else
  libksba_version_script_cmd =
endif


if HAVE_W32_SYSTEM
RCCOMPILE = $(RC) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) \
	$(libksba_la_CPPFLAGS) $(AM_CPPFLAGS) $(CPPFLAGS)
LTRCCOMPILE = $(LIBTOOL) --mode=compile --tag=RC $(RCCOMPILE)

SUFFIXES = .rc .lo

.rc.lo:
	$(LTRCCOMPILE) -i "$<" -o "$@"

ksba_res = versioninfo.lo
no_undefined = -no-undefined
export_symbols = -export-symbols $(srcdir)/libksba.def
extra_ltoptions = -XCClinker -static-libgcc

uninstall-def-file:
	-rm $(DESTDIR)$(libdir)/libksba.def

ksba_deps = $(ksba_res) libksba.def
ksbadefdir = $(libdir)
ksbadef_DATA = libksba.def

else !HAVE_W32_SYSTEM
ksba_res =
no_undefined =
export_symbols =
extra_ltoptions =
ksba_deps =
uninstall-def-file:
endif !HAVE_W32_SYSTEM


libksba_la_LDFLAGS = $(no_undefined) $(export_symbols) $(extra_ltoptions) \
      $(libksba_version_script_cmd) -version-info \
      @LIBKSBA_LT_CURRENT@:@LIBKSBA_LT_REVISION@:@LIBKSBA_LT_AGE@ \
      $(COVERAGE_LDFLAGS)
libksba_la_INCLUDES = -I$(top_srcdir)/lib
libksba_la_DEPENDENCIES = $(srcdir)/libksba.vers $(ksba_deps)
libksba_la_LIBADD = $(ksba_res) @LTLIBOBJS@ @GPG_ERROR_LIBS@


libksba_la_SOURCES = \
	ksba.h \
        visibility.c visibility.h \
	reader.c reader.h \
	writer.c writer.h \
	asn1-parse.y \
	asn1-func.c asn1-func2.c asn1-func.h asn1-constants.h \
	ber-help.c ber-help.h \
	ber-decoder.c ber-decoder.h \
	der-encoder.c der-encoder.h \
        der-builder.c der-builder.h \
        cert.c cert.h certcheck.c pkcs10-gost.c \
        cms.c cms.h cms-parser.c \
        pem.c \
        crl.c crl.h \
	certreq.c certreq.h \
	ocsp.c ocsp.h \
	keyinfo.c keyinfo.h \
	oid.c name.c dn.c time.c convert.h stringbuf.h \
	version.c util.c util.h shared.h \
	sexp-parse.h \
	asn1-tables.c

ber_dump_SOURCES = ber-dump.c \
                   ber-decoder.c ber-help.c reader.c writer.c asn1-parse.c \
                   asn1-func.c oid.c time.c util.c
ber_dump_LDADD = $(GPG_ERROR_LIBS) ../gl/libgnu.la
ber_dump_CFLAGS = $(AM_CFLAGS)

asn1-parse.c : asn1-func.h gen-help.h

asn1-gentables$(EXEEXT_FOR_BUILD): asn1-gentables.c asn1-parse.c asn1-func.c \
 gen-help.c gen-help.h
	$(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) \
	        $(CPPFLAGS_FOR_BUILD) -I$(srcdir) -DBUILD_GENTOOLS -o $@ \
		$(srcdir)/asn1-gentables.c \
                `test -f 'asn1-parse.c' || echo '$(srcdir)/'`asn1-parse.c  \
                $(srcdir)/asn1-func.c      \
                $(srcdir)/gen-help.c

asn1-tables.c : $(asn1_modules) asn1-gentables$(EXEEXT_FOR_BUILD)
	@set -e; list=""; \
	  for file in $(asn1_modules); do list="$$list $(srcdir)/$$file";done;\
	  ./asn1-gentables$(EXEEXT_FOR_BUILD) $$list > asn1-tables.c


uninstall-local: uninstall-def-file
