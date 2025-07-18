# Makefile.am - for the KSBA regression tests
#       Copyright (C) 2001, 2003 g10 Code GmbH
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

TESTS_ENVIRONMENT =

test_certs = samples/cert_dfn_pca01.der samples/cert_dfn_pca15.der \
	     samples/cert_g10code_test1.der samples/crl_testpki_testpca.der \
	     samples/authority.crt samples/betsy.crt samples/bull.crt \
             samples/ov-ocsp-server.crt samples/ov-userrev.crt \
             samples/ov-root-ca-cert.crt samples/ov-serverrev.crt \
	     samples/ov-user.crt samples/ov-server.crt  \
             samples/ov2-root-ca-cert.crt samples/ov2-ocsp-server.crt \
             samples/ov2-user.crt samples/ov2-userrev.crt \
             samples/secp256r1-sha384_cert.crt \
             samples/secp256r1-sha512_cert.crt \
             samples/secp384r1-sha512_cert.crt \
             samples/openssl-secp256r1ca.cert.crt \
             samples/ed25519-rfc8410.crt \
             samples/ed25519-ossl-1.crt \
             samples/ed448-ossl-1.crt \
             samples/user_gost.der samples/ca_gost.der


test_crls = samples/ov-test-crl.crl

test_keys = samples/ov-server.p12  samples/ov-userrev.p12 \
            samples/ov-serverrev.p12  samples/ov-user.p12

EXTRA_DIST = $(test_certs)  mkoidtbl.awk \
             samples/README \
             samples/detached-sig.cms \
	     samples/rsa-sample1.p7m  samples/rsa-sample1.p7m \
	     samples/rsa-sample1.p7s  samples/rsa-sample1.p7s \
             samples/ecdh-sample1.p7m samples/ecdh-sample1.p7m.asn \
             samples/ecdsa-sample1.p7s samples/ecdsa-sample1.p7s.asn \
             samples/gost_test.txt samples/gost_test.txt.p7s


BUILT_SOURCES = oidtranstbl.h
CLEANFILES = oidtranstbl.h

TESTS = cert-basic t-crl-parser t-dnparser t-oid t-reader t-cms-parser \
       t-der-builder t-gost-cert t-gost-cms t-gost-vko \
       test_gost_certs_verify test_gost_tk26_chains \
       test_gost_pem_russian

AM_CFLAGS = $(GPG_ERROR_CFLAGS) $(COVERAGE_CFLAGS)
if HAVE_W32_SYSTEM
AM_LDFLAGS = -no-fast-install $(COVERAGE_LDFLAGS)
else
AM_LDFLAGS = -no-install $(COVERAGE_LDFLAGS)
endif

noinst_HEADERS = t-common.h
noinst_PROGRAMS = $(TESTS) t-ocsp
LDADD = ../src/libksba.la $(GPG_ERROR_LIBS) -lgcrypt @LDADD_FOR_TESTS_KLUDGE@

t_ocsp_SOURCES = t-ocsp.c sha1.c

# Build the OID table: Note that the binary includes data from an
# another program and we may not be allowed to distribute this.  This
# ain't no problem as the programs using this generated data are not
# installed and thus not distributed.
oidtranstbl.h: Makefile mkoidtbl.awk
	set -e; f="/dev/null"; \
        for i in /etc/dumpasn1 /usr/local/bin /usr/local/share /usr/bin \
                 /usr/share ; do \
          if test -f $$i/dumpasn1.cfg; then f=$$i/dumpasn1.cfg; break; fi; \
        done; tr -d '\r' <$$f | $(AWK) -f $(srcdir)/mkoidtbl.awk >$@

LOG_COMPILER = $(VALGRIND)
