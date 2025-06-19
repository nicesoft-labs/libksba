#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "../src/ksba.h"
#define KSBA_TESTING
#define _KSBA_VISIBILITY_DEFAULT
#include "../src/cms.h"
#include "../src/keyinfo.h"
#include "t-common.h"

static int verbose;

static unsigned char *hex2bin(const char *hex, size_t *r_len)
{
  size_t len = strlen(hex)/2;
  unsigned char *buf = xmalloc(len);
  size_t i; char tmp[3]; tmp[2] = 0;
  for(i=0;i<len;i++) { tmp[0]=hex[i*2]; tmp[1]=hex[i*2+1]; buf[i]=strtoul(tmp,NULL,16); }
  *r_len = len; return buf;
}

static void test_algid(void)
{
  const char *hex_no="300806062a8503020215";
  const char *hex_oct="30110609608648016503040102040401020304";
  const char *hex_seq="301906062a8503020215300f04040506070806072a850302021f01";
  const char *hex_bad="300206012a"; /* truncated */
  size_t len; unsigned char *der; gpg_error_t err; char *oid;
  struct algorithm_param_s *parm; int count; size_t nread;

  der = hex2bin(hex_no,&len);
  err = _ksba_parse_algorithm_identifier2(der,len,&nread,&oid,&parm,&count);
  assert(!err && !count && !parm);
  assert(!strcmp(oid,"1.2.643.2.2.21"));
  xfree(oid); free(der);

  der = hex2bin(hex_oct,&len);
  err = _ksba_parse_algorithm_identifier2(der,len,&nread,&oid,&parm,&count);
  assert(!err && count==1);
  assert(!strcmp(oid,"2.16.840.1.101.3.4.1.2"));
  assert(parm[0].tag==TYPE_OCTET_STRING && parm[0].length==4);
  release_algorithm_params(parm,count); xfree(oid); free(der);

  der = hex2bin(hex_seq,&len);
  err = _ksba_parse_algorithm_identifier2(der,len,&nread,&oid,&parm,&count);
  assert(!err && count==2);
  assert(!strcmp(oid,"1.2.643.2.2.21"));
  assert(parm[0].tag==TYPE_OCTET_STRING && parm[0].length==4);
  assert(parm[1].tag==TYPE_OBJECT_ID);
  release_algorithm_params(parm,count); xfree(oid); free(der);

  der = hex2bin(hex_bad,&len);
  err = _ksba_parse_algorithm_identifier2(der,len,&nread,&oid,&parm,&count);
  assert(err);
  free(der);
}

static void test_release(void)
{
  struct algorithm_param_s *p = xmalloc(2*sizeof *p);
  p[0].value = xmalloc(1); p[0].length=1;
  p[1].value = xmalloc(2); p[1].length=2;
  release_algorithm_params(p,2);
}

static int dummy_writer_cb(void *cb,const void *buf,size_t len){ (void)cb;(void)buf;(void)len; return 0; }

static void test_eci(void)
{
  const char *hex_aes="302406092a864886f70d01070130110609608648016503040102040401020304800461626364";
  const char *hex_gost="302c06092a864886f70d010701301906062a8503020215300f0404aabbccdd06072a850302021f0180047a7a7a7a";
  const char *hex_unk="301d06092a864886f70d010701300c06042a03040504041122334480027878";
  const char *hexes[]={hex_aes,hex_gost,hex_unk};
  const char *oids[]={"2.16.840.1.101.3.4.1.2","1.2.643.2.2.21","1.2.3.4.5"};
  for(int i=0;i<3;i++){
    size_t len; unsigned char *buf=hex2bin(hexes[i],&len);
    ksba_reader_t r; gpg_error_t err; unsigned long clen; int cndef; char *coid; char *aoid; struct algorithm_param_s *parm; int count; int ptype; int has;
    err=ksba_reader_new(&r); assert(!err);
    err=ksba_reader_set_mem(r,buf,len); assert(!err);
    err=_ksba_test_parse_encrypted_content_info(r,&clen,&cndef,&coid,&aoid,&parm,&count,&ptype,&has);
    assert(!err);
    assert(!strcmp(coid,"1.2.840.113549.1.7.1"));
    assert(!strcmp(aoid,oids[i]));
    release_algorithm_params(parm,count); xfree(coid); xfree(aoid); ksba_reader_release(r); free(buf);
  }
}

static void test_integration(void)
{
  const char *hex_cms="304206092a864886f70d010703a03530330201003100302c06092a864886f70d010701301906062a8503020215300f0404aabbccdd06072a850302021f01800464617461";
  size_t len; unsigned char *buf = hex2bin(hex_cms,&len);
  ksba_reader_t r; ksba_writer_t w; ksba_cms_t cms; gpg_error_t err; ksba_stop_reason_t sr;
  err=ksba_reader_new(&r); assert(!err);
  err=ksba_reader_set_mem(r,buf,len); assert(!err);
  err=ksba_writer_new(&w); assert(!err);
  err=ksba_writer_set_cb(w,dummy_writer_cb,NULL); assert(!err);
  err=ksba_cms_new(&cms); assert(!err);
  err=ksba_cms_set_reader_writer(cms,r,w); assert(!err);
  do { err=ksba_cms_parse(cms,&sr); assert(!err); } while(sr!=KSBA_SR_READY);
  const char *oid = ksba_cms_get_content_oid(cms,2);
  const char *sbox = ksba_cms_get_content_oid(cms,3);
  assert(oid && !strcmp(oid,"1.2.643.2.2.21"));
  assert(sbox && !strcmp(sbox,"1.2.643.2.2.31.1"));
  unsigned char iv[8]; size_t ivlen; err=ksba_cms_get_content_enc_iv(cms,iv,sizeof(iv),&ivlen); assert(!err && ivlen==4);
  ksba_cms_release(cms); ksba_reader_release(r); ksba_writer_release(w); free(buf);
}

int main(int argc,char **argv){
  (void)argc; (void)argv;
  test_algid();
  test_release();
  test_eci();
  test_integration();
  if (verbose) printf("All tests passed\n");
  return 0;
}
