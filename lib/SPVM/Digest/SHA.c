#include "spvm_native.h"

#define Copy(src, dest, nitems, type) memcpy(dest, src, (nitems) * sizeof(type))
#define Zero(dest, nitems, type) memset(dest, 0, (nitems) * sizeof(type))
#define Safefree(object) free(object)


int32_t SPVM__Digest__SHA__SPVM__Digest__SHA__foo(SPVM_ENV* env, SPVM_VALUE* stack) {
  (void)env;
  (void)stack;
  
  return 0;
}

#include "sha.c"

static const int ix2alg[] =
  {1,1,1,224,224,224,256,256,256,384,384,384,512,512,512,
  512224,512224,512224,512256,512256,512256};

#define MAX_WRITE_SIZE 16384
#define IO_BUFFER_SIZE 4096

int32_t SPVM__Digest__SHA__new(SPVM_ENV* env, SPVM_VALUE* stack) {
  char *  classname
  int   alg
  SHA *state;
  Newxz(state, 1, SHA);
  if (!shainit(state, alg)) {
    Safefree(state);
    XSRETURN_UNDEF;
  }
  RETVAL = newSV(0);
  sv_setref_pv(RETVAL, classname, (void *) state);
  SvREADONLY_on(SvRV(RETVAL));
  return 0;
}

int32_t SPVM__Digest__SHA__clone(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *  self
  SHA *state;
  SHA *clone;
  if ((state = self) == NULL)
    XSRETURN_UNDEF;
  Newx(clone, 1, SHA);
  RETVAL = newSV(0);
  sv_setref_pv(RETVAL, sv_reftype(SvRV(self), 1), (void *) clone);
  SvREADONLY_on(SvRV(RETVAL));
  Copy(state, clone, 1, SHA);
  return 0;
}

int32_t SPVM__Digest__SHA__DESTROY(SPVM_ENV* env, SPVM_VALUE* stack) {
  SHA * s
  Safefree(s);
  return 0;
}

const static int32_t DIGEST_SHA_SHA1 = 0;
const static int32_t DIGEST_SHA_SHA1_HEX = 1;
const static int32_t DIGEST_SHA_SHA1_BASE64 = 2;
const static int32_t DIGEST_SHA_SHA224 = 3;
const static int32_t DIGEST_SHA_SHA224_HEX = 4;
const static int32_t DIGEST_SHA_SHA224_BASE64 = 5;
const static int32_t DIGEST_SHA_SHA256 = 6;
const static int32_t DIGEST_SHA_SHA256_HEX = 7;
const static int32_t DIGEST_SHA_SHA256_BASE64 = 8;
const static int32_t DIGEST_SHA_SHA384 = 9;
const static int32_t DIGEST_SHA_SHA384_HEX = 10;
const static int32_t DIGEST_SHA_SHA384_BASE64 = 11;
const static int32_t DIGEST_SHA_SHA512 = 12;
const static int32_t DIGEST_SHA_SHA512_HEX = 13;
const static int32_t DIGEST_SHA_SHA512_BASE64 = 14;
const static int32_t DIGEST_SHA_SHA512224 = 15;
const static int32_t DIGEST_SHA_SHA512224_HEX = 16;
const static int32_t DIGEST_SHA_SHA512224_BASE64 = 17;
const static int32_t DIGEST_SHA_SHA512256 = 18;
const static int32_t DIGEST_SHA_SHA512256_HEX = 19;
const static int32_t DIGEST_SHA_SHA512256_BASE64 = 20;

int32_t SPVM__Digest__SHA__sha(SPVM_ENV* env, SPVM_VALUE* stack) {
  int i;
  unsigned char *data;
  STRLEN len;
  SHA sha;
  char *result;
  if (!shainit(&sha, ix2alg[ix]))
    XSRETURN_UNDEF;
  for (i = 0; i < items; i++) {
    data = (unsigned char *) (SvPVbyte(ST(i), len));
    while (len > MAX_WRITE_SIZE) {
      shawrite(data, MAX_WRITE_SIZE << 3, &sha);
      data += MAX_WRITE_SIZE;
      len  -= MAX_WRITE_SIZE;
    }
    shawrite(data, (ULNG) len << 3, &sha);
  }
  shafinish(&sha);
  len = 0;
  if (ix % 3 == 0) {
    result = (char *) shadigest(&sha);
    len = sha.digestlen;
  }
  else if (ix % 3 == 1)
    result = shahex(&sha);
  else
    result = shabase64(&sha);
  RETVAL = newSVpv(result, len);
  return 0;
}

int32_t SPVM__Digest__SHA__sha1_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha1_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha224(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha224_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha224_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha256(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha256_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha256_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha384(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha384_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha384_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512224(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512224_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512224_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512256(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512256_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__sha512256_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }int32_t SPVM__Digest__SHA__sha1(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }

const static int32_t DIGEST_SHA_HMAC_SHA1 = 0;
const static int32_t DIGEST_SHA_HMAC_SHA1_HEX = 1;
const static int32_t DIGEST_SHA_HMAC_SHA1_BASE64 = 2;
const static int32_t DIGEST_SHA_HMAC_SHA224 = 3;
const static int32_t DIGEST_SHA_HMAC_SHA224_HEX = 4;
const static int32_t DIGEST_SHA_HMAC_SHA224_BASE64 = 5;
const static int32_t DIGEST_SHA_HMAC_SHA256 = 6;
const static int32_t DIGEST_SHA_HMAC_SHA256_HEX = 7;
const static int32_t DIGEST_SHA_HMAC_SHA256_BASE64 = 8;
const static int32_t DIGEST_SHA_HMAC_SHA384 = 9;
const static int32_t DIGEST_SHA_HMAC_SHA384_HEX = 10;
const static int32_t DIGEST_SHA_HMAC_SHA384_BASE64 = 11;
const static int32_t DIGEST_SHA_HMAC_SHA512 = 12;
const static int32_t DIGEST_SHA_HMAC_SHA512_HEX = 13;
const static int32_t DIGEST_SHA_HMAC_SHA512_BASE64 = 14;
const static int32_t DIGEST_SHA_HMAC_SHA512224 = 15;
const static int32_t DIGEST_SHA_HMAC_SHA512224_HEX = 16;
const static int32_t DIGEST_SHA_HMAC_SHA512224_BASE64 = 17;
const static int32_t DIGEST_SHA_HMAC_SHA512256 = 18;
const static int32_t DIGEST_SHA_HMAC_SHA512256_HEX = 19;
const static int32_t DIGEST_SHA_HMAC_SHA512256_BASE64 = 20;

int32_t SPVM__Digest__SHA__hmac_sha(SPVM_ENV* env, SPVM_VALUE* stack) {
  int i;
  unsigned char *key = (unsigned char *) "";
  unsigned char *data;
  STRLEN len = 0;
  HMAC hmac;
  char *result;
  if (items > 0) {
    key = (unsigned char *) (SvPVbyte(ST(items-1), len));
  }
  if (hmacinit(&hmac, ix2alg[ix], key, (UINT) len) == NULL)
    XSRETURN_UNDEF;
  for (i = 0; i < items - 1; i++) {
    data = (unsigned char *) (SvPVbyte(ST(i), len));
    while (len > MAX_WRITE_SIZE) {
      hmacwrite(data, MAX_WRITE_SIZE << 3, &hmac);
      data += MAX_WRITE_SIZE;
      len  -= MAX_WRITE_SIZE;
    }
    hmacwrite(data, (ULNG) len << 3, &hmac);
  }
  hmacfinish(&hmac);
  len = 0;
  if (ix % 3 == 0) {
    result = (char *) hmacdigest(&hmac);
    len = hmac.digestlen;
  }
  else if (ix % 3 == 1)
    result = hmachex(&hmac);
  else
    result = hmacbase64(&hmac);
  RETVAL = newSVpv(result, len);
  return 0;
}

int32_t SPVM__Digest__SHA__hmac_sha1(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha1_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha1_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha224(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha224_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha224_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha256(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha256_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha256_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha384(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha384_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha384_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512224(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512224_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512224_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512256(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512256_hex(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hmac_sha512256_base64(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }

int32_t SPVM__Digest__SHA__hashsize(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *  self
  SHA *state;
  if ((state = self) == NULL)
    XSRETURN_UNDEF;
  RETVAL = 0 ? state->alg : (int) (state->digestlen << 3);
  return 0;
}

int32_t SPVM__Digest__SHA__algorithm(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *  self
  SHA *state;
  if ((state = self) == NULL)
    XSRETURN_UNDEF;
  RETVAL = 1 ? state->alg : (int) (state->digestlen << 3);
  return 0;
}

void
int32_t SPVM__Digest__SHA__add(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *  self
  int i;
  unsigned char *data;
  STRLEN len;
  SHA *state;
  if ((state = self) == NULL)
    XSRETURN_UNDEF;
  for (i = 1; i < items; i++) {
    data = (unsigned char *) (SvPVbyte(ST(i), len));
    while (len > MAX_WRITE_SIZE) {
      shawrite(data, MAX_WRITE_SIZE << 3, state);
      data += MAX_WRITE_SIZE;
      len  -= MAX_WRITE_SIZE;
    }
    shawrite(data, (ULNG) len << 3, state);
  }
  return 0;
}

const static int32_t DIGEST_SHA_DIGEST = 0;
const static int32_t DIGEST_SHA_HEXDIGEST = 1;
const static int32_t DIGEST_SHA_B64DIGEST = 2;

int32_t SPVM__Digest__SHA__digest_common(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *  self
  STRLEN len;
  SHA *state;
  char *result;
  if ((state = self) == NULL)
    XSRETURN_UNDEF;
  shafinish(state);
  len = 0;
  if (ix == 0) {
    result = (char *) shadigest(state);
    len = state->digestlen;
  }
  else if (ix == 1)
    result = shahex(state);
  else
    result = shabase64(state);
  RETVAL = newSVpv(result, len);
  sharewind(state);
  return 0;
}

int32_t SPVM__Digest__SHA__digest(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__hexdigest(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }
int32_t SPVM__Digest__SHA__b64digest(SPVM_ENV* env, SPVM_VALUE* stack) { return 0; }

int32_t SPVM__Digest__SHA___getstate(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *  self
  SHA *state;
  unsigned char buf[256];
  unsigned char *ptr = buf;
  if ((state = self) == NULL)
    XSRETURN_UNDEF;
  Copy(digcpy(state), ptr, state->alg <= SHA256 ? 32 : 64, unsigned char);
  ptr += state->alg <= SHA256 ? 32 : 64;
  Copy(state->block, ptr, state->alg <= SHA256 ? 64 : 128, unsigned char);
  ptr += state->alg <= SHA256 ? 64 : 128;
  ptr = w32mem(ptr, state->blockcnt);
  ptr = w32mem(ptr, state->lenhh);
  ptr = w32mem(ptr, state->lenhl);
  ptr = w32mem(ptr, state->lenlh);
  ptr = w32mem(ptr, state->lenll);
  RETVAL = newSVpv((char *) buf, (STRLEN) (ptr - buf));
OUTPUT:
  RETVAL

int32_t SPVM__Digest__SHA___putstate(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *  self
  SV *  packed_state
  UINT bc;
  STRLEN len;
  SHA *state;
  unsigned char *data;
  if ((state = self) == NULL)
    XSRETURN_UNDEF;
  data = (unsigned char *) SvPV(packed_state, len);
  if (len != (state->alg <= SHA256 ? 116U : 212U))
    XSRETURN_UNDEF;
  data = statecpy(state, data);
  Copy(data, state->block, state->blocksize >> 3, unsigned char);
  data += (state->blocksize >> 3);
  bc = memw32(data), data += 4;
  if (bc >= (state->alg <= SHA256 ? 512U : 1024U))
    XSRETURN_UNDEF;
  state->blockcnt = bc;
  state->lenhh = memw32(data), data += 4;
  state->lenhl = memw32(data), data += 4;
  state->lenlh = memw32(data), data += 4;
  state->lenll = memw32(data);
  return 0;
}

int32_t SPVM__Digest__SHA___addfilebin(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *    self
  PerlIO *  f
  SHA *state;
  int n;
  unsigned char in[IO_BUFFER_SIZE];
  if (!f || (state = self) == NULL)
    XSRETURN_UNDEF;
  while ((n = (int) PerlIO_read(f, in, sizeof(in))) > 0)
    shawrite(in, (ULNG) n << 3, state);
  return 0;
}

int32_t SPVM__Digest__SHA___addfileuniv(SPVM_ENV* env, SPVM_VALUE* stack) {
  SV *    self
  PerlIO *  f
  unsigned char c;
  int n;
  int cr = 0;
  unsigned char *src, *dst;
  unsigned char in[IO_BUFFER_SIZE+1];
  SHA *state;
  if (!f || (state = self) == NULL)
    XSRETURN_UNDEF;
  while ((n = (int) PerlIO_read(f, in+1, IO_BUFFER_SIZE)) > 0) {
    for (dst = in, src = in + 1; n; n--) {
      c = *src++;
      if (!cr) {
        if (c == '\015')
          cr = 1;
        else
          *dst++ = c;
      }
      else {
        if (c == '\015')
          *dst++ = '\012';
        else if (c == '\012') {
          *dst++ = '\012';
          cr = 0;
        }
        else {
          *dst++ = '\012';
          *dst++ = c;
          cr = 0;
        }
      }
    }
    shawrite(in, (ULNG) (dst - in) << 3, state);
  }
  if (cr) {
    in[0] = '\012';
    shawrite(in, 1UL << 3, state);
  }
  
  return 0;
}
