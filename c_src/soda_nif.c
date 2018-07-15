#include "erl_nif.h"
#include <string.h>
#include <limits.h>
#include <stdint.h>
#include <sodium.h>

#ifdef UNUSED
#elif defined(__GNUC__)
# define UNUSED(x) UNUSED_ ## x __attribute__((unused))
#elif defined(__LCLINT__)
# define UNUSED(x) /*@unused@*/ x
#else
# define UNUSED(x) x
#endif

#define ATOM_OK "ok"
#define ATOM_UNKNOWN "unknown"
#define ATOM_ERROR "error"
#define ATOM_TRUE "true"
#define ATOM_FALSE "false"
#define ATOM_OOM "out_of_memory"
#define ATOM_ENCRYPT_FAIL "encrypt_failed"
#define ATOM_DECRYPT_FAIL "decrypt_failed"
#define ATOM_BAD_SIZE "bad_size"
#define ATOM_BAD_SALT_SIZE "bad_salt_size"
#define ATOM_BAD_KEY_SIZE "bad_key_size"
#define ATOM_BAD_NONCE_SIZE "bad_nonce_size"


#define MK_ATOM(env, str) enif_make_atom(env, str)
#define MK_BIN(env, bin) enif_make_binary(env, bin)
#define BADARG(env) enif_make_badarg(env)
#define GET_BIN(env, term, bin) enif_inspect_binary(env, term, bin)
#define MK_UINT(env, val, size) enif_get_uint(env, val, size)
#define ALLOC_BIN(size, pk) enif_alloc_binary(size, pk)
#define ERROR(env, atom_arg) enif_make_tuple2(env, MK_ATOM(env, ATOM_ERROR), MK_ATOM(env, atom_arg))
#define OOM_ERROR(env) ERROR(env, ATOM_OOM)
#define ENCRYPT_FAILED_ERROR(env) ERROR(env, ATOM_ENCRYPT_FAIL)
#define DECRYPT_FAILED_ERROR(env) ERROR(env, ATOM_DECRYPT_FAIL)
#define BAD_SALT_SIZE_ERROR(env) ERROR(env, ATOM_BAD_SALT_SIZE)
#define BAD_KEY_SIZE_ERROR(env) ERROR(env, ATOM_BAD_KEY_SIZE)
#define BAD_NONCE_SIZE_ERROR(env) ERROR(env, ATOM_BAD_NONCE_SIZE)
#define OK_TUPLE(env, ret) enif_make_tuple2(env, MK_ATOM(env, ATOM_OK), ret)
#define RAISE(env, atom_arg) enif_raise_exception(env, MK_ATOM(env, atom_arg))
#define FREE(r) enif_free(r)
#define FREE_BIN(bin) enif_release_binary(bin)
#define IS_NUM(env, arg) enif_is_number(env, arg)

/* It is our responsiblity to free these */
static int zero_terminate(ErlNifBinary bin, char **buf) {
  *buf = enif_alloc(bin.size + 1);
  if (!*buf) { 
    return 0;
  }
  memmove(*buf, bin.data, bin.size);
  *(*buf + bin.size) = 0;
  return 1;
}

static int load(ErlNifEnv *UNUSED(env), void **UNUSED(priv), ERL_NIF_TERM UNUSED(info))
{
  return sodium_init() == -1 ? 1 : 0;
}

static int
upgrade(ErlNifEnv *UNUSED(env), void **UNUSED(priv), void **UNUSED(old_priv), ERL_NIF_TERM UNUSED(info))
{
  return 0;
}

static void unload(ErlNifEnv *UNUSED(env), void *UNUSED(priv))
{
  return;
}

/* BEGIN */

static ERL_NIF_TERM
enif_crypto_randombytes(ErlNifEnv * env, int argc, ERL_NIF_TERM const argv[])
{
  unsigned int size;
  ErlNifBinary result;

  if ((1 != argc)
      || !IS_NUM(env, argv[0])
      || (!MK_UINT(env, argv[0], &size)))
  {
    return BADARG(env);
  }

  if (SIZE_MAX <= (unsigned long)size) {
    return RAISE(env, ATOM_BAD_SIZE);
  }

  if (1 != ALLOC_BIN(size, &result)) {
    FREE_BIN(&result);
    return OOM_ERROR(env);
  }

  randombytes(result.data, result.size);

  if (result.size != size) {
    FREE_BIN(&result);
    return RAISE(env, ATOM_UNKNOWN);
  }

  return MK_BIN(env, &result);
}

static ERL_NIF_TERM
enif_crypto_pwhash(ErlNifEnv * env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary h, p, s;

  if ((2 != argc)
      || (!GET_BIN(env, argv[0], &p))
      || (!GET_BIN(env, argv[1], &s)))
  {
    return BADARG(env);
  }

  if (s.size != crypto_pwhash_SALTBYTES) {
    return ERROR(env, ATOM_BAD_SALT_SIZE);
  }

  if (!ALLOC_BIN(crypto_box_SEEDBYTES, &h)) {
    FREE_BIN(&h);
    return OOM_ERROR(env);
  }

  if (0 != crypto_pwhash(
          h.data
        , h.size
        , (char *)p.data
        , p.size
        , s.data
        , crypto_pwhash_OPSLIMIT_INTERACTIVE
        , crypto_pwhash_MEMLIMIT_INTERACTIVE
        , crypto_pwhash_ALG_DEFAULT))
  {
    FREE_BIN(&h);
    return OOM_ERROR(env);
  }

  return OK_TUPLE(env, MK_BIN(env, &h));
}

static ERL_NIF_TERM
enif_crypto_pwhash_str(ErlNifEnv * env, int argc, ERL_NIF_TERM const argv[])
{
  ErlNifBinary h, p;

  if ((1 != argc) || (!GET_BIN(env, argv[0], &p))) {
    return BADARG(env);
  }

  /* zero-byte terminate ... this must be enif_free()d! */
  char *passwd;
  if (!zero_terminate(p, &passwd)) { 
   return BADARG(env);  
  }

  if (!ALLOC_BIN(crypto_pwhash_STRBYTES, &h)) {
    FREE_BIN(&h);
    return OOM_ERROR(env);
  }

  int res = crypto_pwhash_str(
          (char *)h.data
        , passwd
        , p.size
        , crypto_pwhash_OPSLIMIT_INTERACTIVE
        , crypto_pwhash_MEMLIMIT_INTERACTIVE);

  FREE(passwd);

  if (res !=0 ) { 
    FREE_BIN(&h);
    return OOM_ERROR(env);
  } else { 
    return OK_TUPLE(env, MK_BIN(env, &h));
  }
}

static ERL_NIF_TERM
enif_crypto_pwhash_str_verify(ErlNifEnv * env, int argc,
            ERL_NIF_TERM const argv[])
{
  ErlNifBinary h, p;

 if ((2 != argc)
      || (!GET_BIN(env, argv[0], &h))
      || (!GET_BIN(env, argv[1], &p))) {
    return BADARG(env);
  }

  /* zero-byte terminate ... these must be enif_free()d! */
  char *hash;
  char *passwd;
  if (!zero_terminate(h, &hash) || !zero_terminate(p, &passwd)) { 
    return BADARG(env);
  }

  ERL_NIF_TERM retVal = MK_ATOM(env, ATOM_TRUE);
  if (0 != crypto_pwhash_str_verify(hash, passwd, p.size)) {
    retVal = MK_ATOM(env, ATOM_FALSE);
  }

  FREE(hash);
  FREE(passwd);
  return retVal;
}

static
ERL_NIF_TERM enif_crypto_sign_keypair(ErlNifEnv * env, int argc,
              ERL_NIF_TERM const UNUSED(argv[]))
{
  ErlNifBinary pk, sk;

  if (0 != argc) {
    return BADARG(env);
  }

  if (!ALLOC_BIN(crypto_sign_PUBLICKEYBYTES, &pk)
      || !ALLOC_BIN(crypto_sign_SECRETKEYBYTES, &sk))
  {
    FREE_BIN(&pk);
    FREE_BIN(&sk);
    return OOM_ERROR(env);
  }

  crypto_sign_keypair(pk.data, sk.data);

  return enif_make_tuple2(env, MK_BIN(env, &pk), MK_BIN(env, &sk));
}

static
ERL_NIF_TERM enif_crypto_sign_detached(ErlNifEnv * env, int argc,
               ERL_NIF_TERM const argv[])
{
  ErlNifBinary m, sk, sig;
  unsigned long long siglen;

  if ((2 != argc)
      || (!GET_BIN(env, argv[0], &m))
      || (!enif_inspect_binary(env, argv[1], &sk)))
  {
    return BADARG(env);
  }

  if (sk.size != crypto_sign_SECRETKEYBYTES) {
    return BADARG(env);
  }

  if (!ALLOC_BIN(crypto_sign_BYTES, &sig)) {
    FREE_BIN(&sig);
    return OOM_ERROR(env);
  }

  crypto_sign_detached(sig.data, &siglen, m.data, m.size, sk.data);

  return MK_BIN(env, &sig);
}

static
ERL_NIF_TERM enif_crypto_sign_verify_detached(ErlNifEnv * env, int argc,
                ERL_NIF_TERM const argv[])
{
  ErlNifBinary m, sig, pk;

  if ((3 != argc)
      || (!GET_BIN(env, argv[0], &sig))
      || (!GET_BIN(env, argv[1], &m))
      || (!GET_BIN(env, argv[2], &pk)))
  {
    return BADARG(env);
  }

  if (pk.size != crypto_sign_PUBLICKEYBYTES) {
    return BADARG(env);
  }

  if (0 == crypto_sign_verify_detached(sig.data, m.data, m.size, pk.data)) {
    return MK_ATOM(env, ATOM_TRUE);
  }

  return MK_ATOM(env, ATOM_FALSE);
}

static ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_ietf_keygen(
    ErlNifEnv * env
    , int argc
    , ERL_NIF_TERM const UNUSED(argv[]))
{

  ErlNifBinary key;
  if (0 != argc) {
    return BADARG(env);
  }

  if (!ALLOC_BIN(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, &key)) { 
    FREE_BIN(&key);
    return OOM_ERROR(env);  
  }

  crypto_aead_xchacha20poly1305_ietf_keygen(key.data);
  return MK_BIN(env, &key);
}

static ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_ietf_encrypt(
    ErlNifEnv * env
    , int argc
    , ERL_NIF_TERM const argv[])
{
  ErlNifBinary msg, ad, nonce, key, ct;
  if ((4 != argc) || (!GET_BIN(env, argv[0], &msg))
      || (!GET_BIN(env, argv[1], &ad))
      || (!GET_BIN(env, argv[2], &nonce))
      || (!GET_BIN(env, argv[3], &key)))
  {
    return BADARG(env);
  }

  if (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) 
  { 
    return RAISE(env, ATOM_BAD_KEY_SIZE);
  }

  if (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  {
    return RAISE(env, ATOM_BAD_NONCE_SIZE);
  }

  if (!ALLOC_BIN(msg.size + crypto_aead_xchacha20poly1305_ietf_ABYTES, &ct)) {
    FREE_BIN(&ct);
    return OOM_ERROR(env);
  }

  if (0 != crypto_aead_xchacha20poly1305_ietf_encrypt(
        ct.data
        , NULL
        , msg.data
        , msg.size
        , ad.data
        , ad.size
        , NULL
        , nonce.data
        , key.data))
  {
    FREE_BIN(&ct);
    return ENCRYPT_FAILED_ERROR(env);
  }

  return MK_BIN(env, &ct);
}

static ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_ietf_decrypt(ErlNifEnv * env, int argc,
            ERL_NIF_TERM const argv[])
{
  ErlNifBinary ct, ad, nonce, key, msg;

  if ((4 != argc)
      || (!GET_BIN(env, argv[0], &ct))
      || (!GET_BIN(env, argv[1], &ad))
      || (!GET_BIN(env, argv[2], &nonce))
      || (!GET_BIN(env, argv[3], &key))
    ) 
  {
    return BADARG(env);
  }
  
  if (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) 
  { 
    return RAISE(env, ATOM_BAD_KEY_SIZE);
  }

  if (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
  {
    return RAISE(env, ATOM_BAD_NONCE_SIZE);
  }

  if (!ALLOC_BIN(ct.size - crypto_aead_xchacha20poly1305_ietf_ABYTES, &msg))
  {
    FREE_BIN(&msg);
    return OOM_ERROR(env);
  }

  if (0 > crypto_aead_xchacha20poly1305_ietf_decrypt(
        msg.data
      , NULL
      , NULL
      , ct.data
      , ct.size
      , ad.data
      , ad.size
      , nonce.data
      , key.data))
  {
    FREE_BIN(&msg);
    return DECRYPT_FAILED_ERROR(env);
  }

  return MK_BIN(env, &msg);
}

static ErlNifFunc nif_funcs[] = {
  {
   "crypto_randombytes", 1,
   enif_crypto_randombytes, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {
   "crypto_pwhash", 2,
   enif_crypto_pwhash, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {
   "crypto_pwhash_str", 1,
   enif_crypto_pwhash_str, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {
   "crypto_pwhash_str_verify", 2,
   enif_crypto_pwhash_str_verify, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {
   "crypto_sign_keypair", 0,
   enif_crypto_sign_keypair, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {
   "crypto_sign_detached", 2,
   enif_crypto_sign_detached, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {
   "crypto_sign_verify_detached", 3,
   enif_crypto_sign_verify_detached, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {
   "crypto_aead_xchacha20poly1305_ietf_keygen", 0,
   enif_crypto_aead_xchacha20poly1305_ietf_keygen,
   ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {
   "crypto_aead_xchacha20poly1305_ietf_encrypt", 4,
   enif_crypto_aead_xchacha20poly1305_ietf_encrypt,
   ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"crypto_aead_xchacha20poly1305_ietf_decrypt", 4,
   enif_crypto_aead_xchacha20poly1305_ietf_decrypt,
   ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

ERL_NIF_INIT(soda_api, nif_funcs, &load, NULL, &upgrade, &unload);
