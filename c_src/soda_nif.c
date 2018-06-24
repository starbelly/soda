#include "erl_nif.h"

#include <string.h>

#include <sodium.h>

#define ATOM_OK "ok"
#define ATOM_ERROR "error"
#define ATOM_TRUE "true"
#define ATOM_FALSE "false"


static
int enif_sodium_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
  return sodium_init();
}

static
ERL_NIF_TERM soda_error(ErlNifEnv *env, char *error_atom) {
  return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error_atom));
}

static
ERL_NIF_TERM enif_randombytes(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[])
{
	unsigned req_size;
	ErlNifBinary result;

	if ((argc != 1) || (!enif_get_uint(env, argv[0], &req_size))) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary(req_size, &result)) {
		return soda_error(env, "alloc_failed");
	}

	randombytes(result.data, result.size);

	return enif_make_binary(env, &result);
}

/*
 * AEAD XChaCha20 Poly1305 IETF
 */

static
ERL_NIF_TERM enif_crypto_aead_xchacha20poly1305_ietf_KEYBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_KEYBYTES);
}

static
ERL_NIF_TERM enif_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
}

static
ERL_NIF_TERM enif_crypto_aead_xchacha20poly1305_ietf_ABYTES(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_ABYTES);
}

static
ERL_NIF_TERM enif_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  return enif_make_int64(env, crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX);
}

static
ERL_NIF_TERM enif_crypto_aead_xchacha20poly1305_ietf_keygen(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  ErlNifBinary key;
  if (0 != argc) return enif_make_badarg(env);

  enif_alloc_binary(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, &key);
  crypto_aead_xchacha20poly1305_ietf_keygen(key.data);
	return enif_make_binary(env, &key);
}


static
ERL_NIF_TERM enif_crypto_aead_xchacha20poly1305_ietf_encrypt(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  ErlNifBinary msg, ad, nonce, key, ciphertext;
  if ((argc != 4) || (!enif_inspect_iolist_as_binary(env, argv[0], &msg))
                  || (!enif_inspect_iolist_as_binary(env, argv[1], &ad))
                  || (!enif_inspect_iolist_as_binary(env, argv[2], &nonce))
                  || (!enif_inspect_iolist_as_binary(env, argv[3], &key))
                  || (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
                  || (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(msg.size + crypto_aead_xchacha20poly1305_ietf_ABYTES, &ciphertext)) {
    return soda_error(env, "alloc_failed");
  }

  if (crypto_aead_xchacha20poly1305_ietf_encrypt(ciphertext.data, NULL, msg.data, msg.size,
                        ad.data, ad.size, NULL, nonce.data, key.data) != 0) {
    return soda_error(env, "aead_xchacha20poly1305_ietf_encrypt_failed");
  }

  return enif_make_binary(env, &ciphertext);
}

static
ERL_NIF_TERM enif_crypto_aead_xchacha20poly1305_ietf_decrypt(ErlNifEnv *env, int argc, ERL_NIF_TERM const argv[]) {
  ErlNifBinary ciphertext, ad, nonce, key, msg;

  if ((argc != 4) || (!enif_inspect_iolist_as_binary(env, argv[0], &ciphertext))
                  || (!enif_inspect_iolist_as_binary(env, argv[1], &ad))
                  || (!enif_inspect_iolist_as_binary(env, argv[2], &nonce))
                  || (!enif_inspect_iolist_as_binary(env, argv[3], &key))
                  || (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
                  || (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)) {
    return enif_make_badarg(env);
  }

  if (!enif_alloc_binary(ciphertext.size - crypto_aead_xchacha20poly1305_ietf_ABYTES, &msg)) {
    return soda_error(env, "alloc_failed");
  }

  if (crypto_aead_xchacha20poly1305_ietf_decrypt(msg.data, NULL, NULL, ciphertext.data, ciphertext.size,
                                                        ad.data, ad.size, nonce.data, key.data) < 0) {
      return soda_error(env, "aead_xchacha20poly1305_ietf_decrypt_failed");
  }

  return enif_make_binary(env, &msg);
}

static ErlNifFunc nif_funcs[] = {
  {"randombytes", 1, enif_randombytes, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"crypto_aead_xchacha20poly1305_ietf_KEYBYTES", 0, enif_crypto_aead_xchacha20poly1305_ietf_KEYBYTES},
  {"crypto_aead_xchacha20poly1305_ietf_NPUBBYTES", 0, enif_crypto_aead_xchacha20poly1305_ietf_NPUBBYTES},
  {"crypto_aead_xchacha20poly1305_ietf_ABYTES", 0, enif_crypto_aead_xchacha20poly1305_ietf_ABYTES},
  {"crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX", 0, enif_crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX},
  {"crypto_aead_xchacha20poly1305_ietf_keygen", 0, enif_crypto_aead_xchacha20poly1305_ietf_keygen, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"crypto_aead_xchacha20poly1305_ietf_encrypt", 4, enif_crypto_aead_xchacha20poly1305_ietf_encrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND},
  {"crypto_aead_xchacha20poly1305_ietf_decrypt", 4, enif_crypto_aead_xchacha20poly1305_ietf_decrypt, ERL_NIF_DIRTY_JOB_CPU_BOUND}
};

ERL_NIF_INIT(soda_nif, nif_funcs, enif_sodium_load, NULL, NULL, NULL);
