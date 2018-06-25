#include "erl_nif.h"
#include <string.h>
#include <sodium.h>

#define ATOM_OK "ok"
#define ATOM_ERROR "error"
#define ATOM_TRUE "true"
#define ATOM_FALSE "false"

static int
sodium_load(ErlNifEnv * env, void **priv_data, ERL_NIF_TERM load_info)
{
	if (sodium_init() == -1) {
		return 1;
	} else {
		return 0;
	}
}

static int
sodium_upgrade(ErlNifEnv * env, void **priv, void **old_priv, ERL_NIF_TERM info)
{
	return 0;
}

static void sodium_unload(ErlNifEnv * env, void *priv)
{
	return;
}

static ERL_NIF_TERM soda_error(ErlNifEnv * env, char *error_atom)
{
	return enif_make_tuple2(env, enif_make_atom(env, "error"),
				enif_make_atom(env, error_atom));
}

static ERL_NIF_TERM
enif_crypto_randombytes(ErlNifEnv * env, int argc, ERL_NIF_TERM const argv[])
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

static ERL_NIF_TERM
enif_crypto_pwhash(ErlNifEnv * env, int argc, ERL_NIF_TERM const argv[])
{
	ErlNifBinary h, p, s;

	if ((argc != 2) ||
	    (!enif_inspect_iolist_as_binary(env, argv[0], &p)) ||
	    (!enif_inspect_binary(env, argv[1], &s))) {
		return enif_make_badarg(env);
	}

	if (s.size != crypto_pwhash_SALTBYTES) {
		return soda_error(env, "bad_salt_size");
	}

	if (!enif_alloc_binary(crypto_box_SEEDBYTES, &h)) {
		return soda_error(env, "alloc_failed");
	}

	if (crypto_pwhash(h.data, h.size, (char *)p.data, p.size, s.data,
			  crypto_pwhash_OPSLIMIT_INTERACTIVE,
			  crypto_pwhash_MEMLIMIT_INTERACTIVE,
			  crypto_pwhash_ALG_DEFAULT) != 0) {
		enif_release_binary(&h);
		return soda_error(env, "out_of_memory");
	}

	ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
	ERL_NIF_TERM ret = enif_make_binary(env, &h);

	return enif_make_tuple2(env, ok, ret);
}

static ERL_NIF_TERM
enif_crypto_pwhash_str(ErlNifEnv * env, int argc, ERL_NIF_TERM const argv[])
{
	ErlNifBinary h, p;

	// Validate the arguments
	if ((argc != 1) || (!enif_inspect_iolist_as_binary(env, argv[0], &p))) {
		return enif_make_badarg(env);
	}
	// Allocate memory for return binary
	if (!enif_alloc_binary(crypto_pwhash_STRBYTES, &h)) {
		return soda_error(env, "alloc_failed");
	}

	if (crypto_pwhash_str((char *)h.data, (char *)p.data, p.size,
			      crypto_pwhash_OPSLIMIT_INTERACTIVE,
			      crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) {
		/*
		 * out of memory 
		 */
		enif_release_binary(&h);
		return soda_error(env, "out_of_memory");
	}

	ERL_NIF_TERM ok = enif_make_atom(env, ATOM_OK);
	ERL_NIF_TERM ret = enif_make_binary(env, &h);

	return enif_make_tuple2(env, ok, ret);
}

static ERL_NIF_TERM
enif_crypto_pwhash_str_verify(ErlNifEnv * env, int argc,
			      ERL_NIF_TERM const argv[])
{
	ErlNifBinary h, p;

	// Validate the arguments
	if ((argc != 2) ||
	    (!enif_inspect_iolist_as_binary(env, argv[0], &h)) ||
	    (!enif_inspect_iolist_as_binary(env, argv[1], &p))) {
		return enif_make_badarg(env);
	}

	ERL_NIF_TERM retVal = enif_make_atom(env, ATOM_TRUE);
	if (crypto_pwhash_str_verify((char *)h.data, (char *)p.data, p.size)
	    != 0) {
		/*
		 * wrong password 
		 */
		retVal = enif_make_atom(env, ATOM_FALSE);
	}

	return retVal;
}

/*
 * AEAD XChaCha20 Poly1305 IETF
 */

static ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_ietf_keygen(ErlNifEnv * env, int argc,
					       ERL_NIF_TERM const argv[])
{
	ErlNifBinary key;
	if (0 != argc)
		return enif_make_badarg(env);

	enif_alloc_binary(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, &key);
	crypto_aead_xchacha20poly1305_ietf_keygen(key.data);
	return enif_make_binary(env, &key);
}

static ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_ietf_encrypt(ErlNifEnv * env, int argc,
						ERL_NIF_TERM const argv[])
{
	ErlNifBinary msg, ad, nonce, key, ciphertext;
	if ((argc != 4) || (!enif_inspect_iolist_as_binary(env, argv[0], &msg))
	    || (!enif_inspect_iolist_as_binary(env, argv[1], &ad))
	    || (!enif_inspect_iolist_as_binary(env, argv[2], &nonce))
	    || (!enif_inspect_iolist_as_binary(env, argv[3], &key))
	    || (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
	    || (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary
	    (msg.size + crypto_aead_xchacha20poly1305_ietf_ABYTES, &ciphertext))
	{
		return soda_error(env, "alloc_failed");
	}

	if (crypto_aead_xchacha20poly1305_ietf_encrypt
	    (ciphertext.data, NULL, msg.data, msg.size, ad.data, ad.size, NULL,
	     nonce.data, key.data) != 0) {
		return soda_error(env,
				  "aead_xchacha20poly1305_ietf_encrypt_failed");
	}

	return enif_make_binary(env, &ciphertext);
}

static ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_ietf_decrypt(ErlNifEnv * env, int argc,
						ERL_NIF_TERM const argv[])
{
	ErlNifBinary ciphertext, ad, nonce, key, msg;

	if ((argc != 4)
	    || (!enif_inspect_iolist_as_binary(env, argv[0], &ciphertext))
	    || (!enif_inspect_iolist_as_binary(env, argv[1], &ad))
	    || (!enif_inspect_iolist_as_binary(env, argv[2], &nonce))
	    || (!enif_inspect_iolist_as_binary(env, argv[3], &key))
	    || (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES)
	    || (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)) {
		return enif_make_badarg(env);
	}

	if (!enif_alloc_binary
	    (ciphertext.size - crypto_aead_xchacha20poly1305_ietf_ABYTES, &msg))
	{
		return soda_error(env, "alloc_failed");
	}

	if (crypto_aead_xchacha20poly1305_ietf_decrypt
	    (msg.data, NULL, NULL, ciphertext.data, ciphertext.size, ad.data,
	     ad.size, nonce.data, key.data) < 0) {
		return soda_error(env,
				  "aead_xchacha20poly1305_ietf_decrypt_failed");
	}

	return enif_make_binary(env, &msg);
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

ERL_NIF_INIT(soda_api, nif_funcs, &sodium_load, NULL, &sodium_upgrade,
	     &sodium_unload);
