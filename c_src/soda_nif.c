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
#define ATOM_BAD_HASH_SIZE "bad_hash_size"
#define ATOM_BAD_KEY_SIZE "bad_key_size"
#define ATOM_BAD_NONCE_SIZE "bad_nonce_size"

/* Shorter aliases */
#define gen_hash_SIZE_MIN crypto_generichash_BYTES_MIN
#define gen_hash_SIZE_MAX crypto_generichash_BYTES_MIN
#define gen_hash_KEYSIZE_MIN  crypto_generichash_KEYBYTES_MIN
#define gen_hash_KEYSIZE_MAX  crypto_generichash_KEYBYTES_MAX

#define MK_ATOM(env, str) enif_make_atom(env, str)
#define MK_BIN(env, bin) enif_make_binary(env, bin)
#define MK_TUPLE(env, ret1, ret2) enif_make_tuple2(env, ret1, ret2)
#define MK_RESOURCE(env, res) enif_make_resource(env, res)
#define BADARG(env) enif_make_badarg(env)
#define GET_BIN(env, term, bin) enif_inspect_binary(env, term, bin)
#define GET_RESOURCE(env, term, type, res) enif_get_resource(env, term, type, res)
#define MK_UINT(env, val, size) enif_get_uint(env, val, size)
#define ALLOC_BIN(size, pk) enif_alloc_binary(size, pk)
#define ALLOC_RESOURCE(env, type) enif_alloc_resource(env, type)
#define ERROR(env, atom_arg) enif_make_tuple2(env, MK_ATOM(env, ATOM_ERROR), MK_ATOM(env, atom_arg))
#define OOM_ERROR(env) ERROR(env, ATOM_OOM)
#define ENCRYPT_FAILED_ERROR(env) ERROR(env, ATOM_ENCRYPT_FAIL)
#define DECRYPT_FAILED_ERROR(env) ERROR(env, ATOM_DECRYPT_FAIL)
#define BAD_SALT_SIZE_ERROR(env) ERROR(env, ATOM_BAD_SALT_SIZE)
#define BAD_KEY_SIZE_ERROR(env) ERROR(env, ATOM_BAD_KEY_SIZE)
#define BAD_NONCE_SIZE_ERROR(env) ERROR(env, ATOM_BAD_NONCE_SIZE)
#define OK_TUPLE(env, ret) enif_make_tuple2(env, MK_ATOM(env, ATOM_OK), ret)
#define OK_TUPLE3(env, ret1, ret2) enif_make_tuple3(env, MK_ATOM(env, ATOM_OK), ret1, ret2)
#define RAISE(env, atom_arg) enif_raise_exception(env, MK_ATOM(env, atom_arg))
#define FREE(r) enif_free(r)
#define FREE_BIN(bin) enif_release_binary(bin)
#define FREE_RESOURCE(res) enif_release_resource(res)
#define IS_NUM(env, arg) enif_is_number(env, arg)
#define GT(arg1, arg2) arg1 > arg2
#define LT(arg1, arg2) arg1 < arg2
#define LT_OR_EQ(arg1, arg2) arg1 <= arg2
#define GT_OR_EQ(arg1, arg2) arg1 >= arg2
#define IN_RANGE(arg1, arg2, arg3) (LT_OR_EQ(arg2, arg1) && GT_OR_EQ(arg2, arg1))
#define NOT_IN_RANGE(arg1, arg2, arg3) (LT_OR_EQ(arg1, arg2) || GT_OR_EQ(arg1, arg3))

#define HASH_STATE_NAME "generichash_state"

static ErlNifResourceType *gen_hash_state_t = NULL;

/* It is our responsiblity to free these */
static int zero_terminate(ErlNifBinary bin, char **buf)
{
	*buf = enif_alloc(bin.size + 1);
	if (!*buf) {
		return 0;
	}
	memmove(*buf, bin.data, bin.size);
	*(*buf + bin.size) = 0;
	return 1;
}

static ErlNifResourceType *init_resource_type(ErlNifEnv * env)
{
	return enif_open_resource_type(env, NULL, HASH_STATE_NAME, NULL,
				       ERL_NIF_RT_CREATE, NULL);
}

static int load(ErlNifEnv * env, void **UNUSED(priv), ERL_NIF_TERM UNUSED(info))
{
	gen_hash_state_t = init_resource_type(env);
	return !gen_hash_state_t || sodium_init() == -1 ? 1 : 0;
}

static int
upgrade(ErlNifEnv * UNUSED(env), void **UNUSED(priv), void **UNUSED(old_priv),
	ERL_NIF_TERM UNUSED(info))
{
	return 0;
}

static void unload(ErlNifEnv * UNUSED(env), void *UNUSED(priv))
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
	    || (!MK_UINT(env, argv[0], &size))) {
		return BADARG(env);
	}

	if (SIZE_MAX <= (unsigned long)size) {
		return RAISE(env, ATOM_BAD_SIZE);
	}

	if (1 != ALLOC_BIN(size, &result)) {
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
enif_crypto_generichash(ErlNifEnv * env, int argc, ERL_NIF_TERM const argv[])
{
	unsigned int s;
	ErlNifBinary h, m, k;

	if ((3 != argc)
	    || !IS_NUM(env, argv[0])
	    || (!MK_UINT(env, argv[0], &s))
	    || (!GET_BIN(env, argv[1], &m))
	    || (!GET_BIN(env, argv[2], &k))) {
		return BADARG(env);
	}

	if (NOT_IN_RANGE(s, gen_hash_SIZE_MIN, gen_hash_SIZE_MAX)) {
		return ERROR(env, ATOM_BAD_HASH_SIZE);
	}

	if (NOT_IN_RANGE(k.size, gen_hash_KEYSIZE_MIN, gen_hash_KEYSIZE_MAX)) {
		return ERROR(env, ATOM_BAD_KEY_SIZE);
	}

	if (!ALLOC_BIN(s, &h)) {
		return OOM_ERROR(env);
	}

	if (0 !=
	    crypto_generichash(h.data, h.size, m.data, m.size, k.data,
			       k.size)) {
		FREE_BIN(&h);
		return ENCRYPT_FAILED_ERROR(env);
	}

	return OK_TUPLE(env, MK_BIN(env, &h));

}

static ERL_NIF_TERM
enif_crypto_generichash_init(ErlNifEnv * env, int argc,
			     ERL_NIF_TERM const argv[])
{
	unsigned int s;
	ErlNifBinary k;

	if ((2 != argc)
	    || !IS_NUM(env, argv[0])
	    || (!MK_UINT(env, argv[0], &s))
	    || (!GET_BIN(env, argv[1], &k))) {
		return BADARG(env);
	}

	if (NOT_IN_RANGE(s, gen_hash_SIZE_MIN, gen_hash_SIZE_MAX)) {
		return ERROR(env, ATOM_BAD_HASH_SIZE);
	}

	unsigned char *key = 0 == k.size ? NULL : k.data;

	if (key
	    && NOT_IN_RANGE(k.size, gen_hash_KEYSIZE_MIN,
			    gen_hash_KEYSIZE_MAX)) {
		return ERROR(env, ATOM_BAD_KEY_SIZE);
	}

	unsigned long b = crypto_generichash_statebytes();
	crypto_generichash_state *state =
	    (crypto_generichash_state *) ALLOC_RESOURCE(gen_hash_state_t, b);

	if (!state) {
		return OOM_ERROR(env);
	}

	if (0 != crypto_generichash_init(state, key, k.size, s)) {
		FREE_RESOURCE(state);
		return ENCRYPT_FAILED_ERROR(env);
	}

	ERL_NIF_TERM r = MK_RESOURCE(env, state);
	FREE_RESOURCE(state);

	return OK_TUPLE(env, r);
}

static ERL_NIF_TERM
enif_crypto_generichash_update(ErlNifEnv * env, int argc,
			       ERL_NIF_TERM const argv[])
{
	ErlNifBinary m;
	crypto_generichash_state *state;

	if ((2 != argc)
	    || (!GET_RESOURCE(env, argv[0], gen_hash_state_t, (void **)&state))
	    || (!GET_BIN(env, argv[1], &m))) {
		return BADARG(env);
	}

	if (0 != crypto_generichash_update(state, m.data, m.size)) {
		return ENCRYPT_FAILED_ERROR(env);
	}

	return OK_TUPLE(env, MK_ATOM(env, ATOM_TRUE));
}

static ERL_NIF_TERM
enif_crypto_generichash_final(ErlNifEnv * env, int argc,
			      ERL_NIF_TERM const argv[])
{
	unsigned int s;
	ErlNifBinary h;
	crypto_generichash_state *state;

	if ((2 != argc)
	    || !IS_NUM(env, argv[0])
	    || (!MK_UINT(env, argv[0], &s))
	    || (!GET_RESOURCE(env, argv[1], gen_hash_state_t, (void **)&state))) {
		return BADARG(env);
	}

	if (NOT_IN_RANGE(s, gen_hash_SIZE_MIN, gen_hash_SIZE_MAX)) {
		return ERROR(env, ATOM_BAD_HASH_SIZE);
	}

	if (!ALLOC_BIN(s, &h)) {
		return OOM_ERROR(env);
	}

	crypto_generichash_state safe = *state;

	if (0 != crypto_generichash_final(&safe, h.data, h.size)) {
		FREE_BIN(&h);
		return ENCRYPT_FAILED_ERROR(env);
	}

	ERL_NIF_TERM ret = enif_make_binary(env, &h);
	FREE_RESOURCE(&safe);
  FREE_RESOURCE(&state);
	return OK_TUPLE(env, ret);
}

static ERL_NIF_TERM
enif_crypto_pwhash(ErlNifEnv * env, int argc, ERL_NIF_TERM const argv[])
{
	ErlNifBinary h, p, s;

	if ((2 != argc)
	    || (!GET_BIN(env, argv[0], &p))
	    || (!GET_BIN(env, argv[1], &s))) {
		return BADARG(env);
	}

	if (s.size != crypto_pwhash_SALTBYTES) {
		return ERROR(env, ATOM_BAD_SALT_SIZE);
	}

	if (!ALLOC_BIN(crypto_box_SEEDBYTES, &h)) {
		return OOM_ERROR(env);
	}

	if (0 !=
	    crypto_pwhash(h.data, h.size, (char *)p.data, p.size, s.data,
			  crypto_pwhash_OPSLIMIT_INTERACTIVE,
			  crypto_pwhash_MEMLIMIT_INTERACTIVE,
			  crypto_pwhash_ALG_DEFAULT)) {
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

	char *passwd;
	if (!zero_terminate(p, &passwd)) {
		return BADARG(env);
	}

	if (!ALLOC_BIN(crypto_pwhash_STRBYTES, &h)) {
		return OOM_ERROR(env);
	}

	int res = crypto_pwhash_str((char *)h.data, passwd, p.size,
				    crypto_pwhash_OPSLIMIT_INTERACTIVE,
				    crypto_pwhash_MEMLIMIT_INTERACTIVE);

	FREE(passwd);

	if (res != 0) {
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
	    || !ALLOC_BIN(crypto_sign_SECRETKEYBYTES, &sk)) {
		return OOM_ERROR(env);
	}

	crypto_sign_keypair(pk.data, sk.data);

	return OK_TUPLE3(env, MK_BIN(env, &pk), MK_BIN(env, &sk));
}

static
ERL_NIF_TERM enif_crypto_sign_seed_keypair(ErlNifEnv * env, int argc,
					   ERL_NIF_TERM const argv[])
{
	ErlNifBinary pk, sk, seed;

	if ((1 != argc)
	    || (!GET_BIN(env, argv[0], &seed))) {
		return BADARG(env);
	}

	if (!ALLOC_BIN(crypto_sign_PUBLICKEYBYTES, &pk)
	    || !ALLOC_BIN(crypto_sign_SECRETKEYBYTES, &sk)) {
		return OOM_ERROR(env);
	}

	if (0 != crypto_sign_seed_keypair(pk.data, sk.data, seed.data)) {
		FREE_BIN(&pk);
		FREE_BIN(&sk);
		return OOM_ERROR(env);
	}

	return OK_TUPLE3(env, MK_BIN(env, &pk), MK_BIN(env, &sk));
}

static
ERL_NIF_TERM enif_crypto_sign(ErlNifEnv * env, int argc,
			      ERL_NIF_TERM const argv[])
{
	ErlNifBinary m, sk, sig;

	if ((2 != argc)
	    || (!GET_BIN(env, argv[0], &m))
	    || (!GET_BIN(env, argv[1], &sk))) {
		return BADARG(env);
	}

	if (sk.size != crypto_sign_SECRETKEYBYTES) {
		return BADARG(env);
	}

	if (!ALLOC_BIN(crypto_sign_BYTES + m.size, &sig)) {
		return OOM_ERROR(env);
	}

	if (0 != crypto_sign(sig.data, NULL, m.data, m.size, sk.data)) {
		return ENCRYPT_FAILED_ERROR(env);
	}

	return MK_BIN(env, &sig);
}

static
ERL_NIF_TERM enif_crypto_sign_open(ErlNifEnv * env, int argc,
				   ERL_NIF_TERM const argv[])
{
	ErlNifBinary um, sm, pk;

	if ((2 != argc)
	    || (!GET_BIN(env, argv[0], &sm))
	    || (!GET_BIN(env, argv[1], &pk))) {
		return BADARG(env);
	}

	if (!ALLOC_BIN(sm.size - crypto_sign_BYTES, &um)) {
		return OOM_ERROR(env);
	}

	if (0 != crypto_sign_open(um.data, NULL, sm.data, sm.size, pk.data)) {
		return ENCRYPT_FAILED_ERROR(env);
	}

	return OK_TUPLE(env, MK_BIN(env, &um));

}

static
ERL_NIF_TERM enif_crypto_sign_detached(ErlNifEnv * env, int argc,
				       ERL_NIF_TERM const argv[])
{
	ErlNifBinary m, sk, sig;

	if ((2 != argc)
	    || (!GET_BIN(env, argv[0], &m))
	    || (!GET_BIN(env, argv[1], &sk))) {
		return BADARG(env);
	}

	if (sk.size != crypto_sign_SECRETKEYBYTES) {
		return BADARG(env);
	}

	if (!ALLOC_BIN(crypto_sign_BYTES, &sig)) {
		return OOM_ERROR(env);
	}

	crypto_sign_detached(sig.data, NULL, m.data, m.size, sk.data);

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
	    || (!GET_BIN(env, argv[2], &pk))) {
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
enif_crypto_aead_xchacha20poly1305_ietf_keygen(ErlNifEnv * env, int argc,
					       ERL_NIF_TERM const
					       UNUSED(argv[]))
{

	ErlNifBinary key;
	if (0 != argc) {
		return BADARG(env);
	}

	if (!ALLOC_BIN(crypto_aead_xchacha20poly1305_ietf_KEYBYTES, &key)) {
		return OOM_ERROR(env);
	}

	crypto_aead_xchacha20poly1305_ietf_keygen(key.data);
	return MK_BIN(env, &key);
}

static ERL_NIF_TERM
enif_crypto_aead_xchacha20poly1305_ietf_encrypt(ErlNifEnv * env, int argc,
						ERL_NIF_TERM const argv[])
{
	ErlNifBinary msg, ad, nonce, key, ct;
	if ((4 != argc) || (!GET_BIN(env, argv[0], &msg))
	    || (!GET_BIN(env, argv[1], &ad))
	    || (!GET_BIN(env, argv[2], &nonce))
	    || (!GET_BIN(env, argv[3], &key))) {
		return BADARG(env);
	}

	if (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
		return RAISE(env, ATOM_BAD_KEY_SIZE);
	}

	if (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
		return RAISE(env, ATOM_BAD_NONCE_SIZE);
	}

	if (!ALLOC_BIN
	    (msg.size + crypto_aead_xchacha20poly1305_ietf_ABYTES, &ct)) {
		return OOM_ERROR(env);
	}

	if (0 !=
	    crypto_aead_xchacha20poly1305_ietf_encrypt(ct.data, NULL, msg.data,
						       msg.size, ad.data,
						       ad.size, NULL,
						       nonce.data, key.data)) {
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
	    ) {
		return BADARG(env);
	}

	if (key.size != crypto_aead_xchacha20poly1305_ietf_KEYBYTES) {
		return RAISE(env, ATOM_BAD_KEY_SIZE);
	}

	if (nonce.size != crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
		return RAISE(env, ATOM_BAD_NONCE_SIZE);
	}

	if (!ALLOC_BIN
	    (ct.size - crypto_aead_xchacha20poly1305_ietf_ABYTES, &msg)) {
		return OOM_ERROR(env);
	}

	if (0 >
	    crypto_aead_xchacha20poly1305_ietf_decrypt(msg.data, NULL, NULL,
						       ct.data, ct.size,
						       ad.data, ad.size,
						       nonce.data, key.data)) {
		FREE_BIN(&msg);
		return DECRYPT_FAILED_ERROR(env);
	}

	return MK_BIN(env, &msg);
}

static ErlNifFunc nif_funcs[] = {
	{
	 "crypto_generichash", 3, enif_crypto_generichash,
	 ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{
	 "crypto_generichash_init", 2, enif_crypto_generichash_init,
	 ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{
	 "crypto_generichash_update", 2, enif_crypto_generichash_update,
	 ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{
	 "crypto_generichash_final", 2, enif_crypto_generichash_final,
	 ERL_NIF_DIRTY_JOB_CPU_BOUND},
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
	 "crypto_sign_seed_keypair", 1,
	 enif_crypto_sign_seed_keypair, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{
	 "crypto_sign", 2,
	 enif_crypto_sign, ERL_NIF_DIRTY_JOB_CPU_BOUND},
	{
	 "crypto_sign_open", 2,
	 enif_crypto_sign_open, ERL_NIF_DIRTY_JOB_CPU_BOUND},
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
