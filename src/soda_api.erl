%%% @author Bryan Paxton <starbelly@pobox.com>
%%% @doc The soda_api is the lowest level interface of the soda library. It is
%%% highly recommended to review the official libsodium documentation before
%%% making use of this module.
%%% @end.
-module(soda_api).

-define(APPNAME, soda).
-define(LIBNAME, soda_nif).


-type cipher_text() :: binary().
-type message() :: binary().
-type nonce() :: binary().
-type public_key() :: binary().
-type secret_key() :: binary().

% Generic hashing
-export([
         generichash/1,
         generichash/2,
         generichash_init/0,
         generichash_init/1,
         generichash_update/2,
         generichash_final/1

]).

% AEAD Constructions
-export([
         aead_xchacha20poly1305_ietf_encrypt/4,
         aead_xchacha20poly1305_ietf_decrypt/4,
         aead_xchacha20poly1305_ietf_keygen/0
]).

% Utils
-export([bin2hex/1]).

% Password Hashing and Key Derivation
-export([
         pwhash/2,
         pwhash_str/1,
         pwhash_str_verify/2
]).

% Public key crypto
-export([box_keypair/0, box/4, box_open/4]).

% Public Key Signatures
-export([
         sign_keypair/0,
         sign_seed_keypair/1,
         sign/2,
         sign_open/2,
         sign_detached/2,
         sign_verify_detached/3
]).

% Random Data Generation
-export([randombytes/1]).


-on_load(init/0).

-spec bin2hex(binary()) -> binary().
bin2hex(Bin) ->
    hd(binary:split(sodium_bin2hex(Bin), <<0>>)).

%% @doc
%% @end
-spec generichash(binary()) -> {ok, binary()} | {error, term()}.
generichash(Msg) when is_binary(Msg)  ->
    crypto_generichash(Msg, <<"">>).

-spec generichash(binary(), binary()) -> {ok, binary()} | {error, term()}.
generichash(Msg, Key) when is_binary(Msg)
                            andalso is_binary(Key) ->
    crypto_generichash(Msg, Key).

%% @doc
%% @end
-spec generichash_init() -> {ok, reference()} | {error, term()}.
generichash_init() ->
    crypto_generichash_init(<<"">>).

%% @doc
%% @end
-spec generichash_init(binary()) -> {ok, reference()} | {error, term()}.
generichash_init(Key) when is_binary(Key) ->
    crypto_generichash_init(Key).

%% @doc
%% @end
-spec generichash_update(reference(), binary()) -> {ok, true} | {error, term()}.
generichash_update(State, Msg) when is_reference(State)
                                        andalso is_binary(Msg) ->
    crypto_generichash_update(State, Msg).

%% @doc
%% @end
-spec generichash_final(reference()) -> {ok, binary()} | {error, term()}.
generichash_final(State) when  is_reference(State) ->
    crypto_generichash_final(State).


%% @doc
%% The pwhash/2 function derives a key from a `Passwd' whose length is at least
%% `pwhash_PASSWD_MIN' bytes and a `Salt' whose size is `crypto_pwhash_SALTBYTES' bytes.
%% Returns a binary with a minumum length of at least `crypto_pwhash_BYTES_MIN'
%% and at most `crypto_pwhash_BYTES_MAX'.
%% @end
-spec pwhash(binary(), binary()) -> {ok, binary()} | {error, term()}.
pwhash(Passwd, Salt) when is_binary(Passwd)
                          andalso is_binary(Salt) ->
    crypto_pwhash(Passwd, Salt).

%% @doc
%%  The pwhash_str/1 function is used for generating hashed passwords that are
%%  suitable for storage (e.g., RDBMS, Menesia, etc.)
%%% Specifically, the `Passwd' which shall have a minimum length of
%%% `crypto_pwhash_PASSWD_MIN' is hashed using a memory-hard, CPU-intensive hash
%%% function applied to the password passwd of len. The salt required for the
%%% hashing along with all parameters needed to verify a password against the
%%% hash is stored in the returned binary.
%% @end
-spec pwhash_str(binary()) -> {ok, binary()} | {error, term()}.
pwhash_str(Passwd) when is_binary(Passwd) ->
    case crypto_pwhash_str(Passwd) of
        {ok, Str} ->
            [X, _] =  binary:split(Str, <<0>>),
            {ok, X};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc
%% The pwhash_str_verify/2 function verifies the provided `Passwd' against a
%% supplied `HashStr. `Passwd' should be at least `crypto_pwhash_PASSWD_MIN'
%% @end
-spec pwhash_str_verify(binary(), iodata()) -> boolean().
pwhash_str_verify(HashStr, Passwd) when is_binary(HashStr)
                                        andalso is_binary(Passwd) ->
    crypto_pwhash_str_verify(HashStr, Passwd).

%% @doc
%% Creates and returns a binary with a size of `N' filled with an unpredictable sequence of bytes.
%% @end
-spec randombytes(non_neg_integer()) -> binary().
randombytes(N) when is_integer(N) andalso N >= 0 ->
    crypto_randombytes(N).

%% @doc
%% The box_keypair/0 function randomly generates a secret key with a size of
%% `crypto_box_SECRETKEYBYTES' bytes and a corresponding public key with a size
%% of crypto_box_PUBLICKEYBYTES
%% @end
-spec box_keypair() -> {binary(), binary()}.
box_keypair() ->
    crypto_box_keypair().

%% @doc
%% The box/4 function encrypts a message with a recipient's public key pk, a
%% sender's secret key and the provided nonce.
%% @end
-spec box(message(), nonce(), public_key(), secret_key()) -> {ok, binary()} | {error, term()}.
box(M, N, Pk, Sk) ->
    crypto_box(M, N, Pk, Sk).

%% @doc
%% The box_open/4 function verifies and decrypts a ciphertext produced by box/4.
%% @end
-spec box_open(cipher_text(), nonce(), public_key(), secret_key()) -> {ok, message()} | {error, term()}.
box_open(C, N, Pk, Sk) ->
    crypto_box_open(C, N, Pk, Sk).

%% @doc
%% The sign_keypair/0 function randomly generates a secret key with a size of
%% `crypto_sign_SECRETKEYBYTES' bytes and a corresponding public key with a size
%% of crypto_sign_PUBLICKEYBYTES
%% @end
-spec sign_keypair() -> {binary(), binary()}.
sign_keypair() ->
    crypto_sign_keypair().

%% @doc
%% The sign_keypair/1 function randomly generates a secret key with a size of
%% `crypto_sign_SECRETKEYBYTES' bytes and a corresponding public key with a size
%% of crypto_sign_PUBLICKEYBYTES
%% @end
-spec sign_seed_keypair(binary()) -> {binary(), binary()}.
sign_seed_keypair(Seed) when is_binary(Seed) ->
    crypto_sign_seed_keypair(Seed).

%%% @doc
%%% The sign/2 function signs a the message`M' using
%%% the secret key `Sk' that is a minimum of `crypto_sign_SECRETKEYBYTES' + `M'
%%% length in bytes.
%%% @end
-spec sign(M, Sk) -> {ok, Ds} | {error, failed_verification}
    when
      M  :: binary(),
      Sk :: binary(),
      Ds :: binary().
sign(M, Sk) when is_binary(M)
                          andalso is_binary(Sk) ->
    crypto_sign(M, Sk).

%%% @doc
%%% The sign/2 function signs a the message`M' using
%%% the primary key `Pk' that is a minimum of `crypto_sign_SECRETKEYBYTES' + `M'
%%% length in bytes.
%%% @end
-spec sign_open(Sm, Pk) -> {ok, Ds} | {error, failed_verification}
    when
      Sm ::  binary(),
      Pk :: binary(),
      Ds :: binary().
sign_open(Sm, Pk) when is_binary(Sm)
                          andalso is_binary(Pk) ->
    crypto_sign_open(Sm,  Pk).


%%% @doc
%%% The sign_detached/2 function signs a the message`M' using
%%% the secret key `Sk' that is a minimum of `crypto_sign_SECRETKEYBYTES' bytes.
%%% @end
-spec sign_detached(M, Sk) -> {ok, Ds} | {error, failed_verification}
    when
      M  :: binary(),
      Sk :: binary(),
      Ds :: binary().
sign_detached(M, Sk) when is_binary(M)
                          andalso is_binary(Sk) ->
    crypto_sign_detached(M, Sk).

%%% @doc
%%% The sign_verify_detached/3 function verifies the signature `Sig' is valid for a
%%% the given message `M' using the public key `Pk'.
%%% @end
-spec sign_verify_detached(Sig, M, Pk) -> {ok, M} | {error, failed_verification}
    when
      Sig :: binary(),
      M   :: binary(),
      Pk  :: binary().
sign_verify_detached(Sig, M, Pk) when is_binary(Sig)
                                      andalso is_binary(M)
                                      andalso is_binary(Pk) ->
    case crypto_sign_verify_detached(Sig, M, Pk) of
        true -> {ok, M};
        false -> {error, failed_verification}
    end.

%% ----------------------
%% @doc
%% aead_xchacha20poly1305_ietf_keygen/0 generates a random key is
%% equivalent to calling `randombytes/1' with `aead_xchacha20poly1305_ietf_KEYBYTES'
%% @end
-spec aead_xchacha20poly1305_ietf_keygen() -> binary() | {error, term()}.
aead_xchacha20poly1305_ietf_keygen() ->
    crypto_aead_xchacha20poly1305_ietf_keygen().

%% ----------------------
%% @doc
%% aead_xchacha20poly1305_ietf_encrypt/4 encrypts `Message' with additional data
%% `AD' using `Key' and `Nonce'. Returns the encrypted message followed by
%% `aead_chacha20poly1305_ietf_ABYTES/0' bytes of MAC.
%% @end
-spec aead_xchacha20poly1305_ietf_encrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.
aead_xchacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key) when is_bitstring(Msg)
                                                         andalso is_binary(AD)
                                                         andalso is_binary(Nonce)
                                                         andalso  is_binary(Key) ->
    crypto_aead_xchacha20poly1305_ietf_encrypt(Msg, AD, Nonce, Key).

-spec aead_xchacha20poly1305_ietf_decrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.

%% @doc
%% aead_xchacha20poly1305_ietf_decrypt/4 decrypts ciphertext `CT' with additional
%% data `AD' using `Key' and `Nonce'. Note: `CipherText' should contain
%% `crypto_aead_xchacha20poly1305_ietf_ABYTES' bytes that is the MAC. Returns the decrypted
%% message.
%% @end
aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key) when is_binary(CT)
                                                        andalso is_binary(AD)
                                                        andalso is_binary(Nonce)
                                                        andalso  is_binary(Key) ->
    crypto_aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key).

%%% @private
init() ->
  SoName = case code:priv_dir(?APPNAME) of
        {error, bad_name} ->
            case filelib:is_dir(filename:join(["..", priv])) of
                true ->
                    filename:join(["..", priv, ?LIBNAME]);
                _ ->
                    filename:join([priv, ?LIBNAME])
            end;
        Dir ->
            filename:join(Dir, ?LIBNAME)
    end,
    erlang:load_nif(SoName, 0).


%%% NIF stubs
sodium_bin2hex(_Bin)
    -> erlang:nif_error(nif_not_loaded).

crypto_generichash(_Msg, _Key)
    -> erlang:nif_error(nif_not_loaded).

crypto_generichash_init(_Key)
    -> erlang:nif_error(nif_not_loaded).

crypto_generichash_update(_State, _Msg)
    -> erlang:nif_error(nif_not_loaded).

crypto_generichash_final(_State)
    -> erlang:nif_error(nif_not_loaded).

crypto_pwhash(_Password, _Salt)
    -> erlang:nif_error(nif_not_loaded).

crypto_pwhash_str(_Password)
    -> erlang:nif_error(nif_not_loaded).

crypto_pwhash_str_verify(_Hash, _Password)
    -> erlang:nif_error(nif_not_loaded).

crypto_randombytes(_RequestedSize)
    -> erlang:nif_error(nif_not_loaded).

crypto_box_keypair()
    -> erlang:nif_error(nif_not_loaded).

crypto_box(_M, _N, _Pk, _Sk)
    -> erlang:nif_error(nif_not_loaded).

crypto_box_open(_C, _N, _Pk, _Sk)
    -> erlang:nif_error(nif_not_loaded).

crypto_sign_keypair()
    -> erlang:nif_error(nif_not_loaded).

crypto_sign_seed_keypair(_Seed)
    -> erlang:nif_error(nif_not_loaded).

crypto_sign(_Msg, _Sk)
    -> erlang:nif_error(nif_not_loaded).

crypto_sign_open(_Signed, _Pk)
    -> erlang:nif_error(nif_not_loaded).

crypto_sign_detached(_Msg, _Sk)
    -> erlang:nif_error(nif_not_loaded).

crypto_sign_verify_detached(_Foo, _Bar, _Baz)
    -> erlang:nif_error(nif_not_loaded).

crypto_aead_xchacha20poly1305_ietf_keygen()
    -> erlang:nif_error(nif_not_loaded).

crypto_aead_xchacha20poly1305_ietf_encrypt(_Msg, _Ad, _Nonce, _Key)
    -> erlang:nif_error(nif_not_loaded).

crypto_aead_xchacha20poly1305_ietf_decrypt(_Ciphered, _AD, _Nonce, _Key)
   ->  erlang:nif_error(nif_not_loaded).
