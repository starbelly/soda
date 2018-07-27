%%% @author Bryan Paxton <starbelly@pobox.com>
%%% @doc The soda_api is the lowest level interface of the soda library. It is
%%% highly recommended to review the official libsodium documentation before
%%% making use of this module.  
%%% @end.
-module(soda_api).

-define(APPNAME, soda).
-define(LIBNAME, soda_nif).

% AEAD Constructions
-export([
         aead_xchacha20poly1305_ietf_encrypt/4,
         aead_xchacha20poly1305_ietf_decrypt/4,
         aead_xchacha20poly1305_ietf_keygen/0
]).

% Password Hashing and Key Derivation
-export([
         pwhash/2,
         pwhash_str/1,
         pwhash_str_verify/2
]).

% Public Key Signatures
-export([
         sign_keypair/0,
         sign_detached/2,
         sign_verify_detached/3
]).

% Random Data Generation
-export([randombytes/1]).

-on_load(init/0).

%% @doc pwhash/2 key derivation
%% The pwhash/2 function derives a key from a `Passwd' whose length is at least 
%% `pwhash_PASSWD_MIN' bytes and a `Salt' whose size is `crypto_pwhash_SALTBYTES' bytes. 
%% Returns a binary with a minumum length of at least `crypto_pwhash_BYTES_MIN'
%% and at most `crypto_pwhash_BYTES_MAX'.
%% @end
-spec pwhash(binary(), binary()) -> {ok, binary()} | {error, term()}.
pwhash(Passwd, Salt) ->
    crypto_pwhash(Passwd, Salt).

%% @doc pwhash_str/1 hash a password for storage
%%  The pwhash_str/1 function is used for generating hashed passwords that are
%%  suitable for storage (e.g., RDBMS, Menesia, etc.) 
%%% Specifically, the `Passwd' which shall have a minimum length of
%%% `crypto_pwhash_PASSWD_MIN' is hashed using a memory-hard, CPU-intensive hash
%%% function applied to the password passwd of len. The salt required for the
%%% hashing along with all parameters needed to verify a password against the
%%% hash is stored in the returned binary. 
%% @end
-spec pwhash_str(binary()) -> {ok, binary()} | {error, term()}.
pwhash_str(Passwd) ->
    case crypto_pwhash_str(Passwd) of
        {ok, Str} ->
            [X, _] =  binary:split(Str, <<0>>),
            {ok, X};
        {error, Reason} ->
            {error, Reason}
    end.

%% @doc pwhash_str_verify/2 verify a hashed password
%% The pwhash_str_verify/2 function verifies the provided `Passwd' against a
%% supplied `HashStr. `Passwd' should be at least `crypto_pwhash_PASSWD_MIN'
%% @end
-spec pwhash_str_verify(binary(), iodata()) -> boolean().
pwhash_str_verify(HashStr, Password) ->
    crypto_pwhash_str_verify(HashStr, Password).

%% @doc randombytes/1 generate random data
%% Creates and returns a binary with a size of `N' filled with an unpredictable sequence of bytes.
%% @end
-spec randombytes(non_neg_integer()) -> binary().
randombytes(N) when N >= 0 ->
    crypto_randombytes(N).

%% @doc sign_keypair/0 Create key pair suitable for public signatures. 
%% The sign_keypair/0 function randomly generates a secret key with a size of
%% `crypto_sign_SECRETKEYBYTES' bytes and a corresponding public key with a size
%% of crypto_sign_PUBLICKEYBYTES
%% @end
-spec sign_keypair() -> {binary(), binary()}.
sign_keypair() ->
    crypto_sign_keypair().

%%% @doc sign_detached/2 
%%% The sign_detached/2 function signs a the message`M' using
%%% the secret key `Sk' that is a minimum of `crypto_sign_SECRETKEYBYTES' bytes.
%%% @end
-spec sign_detached(M, Sk) -> {ok, Ds} | {error, failed_verification}
    when
      M  :: iodata(),
      Sk :: binary(),
      Ds :: binary().
sign_detached(M, Sk) ->
    crypto_sign_detached(M, Sk).

%%% @doc sign_verify_detached/3 validate a signature.
%%% The sign_verify_detached/3 function verifies the signature `Sig' is valid for a
%%% the given message `M' using the public key `Pk'.
%%% @end
-spec sign_verify_detached(Sig, M, Pk) -> {ok, M} | {error, failed_verification}
    when
      Sig :: binary(),
      M   :: iodata(),
      Pk  :: binary().
sign_verify_detached(Sig, M, Pk) ->
    case crypto_sign_verify_detached(Sig, M, Pk) of
        true -> {ok, M};
        false -> {error, failed_verification}
    end.

%% ----------------------
%% @doc aead_xchacha20poly1305_ietf_keygen/0 generates a random key is
%% equivalent to calling `randombytes/1' with `aead_xchacha20poly1305_ietf_KEYBYTES'
%% @end
-spec aead_xchacha20poly1305_ietf_keygen() -> binary() | {error, term()}.
aead_xchacha20poly1305_ietf_keygen() ->
    crypto_aead_xchacha20poly1305_ietf_keygen().

%% ----------------------
%% @doc aead_xchacha20poly1305_ietf_encrypt/4 encrypts `Message' with additional data
%% `AD' using `Key' and `Nonce'. Returns the encrypted message followed by
%% `aead_chacha20poly1305_ietf_ABYTES/0' bytes of MAC.
%% @end
-spec aead_xchacha20poly1305_ietf_encrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.
aead_xchacha20poly1305_ietf_encrypt(Message, AD, Nonce, Key) when
      is_bitstring(Message) andalso is_binary(AD) andalso is_binary(Nonce) andalso
      is_binary(Key) ->
    crypto_aead_xchacha20poly1305_ietf_encrypt(Message, AD, Nonce, Key).

-spec aead_xchacha20poly1305_ietf_decrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.

%% @doc aead_xchacha20poly1305_ietf_decrypt/4 decrypts ciphertext `CT' with additional
%% data `AD' using `Key' and `Nonce'. Note: `CipherText' should contain
%% `crypto_aead_xchacha20poly1305_ietf_ABYTES' bytes that is the MAC. Returns the decrypted
%% message.
%% @end
aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key) when
      is_binary(CT) andalso is_binary(AD) andalso is_binary(Nonce) andalso
      is_binary(Key) ->
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
crypto_pwhash(_Password, _Salt)
    -> erlang:nif_error(nif_not_loaded).

crypto_pwhash_str(_Password)
    -> erlang:nif_error(nif_not_loaded).

crypto_pwhash_str_verify(_Hash, _Password)
    -> erlang:nif_error(nif_not_loaded).

crypto_randombytes(_RequestedSize)
    -> erlang:nif_error(nif_not_loaded).

crypto_sign_keypair()
    -> erlang:nif_error(nif_not_loaded).

crypto_sign_detached(_Foo, _Bar)
    -> erlang:nif_error(nif_not_loaded).

crypto_sign_verify_detached(_Foo, _Bar, _Baz)
    -> erlang:nif_error(nif_not_loaded).

crypto_aead_xchacha20poly1305_ietf_keygen()
    -> erlang:nif_error(nif_not_loaded).

crypto_aead_xchacha20poly1305_ietf_encrypt(_Msg, _Ad, _Nonce, _Key)
    -> erlang:nif_error(nif_not_loaded).

crypto_aead_xchacha20poly1305_ietf_decrypt(_Ciphered, _AD, _Nonce, _Key)
   ->  erlang:nif_error(nif_not_loaded).
