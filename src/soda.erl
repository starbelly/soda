%%% @author Bryan Paxton <starbelly@pobox.com>
%%% @doc soda module is the default interface which intends to provide 
%%% a simple and inuitive interface to soda_api, which in turn provides a
%%% lower level interface to libsodium. 
%%% For advanced usage please refer to soda_api.
%%% @end.
-module(soda).

% Helpers
-export([nonce/1, rand/1]).

% Password hashing
-export([hash/1, hash/2, hash_init/0, hash_init/1, hash_update/2, hash_final/1, password_hash/1, password_verify/2]).

% AEAD
-export([aead_encrypt/2, aead_decrypt/4]).

-define(NONCE_SIZES,
        #{
            aead_xchacha20poly1305_ietf => 24
         }
       ).

%% @doc
%% The aead_encrypt/2 function returns an encrypted binary created from the
%% message `Msg'  and non-confidential additional data `Ad'. 
%% The additional data may be 0 byte if no additional data is required.
%% Returns the ciphered text, 192 bit nonce and a secret key. 
%% @end
-spec aead_encrypt(binary(), binary()) -> {ok, binary(), binary(), binary()}.
aead_encrypt(Msg, Ad) when is_binary(Msg) andalso is_binary(Ad) ->
    N = soda:nonce(aead_xchacha20poly1305_ietf),
    K = soda_api:aead_xchacha20poly1305_ietf_keygen(),
    C = soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, N, K),
    {ok, C, N, K}.

%% @doc
%% The aead_decrypt/4 function returns a decrypted message using the supplied
%% cipher text, non-confidential Addition Data, Nonce, and Key. 
%% @end
-spec aead_decrypt(binary(), binary(), binary(), binary()) -> {ok, binary()}.
aead_decrypt(C, Ad, N, K)  when is_binary(C)  andalso is_binary(Ad) andalso
                                is_binary(N) andalso size(N) == 24 andalso
                                is_binary(K)  andalso size(K) == 32 ->
    M = soda_api:aead_xchacha20poly1305_ietf_decrypt(C, Ad, N, K),
    {ok, M}.

%% @doc
%% The hash/1 function returns a computed fixed-length finger print on the
%% supplied message with a fixed output size of 64 bytes.
%% @end
hash(Msg) when is_binary(Msg)  ->
    soda_api:generichash(Msg).

%% @doc
%% Like hash/1 but also takes a key parameter of which key must be at least 32 bytes.
%% @end
hash(Msg, Key) when is_binary(Msg)  ->
    soda_api:generichash(Msg, Key).

%% @doc
%% The hash_init/1 initializes state with no key for a multi-part hash
%% operation. Updates to the state are perfomed using returned reference and hash_update/2
%% @end
-spec hash_init() -> {ok, reference()} | {error, term()}.
hash_init() ->
    soda_api:generichash_init().

%% @doc
%% Like hash_init/1 but also takes a key parameter.
%% @end
-spec hash_init(binary()) -> {ok, reference()} | {error, term()}.
hash_init(Key) when is_binary(Key) ->
    soda_api:generichash_init(Key).

%% @doc
%% The hash_update/2 updates the referenced state with the supplied message.
%% Returning new state which may be used to perform more updates or finalize the
%% hash using hash_final/2.
%% @end
-spec hash_update(reference(), binary()) -> {ok, reference()} | {error, term()}.
hash_update(State, Msg) when is_reference(State) 
                        andalso is_binary(Msg) ->
    soda_api:generichash_update(State, Msg).

%% @doc
%% The hash_final/2 functions returns a complete hash given a reference to a
%% hash state and an output size.
%% @end
-spec hash_final(reference()) -> {ok, binary()} | {error, term()}.
hash_final(State) when is_reference(State) ->
    soda_api:generichash_final(State).

%% @doc
%% The following nonce types are currently supported:
%%   `aead_xchacha20poly1305_ietf'
%% @end
-spec nonce(atom()) -> binary() | {error, term()}.
nonce(NonceType) when is_atom(NonceType) ->
    case maps:get(NonceType, ?NONCE_SIZES, none) of
        none -> {error, unknown_nonce};
        Size -> soda_api:randombytes(Size)
    end.

%% @doc 
%% Creates a hashed password suitable for storage (e.g., RDMBS, Mnesia, etc.). 
%% All parameters needed to verify the password are stored in the returned
%% binary. 
%% @end
-spec password_hash(binary()) -> {ok, binary()} | {error, term()}.
password_hash(Str) when is_binary(Str) ->
    soda_api:pwhash_str(Str).

%% @doc 
%% Verifies a password against a hashed password as created by `password_hash/1'
%% @end
-spec password_verify(binary(), binary()) -> boolean().
password_verify(HashStr, Str) when is_binary(HashStr) 
                                   andalso is_binary(Str) ->
    soda_api:pwhash_str_verify(HashStr, Str).

%% @doc
%% Generate a binary consisting a sequence of `N' unpredictable random bytes.
%% @end
-spec rand(non_neg_integer()) -> binary().
rand(N) when is_integer(N) andalso N >= 0 ->
    soda_api:randombytes(N).
