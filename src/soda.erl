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
-export([hash/3, hash_init/1, hash_init/2, hash_update/2, hash_final/2, password_hash/1, password_verify/2]).

% AEAD
-export([aead_encrypt/2, aead_decrypt/4]).

-define(NONCE_SIZES,
        #{
            aead_xchacha20poly1305_ietf => 24
         }
       ).

%% @doc aead_encrypt/0 encrypts a message with additional data 
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

%% @doc aead_decrypt/4 decrypt a message with non-confidental additional data 
%% The aead_decrypt/4 function returns a decrypted message using the supplied
%% cipher text, non-confidential Addition Data, Nonce, and Key. 
%% @end
-spec aead_decrypt(binary(), binary(), binary(), binary()) -> {ok, binary()}.
aead_decrypt(C, Ad, N, K)  when is_binary(C)  andalso is_binary(Ad) andalso
                                is_binary(N) andalso size(N) == 24 andalso
                                is_binary(K)  andalso size(K) == 32 ->
    M = soda_api:aead_xchacha20poly1305_ietf_decrypt(C, Ad, N, K),
    {ok, M}.

%% @doc hash/3 compute a fixed-length finger print
%% The hash/3 function returns a computed fixed-length finger print (hash) 
%% using the supplied message, key, and size. Size must be between 32 and 64. 
%% @end
hash(Msg, Key, Size) when is_binary(Msg)  ->
    {ok, Hash} = soda_api:generichash(Size, Msg, Key),
    {ok, Hash}.

%% @doc hash_init/1 initialize keyless state for a multi-part hash 
%% The hash_init/1 initializes state with no key for a multi-part hash
%% operation. Updates to the state may be perfomed using returned reference and hash_update/2
%% @end
hash_init(Size) ->
    soda_api:generichash_init(Size).

%% @doc hash_init/2 initialize state for a multi-part hash
%% The hash_init/2 initializes state with the supplied key for a multi-part hash
%% operation. Updates to the state may be perfomed using returned reference and hash_update/2 
%% @end
hash_init(Key, Size) ->
    soda_api:generichash_init(Size, Key).

%% @doc hash_update/2 updates state for a multi-part hash
%% The hash_update/2 updates the referenced state with the supplied message. 
%% @end
hash_update(State, Msg) when is_reference(State) 
                        andalso is_binary(Msg) ->
    soda_api:generichash_update(State, Msg).

%% @doc hash_final/2 finalize a multi-part hash
%% The hash_final/2 functions returns a complete hash given a reference to a
%% hash state and an output size.
%% @end
hash_final(State, Size) when is_reference(State) ->
    soda_api:generichash_final(Size, State).

%% @doc nonce/1 generate a nonce for supported algorithms.
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
