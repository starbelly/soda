%%% @doc module soda provides a refreshing interface to soda_api
%%% @end.
-module(soda).

% Helpers
-export([nonce/1, rand/1]).

% Password hashing
-export([password_hash/1, password_verify/2]). 

% AEAD
-export([aead_encrypt/2, aead_decrypt/4]).

-define(NONCE_SIZES, 
        #{
            aead_xchacha20poly1305_ietf => 24
         }
       ).

-spec aead_encrypt(binary(), binary()) -> {ok, binary(), binary(), binary()}.
aead_encrypt(Msg, Ad) when is_binary(Msg) andalso is_binary(Ad) -> 
    N = soda:nonce(aead_xchacha20poly1305_ietf),
    K = soda_api:aead_xchacha20poly1305_ietf_keygen(),
    C = soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, N, K),
    {ok, C, N, K}.

-spec aead_decrypt(binary(), binary(), binary(), binary()) -> {ok, binary()}.
aead_decrypt(C, Ad, N, K)  -> 
    M = soda_api:aead_xchacha20poly1305_ietf_decrypt(C, Ad, N, K),
    {ok, M}.

-spec nonce(atom()) -> binary() | {error, term()}.
nonce(NonceType) when is_atom(NonceType) ->                                          
    case maps:get(NonceType, ?NONCE_SIZES, none) of 
        none -> {error, unknown_nonce};
        Size -> soda_api:randombytes(Size)
    end.

-spec rand(non_neg_integer()) -> binary().
rand(N) when N >= 0 ->
    soda_api:randombytes(N).

-spec password_hash(binary()) -> binary().
password_hash(Str) ->
    soda_api:pwhash_str(Str).

-spec password_verify(binary(), binary()) -> binary().
password_verify(HashStr,Str) ->
    soda_api:pwhash_str_verify(HashStr, Str).
