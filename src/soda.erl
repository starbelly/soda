%%% @doc module soda provides binding to libsodium for Erlang and Elixir
%%% @end.
-module(soda).

% Helpers
-export([nonce/1]).

% AEAD Constructions
-export([
         aead_xchacha20poly1305_ietf_encrypt/4,
         aead_xchacha20poly1305_ietf_decrypt/4, 
         aead_xchacha20poly1305_ietf_keygen/0
]).

% Random
-export([randombytes/1]).

% Helper map for nonce/1
-define(NONCE_SIZES, 
        #{
            aead_xchacha20poly1305_ietf => 24
         }
       ).

-spec nonce(atom()) -> binary() | {error, term()}.
nonce(NonceType) ->                                          
    case maps:get(NonceType, ?NONCE_SIZES, none) of 
        none -> {error, unknown_nonce};
        Size -> randombytes(Size)
    end.

-spec randombytes(non_neg_integer()) -> binary().
randombytes(N) ->
    soda_nif:randombytes(N).

-spec aead_xchacha20poly1305_ietf_keygen() -> binary() | {error, term()}.
aead_xchacha20poly1305_ietf_keygen() ->                                          
    soda_nif:crypto_aead_xchacha20poly1305_ietf_keygen().

-spec aead_xchacha20poly1305_ietf_encrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.
aead_xchacha20poly1305_ietf_encrypt(Message, AD, Nonce, Key) ->
    soda_nif:crypto_aead_xchacha20poly1305_ietf_encrypt(Message, AD, Nonce, Key).

-spec aead_xchacha20poly1305_ietf_decrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.
aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key) ->
    soda_nif:crypto_aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key).
