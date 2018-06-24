%%% @doc Sweet Erlang bindings for libsodium
%%% @end.
-module(soda).

-export([nonce/1]).

-export([
         aead_xchacha20poly1305_ietf_encrypt/4,
         aead_xchacha20poly1305_ietf_decrypt/4, 
         aead_xchacha20poly1305_ietf_keygen/0,
         aead_xchacha20poly1305_ietf_KEYBYTES/0,
         aead_xchacha20poly1305_ietf_NPUBBYTES/0,
         aead_xchacha20poly1305_ietf_ABYTES/0,
         aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX/0
]).

-export([randombytes/1]).

-define(CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, 24).

% Helper map for nonce/1
-define(NONCE_SIZES, 
        #{
            aead_xchacha20poly1305_ietf => ?CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES
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

-spec aead_xchacha20poly1305_ietf_KEYBYTES() -> pos_integer().
aead_xchacha20poly1305_ietf_KEYBYTES() ->
    soda_nif:crypto_aead_xchacha20poly1305_ietf_KEYBYTES().

-spec aead_xchacha20poly1305_ietf_NPUBBYTES() -> pos_integer().
aead_xchacha20poly1305_ietf_NPUBBYTES() ->
    soda_nif:crypto_aead_xchacha20poly1305_ietf_NPUBBYTES().

-spec aead_xchacha20poly1305_ietf_ABYTES() -> pos_integer().
aead_xchacha20poly1305_ietf_ABYTES() ->
    soda_nif:crypto_aead_xchacha20poly1305_ietf_ABYTES().

-spec aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX() -> pos_integer().
aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX() ->
    soda_nif:crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX().

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


