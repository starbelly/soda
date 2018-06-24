%%% @doc module soda_api provides bindings to libsodium for Erlang
%%% @end.
-module(soda_api).

% AEAD Constructions
-export([
         aead_xchacha20poly1305_ietf_encrypt/4,
         aead_xchacha20poly1305_ietf_decrypt/4, 
         aead_xchacha20poly1305_ietf_keygen/0
]).

% Random
-export([randombytes/1]).

-spec randombytes(non_neg_integer()) -> binary().
randombytes(N) when N >= 0 ->
    soda_nif:randombytes(N).

-spec aead_xchacha20poly1305_ietf_keygen() -> binary() | {error, term()}.
aead_xchacha20poly1305_ietf_keygen() ->                                          
    soda_nif:crypto_aead_xchacha20poly1305_ietf_keygen().

-spec aead_xchacha20poly1305_ietf_encrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.
aead_xchacha20poly1305_ietf_encrypt(Message, AD, Nonce, Key) when
      is_binary(Message) andalso is_binary(AD) andalso is_binary(Nonce) andalso
      is_binary(Key) ->
    soda_nif:crypto_aead_xchacha20poly1305_ietf_encrypt(Message, AD, Nonce, Key).

-spec aead_xchacha20poly1305_ietf_decrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.
aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key) when
      is_binary(CT) andalso is_binary(AD) andalso is_binary(Nonce) andalso
      is_binary(Key) ->
    soda_nif:crypto_aead_xchacha20poly1305_ietf_decrypt(CT, AD, Nonce, Key).
