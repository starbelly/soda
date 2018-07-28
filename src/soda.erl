%%% @author Bryan Paxton <starbelly@pobox.com>
%%% @doc soda module is the default interface which intends to provide 
%%% a simple and inuitive interface to soda_api. For advanced usage 
%%% please refer to soda_api.
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

to_bin(List) -> erlang:list_to_binary(List).

%% @doc aead_encrypt/0 encrypt a message with additional data 
%% The aead_encrypt/2 function returns an encrypted binary created from the
%% message `Msg'  and non-confidential additional data `Ad'. 
%% The additional data may be 0 byte if no additional data is required.
%% Returns the ciphered text, 192 bit nonce and a secret key. 
%% @end
-spec aead_encrypt(binary(), binary()) -> {ok, binary(), binary(), binary()}.
aead_encrypt(Msg, Ad) when is_list(Msg) andalso is_list(Ad) ->
     aead_encrypt(to_bin(Msg), to_bin(Ad));
aead_encrypt(Msg, Ad) when is_binary(Msg) andalso is_list(Ad) ->
    aead_encrypt(Msg, to_bin(Ad));
aead_encrypt(Msg, Ad) when is_list(Msg) andalso is_binary(Ad) ->
    aead_encrypt(to_bin(Msg), Ad);
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
