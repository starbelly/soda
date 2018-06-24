%%% @doc module soda provides a refreshing interface to soda_api
%%% @end.
-module(soda).

% Helpers
-export([nonce/1, rand/1]).

-export([passwd/1, passwd_verify/2]). 

-define(NONCE_SIZES, 
        #{
            aead_xchacha20poly1305_ietf => 24
         }
       ).

-spec nonce(atom()) -> binary() | {error, term()}.
nonce(NonceType) when is_atom(NonceType) ->                                          
    case maps:get(NonceType, ?NONCE_SIZES, none) of 
        none -> {error, unknown_nonce};
        Size -> soda_api:randombytes(Size)
    end.

-spec rand(non_neg_integer()) -> binary().
rand(N) when N >= 0 ->
    soda_api:randombytes(N).

-spec passwd(binary()) -> binary().
passwd(Str) ->
    soda_api:pwhash_str(Str).

-spec passwd_verify(binary(), binary()) -> binary().
passwd_verify(HashStr,Str) ->
    soda_api:pwhash_str_verify(HashStr, Str).
