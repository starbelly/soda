%%% @doc module soda_api provides bindings to libsodium for Erlang
%%% @end.
-module(soda_api).

-define(APPNAME, soda).
-define(LIBNAME, soda_nif).

% AEAD Constructions
-export([
         pwhash/2,
         pwhash_str/1,
         pwhash_str_verify/2,
         aead_xchacha20poly1305_ietf_encrypt/4,
         aead_xchacha20poly1305_ietf_decrypt/4, 
         aead_xchacha20poly1305_ietf_keygen/0
]).

% Random data generation
-export([randombytes/1]).

-on_load(init/0).

-spec pwhash(iodata(), binary()) -> {ok, binary()} | {error, term()}.
pwhash(Str, Salt) ->
    crypto_pwhash(Str, Salt).

-spec pwhash_str(iodata()) -> {ok, iodata()} | {error, term()}.
pwhash_str(Password) ->
    case crypto_pwhash_str(Password) of
        {ok, Str} ->
            [X, _] =  binary:split(Str, <<0>>),
            {ok, X};
        {error, Reason} ->
            {error, Reason}
    end.

-spec pwhash_str_verify(binary(), iodata()) -> boolean().
pwhash_str_verify(HashStr, Password) ->
    crypto_pwhash_str_verify(iolist_to_binary([HashStr, 0]), Password).


-spec randombytes(non_neg_integer()) -> binary().
randombytes(N) when N >= 0 ->
    crypto_randombytes(N).

-spec aead_xchacha20poly1305_ietf_keygen() -> binary() | {error, term()}.
aead_xchacha20poly1305_ietf_keygen() ->                                          
    crypto_aead_xchacha20poly1305_ietf_keygen().

-spec aead_xchacha20poly1305_ietf_encrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.
aead_xchacha20poly1305_ietf_encrypt(Message, AD, Nonce, Key) when
      is_binary(Message) andalso is_binary(AD) andalso is_binary(Nonce) andalso
      is_binary(Key) ->
    crypto_aead_xchacha20poly1305_ietf_encrypt(Message, AD, Nonce, Key).

-spec aead_xchacha20poly1305_ietf_decrypt(binary(), binary(), binary(),
                                          binary()) -> binary() | {error,
                                                                   term()}.
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


crypto_pwhash(_Password, _Salt)                                             -> erlang:nif_error(nif_not_loaded).
crypto_pwhash_str(_Password)                                                -> erlang:nif_error(nif_not_loaded).
crypto_pwhash_str_verify(_Hash,_Password)                                   -> erlang:nif_error(nif_not_loaded).
crypto_randombytes(_RequestedSize)                                          -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_keygen()                                 -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_encrypt(_Msg, _Ad, _Nonce, _Key)         -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_decrypt(_Ciphered, _AD, _Nonce, _Key)    -> erlang:nif_error(nif_not_loaded).


