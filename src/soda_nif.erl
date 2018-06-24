%%% @doc module soda_nif lowest level interface to libsodium bindings 
%%%  This module should not be used directly. 
%%% @end
%%% @private
-module(soda_nif).

-define(APPNAME, soda).
-define(LIBNAME, soda_nif).

-export([
         crypto_randombytes/1,
         crypto_pwhash/2,
         crypto_pwhash_str/1,
         crypto_pwhash_str_verify/2,
         crypto_aead_xchacha20poly1305_ietf_encrypt/4,
         crypto_aead_xchacha20poly1305_ietf_decrypt/4,
         crypto_aead_xchacha20poly1305_ietf_keygen/0
        ]).

-on_load(init/0).

init() ->
    load_soda_nif().


crypto_pwhash(_Password, _Salt)                                             -> erlang:nif_error(nif_not_loaded).
crypto_pwhash_str(_Password)                                                -> erlang:nif_error(nif_not_loaded).
crypto_pwhash_str_verify(_Hash,_Password)                                   -> erlang:nif_error(nif_not_loaded).
crypto_randombytes(_RequestedSize)                                          -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_keygen()                                 -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_encrypt(_Msg, _Ad, _Nonce, _Key)         -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_decrypt(_Ciphered, _AD, _Nonce, _Key)    -> erlang:nif_error(nif_not_loaded).

load_soda_nif() -> 
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
