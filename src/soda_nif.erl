%%% @doc module soda_nif
%%% @end
%%% @private
-module(soda_nif).

-export([
         randombytes/1,
         crypto_aead_xchacha20poly1305_ietf_encrypt/4,
         crypto_aead_xchacha20poly1305_ietf_decrypt/4,
         crypto_aead_xchacha20poly1305_ietf_keygen/0,
         crypto_aead_xchacha20poly1305_ietf_KEYBYTES/0,
         crypto_aead_xchacha20poly1305_ietf_NPUBBYTES/0,
         crypto_aead_xchacha20poly1305_ietf_ABYTES/0,
         crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX/0
        ]).

-on_load(init/0).

init() ->
    Dir = case code:priv_dir(soda) of
              {error, bad_name} ->
                  filename:join(
                    filename:dirname(
                      filename:dirname(
                        code:which(?MODULE))), "priv");
              D -> D
          end,
    SoName = filename:join(Dir, atom_to_list(?MODULE)),
    erlang:load_nif(SoName, 0).


randombytes(_RequestedSize)                                                 -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_KEYBYTES()                               -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_NPUBBYTES()                              -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_ABYTES()                                 -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX()                       -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_keygen()                                 -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_encrypt(_Msg, _Ad, _Nonce, _Key)         -> erlang:nif_error(nif_not_loaded).
crypto_aead_xchacha20poly1305_ietf_decrypt(_Ciphered, _AD, _Nonce, _Key)    -> erlang:nif_error(nif_not_loaded).


