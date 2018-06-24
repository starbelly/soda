-module(prop_base).
-include_lib("proper/include/proper.hrl").

-define(AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, 24).
-define(AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 32).
-define(AEAD_XCHACHA20POLY1305_IETF_ABYTES, 24).
-define(AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX, 24).


%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

%% ------------------------------------------------------------
%% * randombytes/1
prop_randombytes() ->
  ?FORALL({I},{non_neg_integer()},
  begin
    is_binary(soda:randombytes(I))
  end).

prop_randombytes_neg_int_fail() ->
  ?FORALL({I},{neg_integer()},
  begin
    try
        soda:randombytes(I),
        false
    catch
        error:badarg          -> true;
        error:function_clause -> true
    end    
  end).

%% AEAD XChaCha20Poly1305
%% ------------------------------------------------------------
%% * aead_chacha20poly1305_encrypt/4,
%% * aead_chacha20poly1305_decrypt/4,
prop_aead_xchacha20poly1305_ietf() ->
  ?FORALL({Msg, Ad, Nonce, Key},
          {binary(), binary(), binary(?AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),
           binary(?AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)},
  begin
    EncryptMsg = soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    equals(soda:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, Ad, Nonce, Key), Msg)
  end).

prop_nonce() ->
  ?FORALL({},{},
  begin
    Props = [
         {aead_xchacha20poly1305_ietf, ?AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES}
        ],
    Pred = fun({N,S}) -> erlang:size(soda:nonce(N)) == S end, 
    [] = lists:dropwhile(Pred, Props),
    true
  end).

prop_nonce_fail() ->
  ?FORALL({},{},
  begin
    case soda:nonce(bad_nonce_type) of 
        {error, unknown_nonce} -> true;
        _ -> false
    end
  end).

prop_aead_xchacha20poly1305_ietf_keygen() ->
  ?FORALL({},{},
  begin
    K = soda:aead_xchacha20poly1305_ietf_keygen(),
    equals(erlang:size(K), ?AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)
  end).

prop_aead_xchacha20poly1305_ietf_msg_fail() ->
  ?FORALL({Msg, Ad, Nonce, Key},
          {binary(), binary(), binary(?AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),
           binary(?AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)},
  begin
    EncryptMsg = soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    case soda:aead_xchacha20poly1305_ietf_decrypt(<<0:8, EncryptMsg/binary>>,
                                                   Ad, Nonce, Key) of
        {error, _} -> true;
        _          -> false
    end
  end).

prop_aead_xchacha20poly1305_ietf_ad_fail() ->
  ?FORALL({Msg, Ad, Nonce, Key},
          {binary(), binary(), binary(?AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),
           binary(?AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)},
  begin
    EncryptMsg = soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    case soda:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, <<0:8, Ad/binary>>, Nonce, Key) of
        {error, _} -> true;
        _          -> false
    end
  end).

prop_aead_xchacha20poly1305_ietf_nonce_fail() ->
  ?FORALL({Msg, Ad, Nonce, Key, BadNonce},
          {binary(), binary(), binary(24), binary(32), binary(24)},
  begin
    EncryptMsg = soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    case soda:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, Ad, BadNonce, Key) of
        {error, _} -> true;
        _          -> false
    end
  end).

prop_aead_xchacha20poly1305_ietf_key_fail() ->
  ?FORALL({Msg, Ad, Nonce, Key, BadKey},
          {binary(), binary(), binary(24), binary(32), binary(32)},
  begin
    EncryptMsg = soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    case soda:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, Ad, Nonce, BadKey) of
        {error, _} -> true;
        _          -> false
    end
  end).

prop_aead_xchacha20poly1305_ietf_nonce_size_fail() ->
  ?FORALL({Msg, Ad, UnderSizedNonce, OverSizedNonce, Key},
          {binary(), binary(), binary(23), binary(25), binary(32)},
  begin
    try
        soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, UnderSizedNonce, Key),
        false
    catch
        error:badarg -> true
    end,
    try
        soda:aead_xchacha20poly1305_ietf_decrypt(Msg, Ad, UnderSizedNonce, Key),
        false
    catch
        error:badarg -> true
    end,
    try
        soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, OverSizedNonce, Key),
        false
    catch
        error:badarg -> true
    end,
    try
        soda:aead_xchacha20poly1305_ietf_decrypt(Msg, Ad, OverSizedNonce, Key),
        false
    catch
        error:badarg -> true
    end
  end).

prop_aead_xchacha20poly1305_ietf_key_size_fail() ->
  ?FORALL({Msg, Ad, Nonce, UnderSizedKey, OverSizedKey},
          {binary(), binary(), binary(24), binary(31), binary(33)},
  begin
    try
        soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, UnderSizedKey),
        false
    catch
        error:badarg -> true
    end,
    try
        soda:aead_xchacha20poly1305_ietf_decrypt(Msg, Ad, Nonce, UnderSizedKey),
        false
    catch
        error:badarg -> true
    end,
    try
        soda:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, OverSizedKey),
        false
    catch
        error:badarg -> true
    end,
    try
        soda:aead_xchacha20poly1305_ietf_decrypt(Msg, Ad, Nonce, OverSizedKey),
        false
    catch
        error:badarg -> true
    end
  end).


%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%
