-module(prop_soda_api).
-include_lib("proper/include/proper.hrl").

-define(AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, 24).
-define(AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 32).
-define(AEAD_XCHACHA20POLY1305_IETF_ABYTES, 24).
-define(AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX, 24).


%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

prop_generichash() ->
    ?FORALL({Msg, Key}, {non_empty(binary(24)), binary(24)},
            begin
                {ok, Bin} = soda_api:generichash(Msg, Key),
                is_binary(Bin)
            end).

prop_generichash_init1() ->
    ?FORALL({}, {},
            begin
                {ok, Ref} = soda_api:generichash_init(),
                true = is_reference(Ref)
            end).

prop_generichash_init2() ->
    ?FORALL({Key}, {non_empty(binary(24))},
            begin
                {ok, Ref} = soda_api:generichash_init(Key),
                true = is_reference(Ref)
            end).

prop_generichash_update() ->
    ?FORALL({Key, Msg}, {non_empty(binary(24)), binary(24)},
            begin
                {ok, State} = soda_api:generichash_init(Key),
                true = is_reference(State),
                {ok, State1} = soda_api:generichash_update(State, Msg),
                true
            end).

prop_generichash_final1() ->
    ?FORALL({Msg1, Msg2}, {binary(24), binary(24)},
            begin
                {ok, State} = soda_api:generichash_init(),
                true = is_reference(State),
                {ok, State1} = soda_api:generichash_update(State, Msg1),
                {ok, State2} = soda_api:generichash_update(State1, Msg2),
                {ok, Hash} = soda_api:generichash_final(State2),
                true = is_binary(Hash)
            end).

prop_generichash_final2() ->
    ?FORALL({Key, Msg1, Msg2}, {non_empty(binary(32)), binary(24), binary(24)},
            begin
                {ok, State} = soda_api:generichash_init(Key),
                true = is_reference(State),
                {ok, State1} = soda_api:generichash_update(State, Msg1),
                {ok, State2} = soda_api:generichash_update(State1, Msg2),
                {ok, Hash} = soda_api:generichash_final(State2),
                true = is_binary(Hash)
            end).

prop_pwhash() ->
    ?FORALL({Passwd, Salt}, {non_empty(binary()), binary(16)},
            begin
                {ok, Bin} = soda_api:pwhash(Passwd, Salt),
                true = is_binary(Bin)
            end).

prop_pwhash_str() ->
    ?FORALL({Passwd}, {non_empty(binary())},
            begin
                {ok, Str} = soda_api:pwhash_str(Passwd),
                true = is_binary(Str)
            end).

prop_pwhash_str_verify() ->
    ?FORALL({Passwd}, {non_empty(binary())},
            begin
                {ok, HashStr} = soda_api:pwhash_str(Passwd),
                equals(soda_api:pwhash_str_verify(HashStr, Passwd), true)
            end).

%% ------------------------------------------------------------
%% * randombytes/1
prop_randombytes() ->
  ?FORALL({I},{non_neg_integer()},
  begin
    is_binary(soda_api:randombytes(I))
  end).

prop_randombytes_neg_int_fail() ->
  ?FORALL({I},{neg_integer()},
  begin
    try
        soda_api:randombytes(I),
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
    EncryptMsg = soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    equals(soda_api:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, Ad, Nonce, Key), Msg)
  end).

prop_aead_xchacha20poly1305_ietf_keygen() ->
  ?FORALL({},{},
  begin
    K = soda_api:aead_xchacha20poly1305_ietf_keygen(),
    equals(erlang:size(K), ?AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)
  end).

prop_aead_xchacha20poly1305_ietf_msg_fail() ->
  ?FORALL({Msg, Ad, Nonce, Key},
          {binary(), binary(), binary(?AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES),
           binary(?AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)},
  begin
    EncryptMsg = soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    case soda_api:aead_xchacha20poly1305_ietf_decrypt(<<0:8, EncryptMsg/binary>>,
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
    EncryptMsg = soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    case soda_api:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, <<0:8, Ad/binary>>, Nonce, Key) of
        {error, _} -> true;
        _          -> false
    end
  end).

prop_aead_xchacha20poly1305_ietf_nonce_fail() ->
  ?FORALL({Msg, Ad, Nonce, Key, BadNonce},
          {binary(), binary(), binary(24), binary(32), binary(24)},
  begin
    EncryptMsg = soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    case soda_api:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, Ad, BadNonce, Key) of
        {error, _} -> true;
        _          -> false
    end
  end).

prop_aead_xchacha20poly1305_ietf_key_fail() ->
  ?FORALL({Msg, Ad, Nonce, Key, BadKey},
          {binary(), binary(), binary(24), binary(32), binary(32)},
  begin
    EncryptMsg = soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, Key),
    case soda_api:aead_xchacha20poly1305_ietf_decrypt(EncryptMsg, Ad, Nonce, BadKey) of
        {error, _} -> true;
        _          -> false
    end
  end).

prop_aead_xchacha20poly1305_ietf_nonce_size_fail() ->
  ?FORALL({Msg, Ad, UnderSizedNonce, OverSizedNonce, Key},
          {binary(), binary(), binary(23), binary(25), binary(32)},
  begin
    try
        soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, UnderSizedNonce, Key),
        false
    catch
        error:bad_nonce_size -> true
    end,
    try
        soda_api:aead_xchacha20poly1305_ietf_decrypt(Msg, Ad, UnderSizedNonce, Key),
        false
    catch
        error:bad_nonce_size -> true
    end,
    try
        soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, OverSizedNonce, Key),
        false
    catch
        error:bad_nonce_size -> true
    end,
    try
        soda_api:aead_xchacha20poly1305_ietf_decrypt(Msg, Ad, OverSizedNonce, Key),
        false
    catch
        error:bad_nonce_size -> true
    end
  end).

prop_aead_xchacha20poly1305_ietf_key_size_fail() ->
  ?FORALL({Msg, Ad, Nonce, UnderSizedKey, OverSizedKey},
          {binary(), binary(), binary(24), binary(31), binary(33)},
  begin
    try
        soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, UnderSizedKey),
        false
    catch
        error:bad_key_size -> true
    end,
    try
        soda_api:aead_xchacha20poly1305_ietf_decrypt(Msg, Ad, Nonce, UnderSizedKey),
        false
    catch
        error:bad_key_size -> true
    end,
    try
        soda_api:aead_xchacha20poly1305_ietf_encrypt(Msg, Ad, Nonce, OverSizedKey),
        false
    catch
        error:bad_key_size -> true
    end,
    try
        soda_api:aead_xchacha20poly1305_ietf_decrypt(Msg, Ad, Nonce, OverSizedKey),
        false
    catch
        error:bad_key_size -> true
    end
  end).

prop_sign_keypair() ->
    ?FORALL({}, {},
      begin
        {ok, _, _ } = soda_api:sign_keypair(),
        true
      end).

prop_sign_seed_keypair() ->
    ?FORALL({Seed}, {binary()},
      begin
        {ok, _, _ } = soda_api:sign_seed_keypair(Seed),
        true
      end).


prop_sign() ->
    ?FORALL({Msg},
        {binary()},
        begin 
            {ok, _Pk, Sk} = soda_api:sign_keypair(),
            case soda_api:sign(Msg, Sk) of 
                B when is_binary(B) -> true;
                _ -> false
            end
        end).

prop_sign_open() ->
    ?FORALL({Msg},
        {non_empty(binary())},
        begin 
            {ok, Pk, Sk} = soda_api:sign_keypair(),
            S = soda_api:sign(Msg, Sk),
            case soda_api:sign_open(S, Pk) of
                {ok, _} -> true;
                {error, _} -> false
            end
        end).


prop_sign_detached() ->
    ?FORALL({Msg},
        {non_empty(binary())},
        begin 
            {ok, _Pk, Sk} = soda_api:sign_keypair(),
            case soda_api:sign_detached(Msg, Sk) of 
                B when is_binary(B) -> true;
                _ -> false
            end
        end).

prop_sign_verify_detached() ->
    ?FORALL({Msg},
        {non_empty(binary())},
        begin 
            {ok, Pk, Sk} = soda_api:sign_keypair(),
            S = soda_api:sign_detached(Msg, Sk),
            case soda_api:sign_verify_detached(S, Msg,  Pk) of
                {ok, _} -> true;
                _ -> false
            end
        end).


%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%
