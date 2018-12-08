-module(prop_soda).
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
prop_rand() ->
  ?FORALL({I},{non_neg_integer()},
  begin
    is_binary(soda:rand(I))
  end).

prop_rand_neg_int_fail() ->
  ?FORALL({I},{neg_integer()},
  begin
    try
        soda:rand(I),
        false
    catch
        error:badarg          -> true;
        error:function_clause -> true
    end    
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


prop_aead() ->
    ?FORALL({Msg, Ad}, {non_empty(binary()), non_empty(binary())},
            begin
                {ok, Ct, N, K} = soda:aead_encrypt(Msg, Ad),
                {ok, M} = soda:aead_decrypt(Ct, Ad, N, K),
                equals(Msg, M)
            end).

prop_hash() ->
    ?FORALL({Msg, Key, Size}, {non_empty(binary(24)), non_empty(binary(24)),
                               range(32, 64)},
            begin
                {ok, Bin} = soda:hash(Msg, Key, Size),
                true = is_binary(Bin)
            end).

prop_hash_multi() ->
    ?FORALL({Key, Msg1, Msg2, Size1, Size2}, {non_empty(binary(24)), non_empty(binary(32)),
                                      non_empty(binary(24)), range(32, 64), range(32, 64)},
            begin
                {ok, Ref} = soda:hash_init(Key, Size1),
                true = is_reference(Ref),
                ok = soda:hash_update(Ref, Msg1),
                ok = soda:hash_update(Ref, Msg2),
                {ok, Hash1} = soda:hash_final(Ref, Size2),
                true = is_binary(Hash1),
                {ok, Ref1} = soda:hash_init(Key, Size1),
                true = is_reference(Ref1),
                ok = soda:hash_update(Ref1, Msg1),
                ok = soda:hash_update(Ref1, Msg2),
                {ok, Hash2} = soda:hash_final(Ref1, Size2),
                true = is_binary(Hash2),
                equals(Hash1, Hash2)
            end).

prop_hash_multi_keylesss() ->
    ?FORALL({Msg1, Msg2, Size1, Size2}, {non_empty(binary(32)),
                                      non_empty(binary(24)), range(32, 64), range(32, 64)},
            begin
                {ok, Ref} = soda:hash_init(Size1),
                true = is_reference(Ref),
                ok = soda:hash_update(Ref, Msg1),
                ok = soda:hash_update(Ref, Msg2),
                {ok, Hash1} = soda:hash_final(Ref, Size2),
                true = is_binary(Hash1),
                {ok, Ref1} = soda:hash_init(Size1),
                true = is_reference(Ref1),
                ok = soda:hash_update(Ref1, Msg1),
                ok = soda:hash_update(Ref1, Msg2),
                {ok, Hash2} = soda:hash_final(Ref1, Size2),
                true = is_binary(Hash2),
                equals(Hash1, Hash2)
            end).


prop_password_hash() ->
    ?FORALL({Pass}, {non_empty(binary())},
            begin
                {ok, Str} = soda:password_hash(Pass),
                is_binary(Str)
            end).

prop_passwd_verify() ->
    ?FORALL({Pass}, {non_empty(binary())},
            begin
                {ok, HashStr} = soda:password_hash(Pass),
                equals(soda:password_verify(HashStr, Pass), true)
            end).

%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%
