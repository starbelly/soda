-module(prop_soda).
-include_lib("proper/include/proper.hrl").

-define(AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, 24).
-define(AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 32).
-define(AEAD_XCHACHA20POLY1305_IETF_ABYTES, 24).
-define(AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX, 24).

%%%%%%%%%%%%%%%%%%
%%% Properties %%%
%%%%%%%%%%%%%%%%%%

prop_bin2hex() ->
    ?FORALL({Bin}, {binary()},
            begin
                Hex = soda:bin2hex(Bin),
                is_binary(Hex)
            end).

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
    ?FORALL({Msg, Key}, {non_empty(binary(24)), non_empty(binary(24))},
            begin
                {ok, Bin} = soda:hash(Msg, Key),
                true = is_binary(Bin)
            end).

prop_hash_multi() ->
    ?FORALL({Key, Msg1, Msg2}, {non_empty(binary(24)), non_empty(binary(32)),
                                      non_empty(binary(24))},
            begin
                {ok, State} = soda:hash_init(Key),
                true = is_reference(State),
                {ok, State1} = soda:hash_update(State, Msg1),
                {ok, State2} = soda:hash_update(State1, Msg2),
                {ok, Hash1} = soda:hash_final(State2),
                true = is_binary(Hash1),
                {ok, State3} = soda:hash_init(Key),
                true = is_reference(State3),
                {ok, State4} = soda:hash_update(State3, Msg1),
                {ok, State5} = soda:hash_update(State4, Msg2),
                {ok, Hash2} = soda:hash_final(State5),
                true = is_binary(Hash2),
                equals(Hash1, Hash2)
            end).

prop_hash_multi_keylesss() ->
    ?FORALL({Msg1, Msg2}, {non_empty(binary(32)),
                                      non_empty(binary(24))},
            begin
                {ok, State} = soda:hash_init(),
                true = is_reference(State),
                {ok, State1} = soda:hash_update(State, Msg1),
                {ok, State2} = soda:hash_update(State1, Msg2),
                {ok, Hash1} = soda:hash_final(State2),
                true = is_binary(Hash1),
                {ok, State3} = soda:hash_init(),
                true = is_reference(State3),
                {ok, State4} = soda:hash_update(State3, Msg1),
                {ok, State5} = soda:hash_update(State4, Msg2),
                {ok, Hash2} = soda:hash_final(State5),
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
