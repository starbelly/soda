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

prop_passwd() ->
    ?FORALL({Passwd}, {non_empty(binary())},
            begin
                {ok, Str} = soda:passwd(Passwd),
                is_binary(Str)
            end).

prop_passwd_verify() ->
    ?FORALL({Passwd}, {non_empty(binary())},
            begin
                {ok, HashStr} = soda:passwd(Passwd),
                equals(soda:passwd_verify(HashStr, Passwd), true)
            end).

%%%%%%%%%%%%%%%
%%% Helpers %%%
%%%%%%%%%%%%%%%

%%%%%%%%%%%%%%%%%%
%%% Generators %%%
%%%%%%%%%%%%%%%%%%
