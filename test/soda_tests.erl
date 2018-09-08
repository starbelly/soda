-module(soda_tests).
-compile(export_all).
-include_lib("eunit/include/eunit.hrl").
-define(AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES, 24).
-define(AEAD_XCHACHA20POLY1305_IETF_KEYBYTES, 32).
-define(AEAD_XCHACHA20POLY1305_IETF_ABYTES, 24).
-define(AEAD_XCHACHA20POLY1305_IETF_MESSAGEBYTES_MAX, 24).

% Version <= 0.1.0 had would segv on mac os (at least) given plain text as an
% input for ciphered text due to calling enif_release_binary/1 when there was
% nothing to free. Reported and test provided by @1ma 
regession1_oom_failure() ->  
    N = soda:nonce(aead_xchacha20poly1305_ietf),
    K = soda:rand(32),
    {error, out_of_memory} = soda_api:aead_xchacha20poly1305_ietf_decrypt(<<"Hello, Mike?">>, <<"Hello, Joe.">>, N, K).

nonce_test() -> 
    Props = [
         {aead_xchacha20poly1305_ietf, ?AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES}
        ],
    Pred = fun({N,S}) -> erlang:size(soda:nonce(N)) == S end, 
    [] = lists:dropwhile(Pred, Props).

password_hash_test() ->
    {ok, Hash} = soda:password_hash(<<"soda">>),
    is_binary(Hash).

pwhash_str_verify_test() ->
    {ok, HashStr} = soda_api:pwhash_str(<<"thuper thecret">>),
    soda:password_verify(HashStr, <<"thuper thecret">>).

rand_test() ->
    is_binary(soda:rand(16)).

rand_neg_int_fail_test() ->
    try
        soda:rand(-16),
        false
    catch
        error:badarg          -> true;
        error:function_clause -> true
    end.
