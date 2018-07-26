-module(soda_api_tests).
-compile(export_all).
-include_lib("eunit/include/eunit.hrl").

pwhash_test() ->
    {ok, _} = soda_api:pwhash(<<"soda">>, <<"1234567890123456">>),
    ok.

pwhash_fail_test() ->
    {error, bad_salt_size} = soda_api:pwhash(<<"soda">>, <<"salt">>),
    ok.

pwhash_str_test() ->
    {ok, _} = soda_api:pwhash_str(<<"thuper thecret">>),
    ok.

pwhash_str_verify_test() ->
    {ok, HashStr} = soda_api:pwhash_str(<<"thuper thecret">>),
    soda_api:pwhash_str_verify(HashStr, <<"thuper thecret">>).

randombytes_test() ->
    is_binary(soda_api:randombytes(16)).

randombytes_neg_int_fail_test() ->
    try
        soda_api:randombytes(-16),
        false
    catch
        error:badarg          -> true;
        error:function_clause -> true
    end.

sign_keypair_test() ->
    { _, _ } = soda_api:sign_keypair(),
    true.

