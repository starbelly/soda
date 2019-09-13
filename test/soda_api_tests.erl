-module(soda_api_tests).
-compile(export_all).
-include_lib("eunit/include/eunit.hrl").

box_test() ->
    Nonce = soda_api:randombytes(24),
    {ok, BobPk, BobSk} = soda_api:box_keypair(),
    {ok, AlicePk, AliceSk} = soda_api:box_keypair(),
    {ok, C} = soda_api:box(<<"Hola">>, Nonce, AlicePk, BobSk),
    {ok, <<"Hola">>} = soda_api:box_open(C, Nonce, BobPk, AliceSk),
    {error, encrypt_failed} = soda_api:box_open(C, Nonce, BobPk, BobSk),
    {error, decrypt_failed} = soda_api:box_open(C, Nonce, AlicePk, AliceSk),
    ok.

generichash_test() ->
    {ok, Ref} = soda_api:generichash_init(
                                          <<126,137,250,131,34,27,214,236,37,85,39,247,4,219,15,199,168,124,136,97,14,161,249,79,248,169,226,9,120,68,172,129>>),
    {ok, Ref1} =
    soda_api:generichash_update(Ref,<<92,36,247,223,162,10,69,168,141,12,47,139,150,21,89,105,144,130,135,11,72,92,238,115>>),
    {ok, Ref2} =
    soda_api:generichash_update(Ref1,<<136,33,85,58,247,178,184,83,73,113,217,2,2,225,77,49,92,108,144,125,32,143,238,92>>),
    {ok, _Hash} = soda_api:generichash_final(Ref2),
    ok.

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
    {ok, _, _ } = soda_api:sign_keypair(),
    true.

