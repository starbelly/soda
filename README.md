![Soda](assets/logo-xsmall.png) Soda [![Hex Version](https://img.shields.io/hexpm/v/soda.svg)](https://hex.pm/packages/soda) [![Gitlab-CI](https://gitlab.com/starbelly/soda/badges/master/pipeline.svg)](https://gitlab.com/starbelly/soda/commits/master) [![Travis-CI](https://travis-ci.org/starbelly/soda.svg?branch=master)](https://travis-ci.org/starbelly/soda) [![License](https://img.shields.io/badge/License-MIT-blue.svg)]()
============

-------------------------------------------
***This project is no longer maintained***
-------------------------------------------
Please use and contribute to [enacl](https://github.com/jlouis/enacl/)
-------------------------------------------

![therecanonlybeone](https://media.giphy.com/media/9Jmb2idg10qJSygvTQ/giphy.gif)
 
  
 
Libsodium bindings for Erlang

## About

Soda provides Erlang bindings to the Sodium Crypto Library ([libsodium](https://download.libsodium.org/doc/)).

Working with Soda is simple in both Erlang and Elixr.

- ***Erlang***
```erlang
1> N = soda:nonce(aead_xchacha20poly1305_ietf).
<<115,97,120,157,28,208,118,165,137,95,122,152,195,49,52,
  188,73,136,216,201,77,183,29,144>>
2> {ok, H} = soda:password_hash("foo").
{ok,<<"$argon2id$v=19$m=65536,t=2,p=1$Isq7U9BICzjQKL7HhrpdtA$8WEFXpc6a3ef+DMZELmmxA23xTCQq9CpN6/NPHXBUPg">>}
2> true = soda:password_verify(H, "foo").
true
```

- ***Elixir***
```elixir
iex(1)> n = :soda.nonce(:aead_xchacha20poly1305_ietf)
<<115,97,120,157,28,208,118,165,137,95,122,152,195,49,52,
  188,73,136,216,201,77,183,29,144>>
iex(2)> {:ok, h} = :soda.password_hash("foo")
{:ok,<<"$argon2id$v=19$m=65536,t=2,p=1$Isq7U9BICzjQKL7HhrpdtA$8WEFXpc6a3ef+DMZELmmxA23xTCQq9CpN6/NPHXBUPg">>}
iex(3)> true = :soda.password_verify(h, "foo")
true
```

## Installation

### Rebar3

```erlang
{deps, [{soda, "1.1.1"}]}
```

### Mix

```elixir
def deps do
  [{:soda, "~> 1.1"}]
end
```

## Usage

### Soda

#### nonce/1 

```erlang
1> N = soda:nonce(aead_xchacha20poly1305_ietf).
<<115,97,120,157,28,208,118,165,137,95,122,152,195,49,52,
  188,73,136,216,201,77,183,29,144>>
```

#### rand/1

```erlang
soda:rand(42).
<<83,247,61,202,83,171,99,56,51,108,141,82,255,186,41,26,
  215,4,229,148,72,204,131,248,8,86,196,104,95,...>>
```

#### password_hash/1 and password_verify/2

```erlang
1> {ok, H} = soda:password_hash("thuper thecret").
{ok,<<"$argon2id$v=19$m=65536,t=2,p=1$rPQCfeJLuKMoLei+d5o9uA$7LsyBNEnYVq2JOpTgD2cil+swou5gvewoEjcuQznYq0">>}
2> true = soda:password_verify(H, "thuper thecret").
true
```

#### aead_encrypt/2 and aead_decrypt/4

```erlang
1> {ok, Ciphered, Nonce, Key} = soda:aead_encrypt(<<"Secret Msg">>, <<"Additional Data">>).
{ok,<<183,123,21,95,51,26,85,197,41,226,96,91,26,28,16,
      110,85,123,18,239,29,57,11,30,228,61>>,
    <<238,32,82,106,137,223,37,173,68,177,216,210,169,168,126,
      245,10,247,27,161,127,195,217,24>>,
    <<8,108,139,115,235,95,95,44,128,74,18,186,2,207,2,83,79,
      53,115,239,12,118,198,100,198,...>>}
2> soda:aead_decrypt(Ciphered, <<"Additional Data">>, Nonce, Key).
{ok,<<"Secret Msg">>}
```

#### Generic Hashing



##### Single part

Without a key

```erlang
1> {ok, Hash} = soda_api:hash(<<"Every book is a children's book if the kid can read!">>).
{ok,<<110,213,155,8,43,187,167,80,146,177,214,102,226,62,
      107,0,197,188,250,227,26,127,216,211,82,111,20,...>>}
```

With a key

```erlang
  1> Key = soda:rand(16).
  <<210,27,222,99,117,191,249,46,192,189,137,37,59,128,142,38>>
  2> Data = <<"Every book is a children's book if the kid can read!">>.
  <<"Every book is a children's book if the kid can read!">>
  2> {ok, Hash} = soda_api:hash(Data, Key).
  {ok,<<46,245,69,115,197,167,214,2,175,251,181,113,130,
      234,222,98,228,42,249,24,59,129,29,107,213,124,46,...>>}
```  

##### Multi-part 

Without a key

```erlang
1> {ok, State} = soda:hash_init().
{ok,#Ref<0.3118750307.3589668872.246381>}
2> Msg1 = <<"Any sufficiently complicated concurrent program in another language
contains an ad hoc informally-specified ">>.
<<"Any sufficiently complicated concurrent program in another language contains an ad hoc informally-specified ">>
3> {ok, State1} = soda:hash_update(State, Msg1).
{ok,#Ref<0.3118750307.3589668872.246382>}
4> Msg2 = <<"bug-ridden slow implementation of half of Erlang.">>.
<<"bug-ridden slow implementation of half of Erlang.">>
5> {ok, State2} = soda:hash_update(State1, Msg2).
{ok,#Ref<0.3118750307.3589668872.246383>}
6> {ok, Hash} = soda:hash_final(State2).
{ok,<<213,253,49,236,84,178,244,57,188,147,14,175,172,74,
      105,61,99,4,143,138,246,208,235,82,205,74,211,...>>}
7> Hex = soda:bin2hex(Hash).
<<"d5fd31ec54b2f439bc930eafac4a693d63048f8af6d0eb52cd4ad353e90fbc01">>
```


With a key

```erlang
1> Key = <<"Virding's first rule of programming">>,
<<"Virding's first rule of programming">>,
2> {ok, State} = soda:hash_init(Key).
{ok,#Ref<0.791790418.1979056136.39831>}
3> Msg1 = <<"Any sufficiently complicated concurrent program in another language
contains an ad hoc informally-specified ">>.
<<"Any sufficiently complicated concurrent program in another language contains an ad hoc informally-specified">>
4> {ok, State1} = soda:hash_update(State, Msg1).
{ok,#Ref<0.791790418.1979056136.39832>}
5> Msg2 = <<"bug-ridden slow implementation of half of Erlang.">>.
<<"bug-ridden slow implementation of half of Erlang.">>
6> {ok, State2} = soda:hash_update(State1, Msg2).
{ok,#Ref<0.791790418.1979056136.39833>}
7> {ok, Hash} = soda:hash_final(State2).
{ok,<<103,191,97,168,121,250,16,57,59,220,113,55,230,119,
    126,141,93,102,86,130,143,198,54,102,23,180,219,...>>}
8> Hex = soda_api:bin2hex(Hash).
<<"67bf61a879fa10393bdc7137e6777e8d5d6656828fc6366617b4db25e93bfe41">>
```

### Soda API

 For advanced usage soda provides soda_api

#### AEAD constructions

##### XChaCha20-Poly1305 construction

1. Generate a public nonce
```erlang
1> N = soda_api:randombytes(24).
<<115,97,120,157,28,208,118,165,137,95,122,152,195,49,52,
  188,73,136,216,201,77,183,29,144>>
```

2. Generate a secret key using the soda_api module
```erlang
2> K = soda_api:aead_xchacha20poly1305_ietf_keygen().
<<234,19,163,89,73,193,122,110,11,196,215,227,56,193,126,
  110,228,27,49,107,19,123,43,168,255,60,92,13,49,...>>
```

3. Encrypt a message with some non-confidential additional data and our secret key and nonce
```erlang
  3> C = soda_api:aead_xchacha20poly1305_ietf_encrypt(<<"Hello, Mike?">>, <<"Hello, Joe.">>, N, K ).
  <<218,218,199,94,171,25,110,199,107,224,186,225,52,248,
    185,1,53,39,16,167,91,24,155,31,143,195,89,87>>
```

4. Decrypt the ciphered message using our additional data, nonce, and key
```erlang
  4> D = soda_api:aead_xchacha20poly1305_ietf_decrypt(C, <<"Hello, Joe.">>, N, K).
  <<"Hello, Mike?">>
```

#### Generic Hashing


##### Single part

Without a key

```erlang
1> {ok, Hash} = soda_api:generichash(<<"Every book is a children's book if the kid can read!">>).
{ok,<<110,213,155,8,43,187,167,80,146,177,214,102,226,62,
    107,0,197,188,250,227,26,127,216,211,82,111,20,...>>}
```

With a key

```erlang
1> Key = soda_api:randombytes(16).
<<210,27,222,99,117,191,249,46,192,189,137,37,59,128,142,38>>
2> Data = <<"Every book is a children's book if the kid can read!">>.
<<"Every book is a children's book if the kid can read!">>
3> {ok, Hash} = soda_api:generichash(<<"Every book is a children's book if the kid can read!">>, Key).
{ok,<<46,245,69,115,197,167,214,2,175,251,181,113,130,
    234,222,98,228,42,249,24,59,129,29,107,213,124,46,...>>}
```  

##### Multi-part 

Without a key

```erlang
1> {ok, State} = soda_api:generichash_init().
{ok,#Ref<0.3118750307.3589668872.246381>}
2> Msg1 = <<"Any sufficiently complicated concurrent program in another language
contains an ad hoc informally-specified ">>.
<<"Any sufficiently complicated concurrent program in another language contains an ad hoc informally-specified ">>
3> {ok, State1} = soda_api:generichash_update(State,  Msg1).
{ok,#Ref<0.3118750307.3589668872.246382>}
4> Msg2 = <<"bug-ridden slow implementation of half of Erlang.">>.
<<"bug-ridden slow implementation of half of Erlang.">>
5> {ok, State2} = soda_api:generichash_update(State1, Msg).
{ok,#Ref<0.3118750307.3589668872.246383>}
6> {ok, Hash} = soda_api:generichash_final(State2).
{ok,<<213,253,49,236,84,178,244,57,188,147,14,175,172,74,
    105,61,99,4,143,138,246,208,235,82,205,74,211,...>>}
7> Hex = soda_api:bin2hex(Hash).
<<"d5fd31ec54b2f439bc930eafac4a693d63048f8af6d0eb52cd4ad353e90fbc01">>
```

With a key

```erlang
1> {ok, State} = soda_api:generichash_init(<<"Virding's first rule of programming">>).
{ok,#Ref<0.791790418.1979056136.39831>}
2> Msg1 = <<"Any sufficiently complicated concurrent program in another language
contains an ad hoc informally-specified ">>.
<<"Any sufficiently complicated concurrent program in another language contains an ad hoc informally-specified ">>
3> {ok, State1} = soda_api:generichash_update(State, Msg1).
{ok,#Ref<0.791790418.1979056136.39832>}
4> Msg2 = <<"bug-ridden slow implementation of half of Erlang.">>.
<<"bug-ridden slow implementation of half of Erlang.">>
5> {ok, State2} = soda_api:generichash_update(State1, Msg2).
{ok,#Ref<0.791790418.1979056136.39833>}
6> {ok, Hash} = soda:generichash_final(State2).
{ok,<<103,191,97,168,121,250,16,57,59,220,113,55,230,119,
    126,141,93,102,86,130,143,198,54,102,23,180,219,...>>}
7> Hex = soda_api:bin2hex(Hash).
<<"67bf61a879fa10393bdc7137e6777e8d5d6656828fc6366617b4db25e93bfe41">>
```

## Reference

 - [libsodium](https://download.libsodium.org/doc/)

## Inspirado

- [jlouis/enacl](https://github.com/jlouis/enacl)
