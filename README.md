![Soda](assets/logo-xsmall.png) Soda [![Hex Version](https://img.shields.io/hexpm/v/soda.svg)](https://hex.pm/packages/soda) [![Gitlab-CI](https://gitlab.com/starbelly/soda/badges/master/pipeline.svg)](https://gitlab.com/starbelly/soda/commits/master) [![Travis-CI](https://travis-ci.org/starbelly/soda.svg?branch=master)](https://travis-ci.org/starbelly/soda) [![coverage report](https://gitlab.com/starbelly/soda/badges/master/coverage.svg)](https://gitlab.com/starbelly/soda/commits/master) [![License](https://img.shields.io/badge/License-MIT-blue.svg)]()
============

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
{deps, [{soda, "0.1.0"}]}
```

### Mix

```elixir
def deps do
  [{:soda, "~> 0.1.0"}]
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

##### aead_encrypt/2 and aead_decrypt/4

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

## Reference

 - [libsodium](https://download.libsodium.org/doc/)

## Inspirado

- [jlouis/enacl](https://github.com/jlouis/enacl)
