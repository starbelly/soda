![Soda](assets/logo-xsmall.png) Soda [![Hex Version](https://img.shields.io/hexpm/v/soda.svg)](https://hex.pm/packages/soda) [![Gitlab-CI](https://gitlab.com/starbelly/soda/badges/master/pipeline.svg)](https://gitlab.com/starbelly/soda/commits/master) [![Travis-CI](https://travis-ci.org/starbelly/soda.svg?branch=master)](https://travis-ci.org/starbelly/soda) [![coverage report](https://gitlab.com/starbelly/soda/badges/master/coverage.svg)](https://gitlab.com/starbelly/soda/commits/master) [![License](https://img.shields.io/badge/License-MIT-blue.svg)]()
============

Sweet libsodium bindings for Erlang and Elixir

## About 

Soda provides bindings to the Sodium crypto library ([libsodium](https://download.libsodium.org/doc/)).

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

### AEAD constructions

#### XChaCha20-Poly1305 construction

1. Generate a public nonce
```erlang
1> N = soda:nonce(aead_xchacha20poly1305_ietf).
<<115,97,120,157,28,208,118,165,137,95,122,152,195,49,52,
  188,73,136,216,201,77,183,29,144>>
```

2. Generate a secret key
```erlang
2> K = soda:aead_xchacha20poly1305_ietf_keygen().
<<234,19,163,89,73,193,122,110,11,196,215,227,56,193,126,
  110,228,27,49,107,19,123,43,168,255,60,92,13,49,...>>
```

3. Encrypt a message with some non-confidential additional data and our secret key and nonce
```erlang
3> C = soda:aead_xchacha20poly1305_ietf_encrypt(<<"Hello, Mike?">>, <<"Hello, Joe.">>, N, K ).
<<218,218,199,94,171,25,110,199,107,224,186,225,52,248,
  185,1,53,39,16,167,91,24,155,31,143,195,89,87>>
```

4. Decrypt the ciphered message using our additional data, nonce, and key
```erlang
4> D = soda:aead_xchacha20poly1305_ietf_decrypt(C, <<"Hello, Joe.">>, N, K).
<<"Hello, Mike?">>
```


## Reference

 - [libsodium](https://download.libsodium.org/doc/)

## Inspirado 

- [jlouis/enacl](https://github.com/jlouis/enacl)
