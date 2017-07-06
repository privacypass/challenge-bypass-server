## Blind Token Daemon

This is the server implementing the second revision of the Cloudflare blinded tokens protocol. For a description of the original protocol and motivations, see the [challenge bypass specification](https://github.com/cloudflare/challenge-bypass-specification) or our talk at [Real World Crypto 2017](https://speakerdeck.com/gtank/solving-the-cloudflare-captcha-rwc2017).

The protocol is based on a variant of an OPRF [password management scheme](https://eprint.iacr.org/2016/144) by Jarecki, Kiayias, Krawczyk and Xu. When adapted to our needs, this scheme allows us to achieve the same goals using faster primitives, less bandwidth, and simpler secret-key operational logistics compared to the earlier RSA-based protocol.

## Quickstart

To run the server:

`go run server/main.go --key testdata/p256-key.pem`

To demo token issuance:

`cat testdata/bl_sig_req | nc localhost 2416`

For a full client implementation, see the [browser extension](https://github.com/cloudflare/challenge-bypass-extension).

### Definitions

A **message authentication code (MAC)** on a message is a keyed authentication tag that can be only be created and verified by the holder of the key.

A **pseudorandom function** is a function whose output cannot be efficiently distinguished from random output. This is a general class of functions; concrete examples include hashes and encryption algorithms.

An **oblivious pseudorandom function (OPRF)** is a two-party protocol between sender *S* and receiver *R* for securely computing a pseudorandom function *f_k(·)* on key *k* contributed by *S* and input *x* contributed by *R*, in such a way that receiver *R* learns only the value *f_k(x)* while sender *S* learns nothing from the interaction.

In this protocol, the Cloudflare edge is the "sender" holding k and the inputs x are the tokens. So the clients don't learn our key and we don't learn the token values.

### Protocol sketch

The core difference is that where we previously relied on asymmetric cryptography for signatures, we can instead construct a symmetric exchange in which a secret key known only to the edge is used to create per-token MAC keys for each redemption request in a way that prevents the server from learning the token values and the client from learning the secret key.

Given a group setting and two hashes H_1, H_2, we build a commitment to a random token per request using a secret key k held by the edge servers. H_1 and H_2 are hash functions onto, respectively, the group and {0, 1}^λ where λ is a security parameter.

1. Client generates random token `x` and a blinding factor `r`
2. Client calculates `a = H_1(x)^r` and sends `a` to the edge along with a CAPTCHA solution
3. Edge validates the solution and computes `b = a^k = H_1(x)^(rk)`, returns `b` to client
4. Client unblinds b to retrieve `n = b^(1/r) = H_1(x)^k`. Now both the server and the client can calculate `H_2(x, n)` as a shared key for the MAC.
5. When the client wants to redeem a token it presents `(x, MAC(request-binding-data))` where `request-binding-data` is made of information observable by the edge that is unique(ish) to that particular request.
6. The server uses `x` as a double-spend index and recalculates `n` using its secret key. Then it can validate the MAC using the shared key.
7. We know that a matching commitment value is valid because generating it requires access to `k`.

We prevent the edge from tracking users by tagging with unique keys using batch discrete-logarithm equality proofs (which are implemented but not yet deployed).

### Benefits vs blind-RSA protocol

- 10x savings in token size (~256 bits instead of ~2048)
- Simpler & faster primitives (also: available in-browser via SJCL)
- No need for public-key encryption at all, since the derived shared key used to calculate each MAC is never transmitted and cannot be calculated without knowledge of the edge key or the client's blinding factor.
- The only secret to be managed is a 32-byte scalar.
- Easier key rotation. Instead of managing RSA certificates with pinning or transparency, we can publish/pin the commitment component of a DLEQ proof to allow clients to positively verify they're in the same anonymity set with regard to k as everyone else. Alternatively or additionally, if we publish historical k values then auditors who save their b results can check our honesty.
