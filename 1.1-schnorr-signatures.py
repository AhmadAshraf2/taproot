#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import random
import util
from test_framework.key import generate_key_pair, generate_bip340_key_pair, ECKey, ECPubKey, jacobi_symbol, SECP256K1_FIELD_SIZE, SECP256K1_ORDER
from test_framework.messages import sha256
from test_framework.script import tagged_hash


# # 1.1 Introduction to Schnorr Signatures
# 
# * Part 1: Schnorr Signatures.
# * Part 2: Nonce Generation.

# ## Part 1: Schnorr Signatures
# 
# [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) defines a signature/verifier scheme, as well as pubkey and signature encodings.
# 
# The schnorr signature equation is the following:
# 
# * `S = R + H(x(R)|x(P)|m) * P`
# 
# Signing involves generating a secret nonce first.
# 
# * Generate secret scalar `k`
# 
# Then computing `s` from:
# 
# * `s = k + H(x(R)|x(P)|m) * d`
# 
# The resulting signature is:
# 
# * `x(R), s`

# ![test](images/schnorr0.jpg)

# ### Constraint on the public key, P, and public nonce point, R
# 
# BIP340 defines a new way of encoding elliptic curve points. To make the encoding of a point as compact as possible only the x-coordinate of the point is used (ie: 32 bytes).
# 
# For a given x-coordinate on the secp256k1 curve, there are two possible curve points:
# 
# * `y^2 = x^3 + 7` (Two y-coordinate values for a given x-coordinate)
#     * For `x`, both `(x, y)` and `(x, -y)` are valid curve points (where `-y` is `SECP256K1_FIELD_SIZE - y` since all arithmetic involving coordinates is modulo `SECP256K1_FIELD_SIZE`).
#     * One of the y-coordinates is even, and the other is odd (since `SECP256K1_FIELD_SIZE` is odd).
#     * One of the y-coordinates is a quadratic residue (has a square root modulo the field size), and the other is not.
# 
# BIP340 constrains private key points `k` such that the y-value of R is even. This means that from the `x` co-ordinate, the verifier can unambigiously determine `y`.
# 
# * `k` and `SECP256K1_ORDER - k` have nonce points `R = (x, y)` and `R = (x, -y)` respectively.
# * Only one will have a y-coordinate which is even. If a randomly generated nonce `k` does not yield a valid nonce point `R`, then the signer can negate `k` to obtain a valid nonce.
# 
# The same goes for private key `d` and its corresponding public key, P.

# #### 1.1.1 Example: Calculating a valid nonce

# In[ ]:


# Generate a random value and its assoctiated curve point. We can use the generate_key_pair convenience function.
k, R = generate_key_pair()

# Find y and -y
y = R.get_y()
minus_y = SECP256K1_FIELD_SIZE - y
print("y = {}".format(y))
print("-y = {}\n".format(minus_y))

# One of y and -y will be even and the other will be odd
print("y is {}".format("odd" if y % 2 else "even"))
print("-y is {}\n".format("odd" if minus_y % 2 else "even"))

print("k is {}a valid nonce".format("" if y % 2 == 0 else "not "))
print("-k is {}a valid nonce".format("" if minus_y % 2 == 0 else "not "))


# #### 1.1.2 _Programming Exercise:_ Verify that inverse nonce values `k` and `-k` generate inverse points `R` and `-R`

# In[ ]:


# Generate a random scalar and its associated curve point
k, R =  # TODO: implement

# Find the x- and y-coordinates from R
# Use the get_x() and get_y() methods
R_x =  # TODO: implement
R_y =  # TODO: implement

print("R_x: {}".format(R_x))
print("R_y: {}\n".format(R_y))

# Find k's inverse (SECP256K1_ORDER - k)
# Extract the secret value from k using .secret
minus_k =  # TODO: implement

# Generate the key pair from minus_k using generate_key_pair() function with minus_k as an argument
minus_k_key, minus_R =  # TODO: implement

# Find the x- and y-coordinates from -R
minus_R_x =  # TODO: implement
minus_R_y =  # TODO: implement

print("minus_R_x: {}".format(minus_R_x))
print("minus_R_y: {}\n".format(minus_R_y))

assert R_x == minus_R_x
assert SECP256K1_FIELD_SIZE - R_y == minus_R_y

print("Success!")


# #### 1.1.3 _Programming Exercise:_ Sign a message with Schnorr
# 
# * Sign the message with the provided key pair below.

# In[ ]:


msg = sha256(b'message')

# Generate a private/public key pair
d, P = generate_key_pair()

# Check that public key point has an even Y-coordinate.
# If not, negate d and P.
if # TODO: implement
    d.negate()
    P.negate()

# Generate a nonce scalar and associated nonce point
k, R = generate_key_pair()

# Check that nonce point has an even Y-coordinate.
# If not, negate k
if # TODO: implement
    k.negate()
# Note that there is no need to negate R, since we only use the x value of R below

# Generate s = k + hash(R_x|P_x|msg) * d
# Method: tagged_hash("BIP0340/challenge", bytes) will give you the byte digest tagged hash of the challenge data.
# Turn that digest into a ECKey object called h, and then set s = k + h * d
# Note that ECPubKey.get_bytes() will return the bip340 encoding of a public key which is equivalent 
# to its x-coordinate
R_x_bytes = R.get_bytes()
P_bytes = P.get_bytes()
h_bytes = # TODO: implement
h = ECKey().set(h_bytes)
s = k + h * d

print("R: {}".format(R))
print("s: {}\n".format(s.get_bytes().hex()))

# Generate sig = R_x|s
# Method: get the x bytes from R and concatenate with the secret bytes from s
sig = # TODO: implement

print("Signature: {}\n".format(sig.hex()))

# Verify the signature
assert P.verify_schnorr(sig, msg)

print("Success!")


# Note that a convenience function, `generate_bip340_key_pair`, is provided which will automatically check the evenness of a the generated public-key's y-coordinate and negate both the private and public key if needed.

# ## Part 2: Generating Nonces for schnorr signatures
# 
# So far we have used a random secret nonce for creating schnorr signatures. This has the disadvantage that the the user must rely on the robustness of the random generator for each signing rounds. If the nonce generator is compromised or even biased, the private key can be derived for a given signature and known nonce.
# 
# For **single signer schnorr signatures**, BIP340 proposes the following nonce generation scheme:
# 
# * Given private-public key pair `(d, P)`, message `m` and optional 32 byte random auxiliary data, `a`
# * Let `t` be the byte-wise `XOR` of `bytes(d)` and `tagged_hash("BIP0340/aux", a)`
# * Let `rand = tagged_hash("BIP0340/nonce", t || bytes(P) || m)`
# * `k = int(rand) mod n`

# #### 1.1.4 _Programming Exercise:_ Signing schnorr with a BIP340 generated nonce
# 
# * Create a Schnorr signature with BIP340's nonce scheme
# * Compare this signature to the private key class method `ECKey.sign_schnorr(msg, aux)`

# In[ ]:


msg = sha256(b'message')
aux = sha256(b'random auxiliary data')

# Generate a valid BIP340 priv-pub key pair using the convenience function `generate_bip340_key_pair`
d, P = generate_bip340_key_pair()
print("message = {}".format(msg.hex()))
print("pubkey = {}\n".format(P.get_bytes().hex()))

# t is the byte-wise xor of bytes(d) and tagged_hash("BIP0340/aux", aux)
t = (d.secret ^ int.from_bytes(tagged_hash("BIP0340/aux", aux), 'big')).to_bytes(32, 'big')
rand = tagged_hash("BIP0340/nonce", t + P.get_bytes() + msg)

# Generate the nonce value k and get the nonce point R
k, R = generate_key_pair(rand)

# Check that nonce has an even y coordinate
# If not, negate k
if # TODO: implement
    k.negate()

print("nonce: {}".format(k))
print("nonce point: {}\n".format(R))

# Generate s = k + tagged_hash("BIP0340/challenge", R_x|P_x|msg) * d
# Method: tagged_hash("BIP0340/challenge", bytes) will give you the byte digest
# Turn that digest into a ECKey object called h, and then set s = k + h * d
R_x_bytes = R.get_bytes()
P_bytes = P.get_bytes()
h_bytes =  # TODO: implement
h = ECKey().set(h_bytes)
s = k + h * d

print("R: {}".format(R))
print("s: {}\n".format(s.get_bytes().hex()))

# Generate sig = R_x|s
# Method: get the x bytes from R and concatenate with the secret bytes from s
sig = # TODO: implement

print("Signature: {}\n".format(sig.hex()))

# Generate a signature using the ECKey.sign_schnorr(msg) method
# This generates the nonce deterministically, so should return the same signature
sig2 = d.sign_schnorr(msg, aux)

# Verify and compare signature(s)
assert P.verify_schnorr(sig, msg)
assert P.verify_schnorr(sig2, msg)
assert sig == sig2

print("Success!")


# **Congratulations!** In this chapter, you have:
# 
# - Learned how to determine if a private key results in a valid BIP340 public key 
# - Created and verified a valid schnorr signature for a public key P and message m
# - Generated a nonce using a hash digest of the public key, message and optional auxiliary data
