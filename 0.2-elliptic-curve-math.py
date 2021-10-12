#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import random
import util
from test_framework.key import generate_key_pair, ECKey, ECPubKey, SECP256K1_FIELD_SIZE, SECP256K1_ORDER


# # 0.2 Elliptic Curve Math (Review)
# 

# Elliptic Curve math involves scalars and points.
# 
# * A scalar is a positive integer which is smaller than the group order, and is denoted by a lower case letter (eg `a`).
# * A point lies on the curve and is denoted by an upper-case letter (eg `C`) or a pair of co-ordinates (eg `(x,y)`).
# 
# In Bitcoin, key pair generation and signing is performed over the secp256k1 curve. All scalars are modulo the group order `SECP256K1_ORDER`, which is a very large number

# ![test](images/ec_math0.jpg)
# 
# _An overview of all operations of scalars and points over elliptic curves._

# ### Classes / Methods for Elliptic Curve Math
# 
# **`Integers`:** All Scalar operations over secp256k1 can be performed with python integers and the modulo `%` operator. 
# 
# Scalar addition, subtraction, multiplication and division over secp256k1 are modulo a large prime number SECP256K1_ORDER.
# 
# * All scalar operations are performed modulo `SECP256K1_ORDER`.
# * Addition: `a + b % SECP256K1_ORDER`
# * Subtraction: `-a = SECP256K1_ORDER - a`
# * Multiplication: `a * b % SECP256K1_ORDER`
# * Division (see [Fermat's little theorem](https://en.wikipedia.org/wiki/Fermat%27s_little_theorem)): `1/b = b ** (SECP256K1_ORDER-2) % SECP256K1_ORDER`
# 
# **`ECKey`:** The Bitcoin Core library provides a private key class which can also perform certain scalar operations.
# 
# * Addition: `a + b`
# * Subtraction: `a - b` 
# * Multiplication: `a * b`
# * Division: `a * 1/b` (See Fermat's little theorem) 
# 
# **`ECPubKey`:** A public key is the private key scalar multiplied by the group's _generator point_ `G`. The following operations are possible with public keys.
# 
# * Addition (of two public keys): `A + B`
# * Subtraction (of one point from another): `A - B` 
# * Multiplication (of a point times a scalar): `A * b`
# * Division (of a point by a scalar): `A * 1/b` (See Fermat's little theorem) 
# 

# ![test](images/ec_math1.jpg)
# 
# _Classes and methods for EC operations provided by the Bitcoin Core test framework._

# #### 0.2.1 Example: Scalar Addition over secp256K1 order
# 
# Addition can be performed with modular arithmetic in python or with the private key class `ECKey`. We can set an `ECKey` object to a certain value, or generate a new private key with the `generate` method.
# 
# In the example below, addition is performed with both integers and the `ECKey` class, and evaluated for equality.

# In[ ]:


# int() operations
# get 2 random numbers a, b
a = random.randrange(1, SECP256K1_ORDER)
b = random.randrange(1, SECP256K1_ORDER)
print("a = {}".format(a))
print("b = {}".format(b))

# use simple addition for a + b but modulo the result to make sure we stay within the SECP256K1_ORDER order
ab = (a + b) % SECP256K1_ORDER
print("\na + b = {}\n".format(ab))

# ECKey() operations
# Use the set() method to instantiate ECKey instances
a_key = ECKey().set(a)
b_key = ECKey().set(b)

ab_key = a_key + b_key

print("a_key private key = {}".format(a_key))
print("b_key private key = {}".format(b_key))
print("\nab_key private key = {}\n".format(ab_key))

# Check operations are equivalent
# Use .secret to retrieve the ECKey's private key 
assert ab_key.secret == ab
print("Success!")


# #### 0.2.2 Example: Scalar Multiplication over secp256K1 order
# 
# In the example below, multiplication is performed with both integers and the `ECKey` class, and evaluated for equality.

# In[ ]:


# int() operations
# get 2 random numbers a, b
a = random.randrange(1, SECP256K1_ORDER)
b = random.randrange(1, SECP256K1_ORDER)
print("a = {}".format(a))
print("b = {}".format(b))

# Use simple multiplication for a * b but modulo the result to make sure we stay within the SECP256K1_ORDER order
ab = (a * b) % SECP256K1_ORDER
print("\na * b = {}\n".format(ab))

# ECkey() operations
# Use the set() method to instantiate ECKey instances
a_key = ECKey().set(a)
b_key = ECKey().set(b)

ab_key = a_key * b_key

print("a_key private key = {}".format(a_key))
print("b_key private key = {}".format(b_key))
print("\nab_key private key = {}\n".format(ab_key))

# Check operations are equivalent
# Use .secret to retrieve the ECKey's private key 
assert ab_key.secret == ab
print("Success!")


# #### 0.2.3 _Programming Exercise:_ Commutative property of scalar operations
# 
# In this exercise we wish to demonstrate the commutative property of scalar addition and multiplication, whilst getting familiarized with both integer modulo operations and the private key `ECKey` methods.
# 
# Consider:
# 
# * `a + b == b + a` over secp256k1
# * `a * b == b * a` over secp256k1

# In[ ]:


a = random.randrange(SECP256K1_ORDER / 2, SECP256K1_ORDER)
a_key = ECKey().set(a) 

b = random.randrange(SECP256K1_ORDER / 2, SECP256K1_ORDER)
b_key = ECKey().set(b) 

# Left: Compute a + b as ints (modulo the sepc256k1 group order)
left_a_plus_b =  # TODO: implement

# Right: Compute b + a as ECKeys
right_b_plus_a =  # TODO: implement

print("Left: {}".format(left_a_plus_b))
print("Right: {}\n".format(right_b_plus_a))

# Left/Right: Assert equality
assert left_a_plus_b == right_b_plus_a.secret

# Left: Compute a * b as ints (modulo the sepc256k1 group order)
left_a_times_b =  # TODO: implement

# Right: Compute b * a as ECKeys
right_b_times_a =  # TODO: implement

print("Left: {}".format(left_a_times_b))
print("Right: {}\n".format(right_b_times_a))

# Left/Right: Assert equality
assert left_a_times_b == right_b_times_a.secret
print("Success!")


# #### 0.2.4 _Programming Exercise:_ Distributivity of scalar operations
# 
# In this exercise we wish to demonstrate the distributivity property of scalar addition and multiplication.
# 
# Consider: `(a - b) * c == a * c - b * c` over SECP256k1

# In[ ]:


a = random.randrange(1, SECP256K1_ORDER)
a_key = ECKey().set(a)

b = random.randrange(1, SECP256K1_ORDER)
b_key = ECKey().set(b)

c = random.randrange(1, SECP256K1_ORDER)
c_key = ECKey().set(c)

# Left: Compute a - b as ints (modulo the sepc256k1 group order)
a_minus_b =  # TODO: implement

# Left: Compute (a - b) * c as ints (modulo the sepc256k1 group order)
left =  # TODO: implement

# Right: Compute a * c - b * c as ECKeys
right =  # TODO: implement

print("Left: {}".format(left))
print("Right: {}".format(right))

# Left/Right: Assert equality
assert left == right.secret
print("\nSuccess!")


# #### 0.2.5 Example: Point Addition over secp256k1
# 
# The public key `ECPubkey` class can be derived from `ECKey` with the `ECKey.get_pubkey` method. 
# 
# In the following example, we perform point addition. Point addition is used to create aggregate MuSig pubkeys.

# In[ ]:


# Generate uses random.randrange(1, SECP256K1_ORDER) similar to what we have done in earlier examples
a = ECKey().generate()

# get_pubkey() generates the pubkey (in the form of an ECPubKey object)
# by multiplying the secret by the generator point G
A = a.get_pubkey()

# Alternatively, use the generate_key_pair() helper function to return a (ECKey, ECPubKey) pair
b, B = generate_key_pair()

# Print the public keys
print("Point A is {}".format(A))
print("Point B is {}".format(B))

# Perform point addition between the two pubkeys
AB = A + B

print("Point (A + B) is {}".format(AB))


# #### 0.2.6  _Programming Exercise:_ Distributivity over scalars and points
# 
# In this exercise we wish to demonstrate the distributivity property of scalar/point operations, whilst getting familiarized with both integer modulo operations and the public key `ECPubKey` methods.
# 
# Consider: `(a - b) * C == a * C + (-b) * C`

# In[ ]:


a = ECKey().generate()
b = ECKey().generate()
c, C = generate_key_pair()

# Left: Compute (a - b) * C  
left =  # TODO: implement

# Right: Compute aC - bC
right =  # TODO: implement

print("Left: {}".format(left))
print("Right: {}".format(right))

# Left/Right: Assert equality
assert left == right
print("\nSuccess!")


# **Congratulations!** You've learned:
# 
# - Scalar addition, subtraction, multiplication and division
# - Point addition and subtraction
# - Multiplying a point by a scalar
# - How to use the `ECKey` and `ECPubKey` classes
