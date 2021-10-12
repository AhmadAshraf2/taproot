#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from test_framework.script import sha256


# # 0.3 Tagged Hashes
# 
# Tagged Hashes are cryptographic hash functions that are used throughout the schnorr/taproot specifications. Their purpose is to make sure that hashes used in one context can't be used in another context. This avoids issues like [CVE-2012-2459](https://en.bitcoin.it/wiki/Common_Vulnerabilities_and_Exposures#CVE-2012-2459), where an internal node in a merkle tree could be reinterpreted as a leaf node, or vice versa.
# 
# [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki) outlines an example concern:
# 
# > For example, without tagged hashing a BIP340 signature could also be valid for a signature scheme where the only difference is that the arguments to the hash function are reordered. Worse, if the BIP340 nonce derivation function was copied or independently created, then the nonce could be accidentally reused in the other scheme leaking the secret key.
# 
# Tagged hash functions are obtained by prefixing the preimage with `sha256(TagName) || sha256(TagName)` and then hashing as normal:
# 
# **`tagged_hash("TagName", data)`** = `sha256(sha256("TagName") + sha256("TagName") + data)`
# 
# The tag name is dependent on context. For example, the hash function in BIP340 uses the tags **BIP0340/aux**, **BIP0340/nonce** and **BIP0340/challenge** and the hash function used for a branch in a taproot tree uses the tag **TapLeaf**.
# 
# The prefixed, context-dependent tag data makes hash collisions between different domains infeasible.
# 
# The BIP340 specification hashes the tag twice because:
# 
# > this is a 64-byte long context-specific constant and the SHA256 block size is also 64 bytes, optimized implementations are possible (identical to SHA256 itself, but with a modified initial state). Using SHA256 of the tag name itself is reasonably simple and efficient for implementations that don't choose to use the optimization.

# #### _0.3.1 Programming Exercise:_ Implement a tagged hash function
# Complete the implementation of the `tagged_hash` function in Python.

# In[ ]:


def tagged_hash(tag, input_data):
    # Hash "TagName" using SHA256
    tag_digest = sha256(tag)
    # The preimage becomes sha256("TagName") + sha256("TagName") + data
    preimage =  # TODO: implement
    return sha256(preimage)

h = tagged_hash(b'SampleTagName', b'Input data')

assert h.hex() == "4c55df56134d7f37d3295850659f2e3729128c969b3386ec661feb7dfe29a99c"
print("Success!")


# **Congratulations!** You've learned:
# 
# - What tagged hashes are, and why they're used
# - How to implement tagged hashes
