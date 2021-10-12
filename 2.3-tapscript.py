#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string, sha256
from test_framework.musig import generate_musig_key
from test_framework.script import hash160, SIGHASH_ALL_TAPROOT, tagged_hash, TapLeaf, TaprootSignatureHash, TapTree


# # 2.3 Tapscript
# 

# In this chapter, we introduce tapscript, an updated Bitcoin scripting language which is introduced in [BIP342](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki). Tapscript retains most of the opcodes and evaluation rules applicable to v0 witness scripts, but includes several notable updates described in part 1 of this chapter. The most notable changes in tapscript include signature opcodes which verify BIP340 signatures, and the newly added `OP_CHECKSIGADD` signature opcode, which replaces the legacy `OP_CHECKMULTISIG` operation.
# 
# * __Part 1: Script updates__
#     * Signature opcode updates.
#         * Schnorr verification.
#         * Checksigadd.
#     * Future Versioning
#         * Tapscript
#         * Opcodes
# 
# We also propose a new set of tapscript descriptors in part 2. [Descriptors](https://github.com/bitcoin/bitcoin/blob/cf57e33cc6d95a96f94b259d7680ff9b4f7e22cf/doc/descriptors.md) are a human-readable, high-level template language to describe an individual output or a range of outputs. The proposed Tapscript descriptors include single or multisig (checksigadd) pay-to-pubkey outputs, in combination with hashlocks and time delays.
# 
# * __Part 2: Tapscript descriptors__ (Proposed)
#     * `Pay-to-pubkey` descriptors
#     * `Checksigadd` descriptors
# 
# In part 3, we learn how a tapscript can be committed to a taptweak. [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0342.mediawiki) proposes such script commitments as an alternative output spending path, which is only revealed when spent. Taproot outputs with committed tapscripts are indistinguishable from other segwit v1 outputs. 
# 
# If the internal key of the taproot is a MuSig key, then a committed tapscript is considered an alternative, enforcing spending path, which can impose a separate set of spending conditions independent of the MuSig key. If all participants agree that the locking conditions of the tapscript can be spent, they can collaboratively spend along the MuSig key path, thereby increasing privacy and saving transaction costs.
# 
# * __Part 3: Committing scripts into taptweaks__
#     * TapTweak: Tagged pubkey tweaks
#     * TapLeaf: Tagged tapscript hashes
#     * Spending a single tapscript commitment

# ## Part 1: Script Updates
# 
# ### Schnorr verification with signature opcodes
# 
# The signature opcodes consume the same stack arguments as in Segwit v0, but now verify schnorr signatures as defined in [BIP340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
# 
# * OP_CHECKSIG
#     * Stack arguments consumed: `[public key] [BIP340 signature]`
#     * Pushes 0x01 on success or 0x00 on failure onto the stack.
#     * Requires an empty signature 0x00 to fail.
#     
#     
# * OP_CHECKSIGVERIFY
#     * Stack arguments consumed: `[public key] [BIP340 signature]`
#     * Continues with next opcode or fails script evaluation.

# #### 2.3.1 Example: Pay-to-pubkey tapscript.
# 
# * The pay-to-pubkey tapscript consist of the following script operations:
#     * `[pk] [checksig]`
#     
# * `TapLeaf.construct_pk(ECPubKey)` contructs a pk tapscript.
# * `TapLeaf.script` returns the script opcodes.
# * `TapLeaf.sat` returns witness elements required to satisfy the tapscript.

# In[ ]:


# Generate key pair
privkey, pubkey = generate_bip340_key_pair()

# Generate tapscript
pk_tapscript = TapLeaf().construct_pk(pubkey)

print("Tapscript operations:")
for op in pk_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

print("\nSatisfying witness element:")
for element, value in pk_tapscript.sat:
    print("Witness element type is: {}".format(element))
    print("Signature corresponds to pubkey: {}".format(value.hex()))


# ### Disabled CHECKMULTISIG opcodes
# 
# Legacy k-of-n multisignature opcodes would previously check each of the k signatures against up to n public keys. This is inefficient and disables batch verification of schnorr signatures, since pubkey and signature pairs cannot be known prior to script execution.
# 
# * OP_CHECKMULTISIG
# * OP_CHECKMULTISIGVERIFY

# ### Multisignatures with CHECKSIGADD
# 
# Tapscript replaces the previous checkmultisig signature operation with OP_CHECKSIGADD. 
# 
# This multisignature signature opcode requires the witness to provide a valid or invalid signature for each public key, thereby avoiding the need to waste signature verification operations for each public key in k-of-n multisignature scripts.
# 
# * OP_CHECKSIGADD
#     * Equivalent to: `[OP_ROT][OP_SWAP][OP_CHECKSIG][OP_ADD]`
#     * Enables multisig scripts as shown below.

# ![test](images/tapscript0.jpg)
# 

# ### k-of-n CHECKSIGADD tapscripts
# 
# Unlike legacy multisig, k-of-n checksigadd multisignature tapscripts will consume a stack element for each public key in the output script. This means that unused public keys must be evaluated against a zero witness element.
# 
# For example:
# * Tapscript: `[pk0] [CHECKSIG] [PK1] [CHECKSIGADD] [PK2] [CHECKSIGADD] [2] [NUMEQUAL]`
# * Possible spending witness(es): 
#     * `[sig2]` `[sig1]` `[]`
#     * `[sig2]` `[]` `[sig0]`
#     * `[]` `[sig1]` `[sig0]`
# 
# The disadvantages of k-of-n Checksigadd multisignature scripts include
# * Cost: unused public keys are paid by the spender.
# * Privacy: unused public keys are revealed when tapscript is spent.

# #### 2.3.2 Example: Generating a 2-of-3 checksigadd output
# 
# In this example, we construct a 2-of-3 multisig output with `OP_CHECKSIGADD`.

# In[ ]:


# Generate key pairs
privkey1, pubkey1 = generate_bip340_key_pair()
privkey2, pubkey2 = generate_bip340_key_pair()
privkey3, pubkey3 = generate_bip340_key_pair()

# Generate tapscript
csa_tapscript = TapLeaf().construct_csa(2, [pubkey1, pubkey2, pubkey3])

print("CSA tapscript operations:")
for op in csa_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

# Satisfying witness element.
print("\nSatisfying witness elements:")
for element, value in csa_tapscript.sat:
    print("Witness element type is: {}".format(element))
    print("Signature corresponds to pubkey: {}".format(value.hex()))


# ### k-of-k CHECKSIGADD scripts
# 
# Alternatively, a k-of-n multisig locking condition can be expressed with multiple k-of-k checksigadd tapscripts. This minimizes leakage of unused public keys and can be more cost-efficient for the spender.
# 
# Use the following convenience method to generate k-of-k checksigadd tapscripts from n public keys.
# * `TapLeaf.generate_threshold_csa(k, [key_0, key_1, ..., key_n])`

# ![test](images/tapscript1.jpg)
# 

# #### 2.3.3 Example: 2-of-3 multisig expressed as 2-of-2 checksigadd tapscripts.

# In[ ]:


# Generate key pairs
privkey1, pubkey1 = generate_bip340_key_pair()
privkey2, pubkey2 = generate_bip340_key_pair()
privkey3, pubkey3 = generate_bip340_key_pair()

# Generate tapscripts
pubkeys = [pubkey1, pubkey2, pubkey3]
tapscripts = TapLeaf.generate_threshold_csa(2, pubkeys)

print("2-of-3 multisig expressed as 2-of-2 checkigadd tapscripts:")
for ts in tapscripts:
    print(ts.desc)


# ### Tapscript versioning
# 
# Tapscript allows for future upgrades of individual tapscripts and specific opcodes.
# 
# * Leaf version (commited to TapTree leaf node)
#     * Initial version: `0xC0`
#     * The leaf version is committed to the tapleaf (See Part 3).
# * Success opcodes (allow for future functionality).
#     * 80, 98, 126-129, 131-134, 137-138, 141-142, 149-153, 187-254
#     * Any of these opcodes end script evaluation successfully.

# ## Part 2: Tapscript descriptors
# 
# A tapscript descriptor is a human-readable language expression which maps to a unique output. We propose each tapscript descriptor to be encapsulated by a tapscript tag `ts`, which can be updated in future tapleaf versions. As of [Bitcoin Core #22051](https://github.com/bitcoin/bitcoin/pull/22051), this section is partly out of date as a different taproot descriptor syntax was adopted.  The information provided here is still useful, and any reader wanting an extended bonus exercise is encouraged to submit a PR updating the implementation in this repository to match the syntax adopted by Bitcoin Core.
# * `ts(pk(key))`, `ts(csa(key))`, ...
# 
# ### Combining public keys with hashlocks and delays
# 
# We also propose tapscript descriptors which describe outputs combining public keys with both hashlocks and delays. The following is a brief overview of the hashlock and delay implementations used in this chapter.
# 
# **A hashlock consumes a 32B preimage and checks the hash digest for correctness:**
# 
# 1. A 32B size guard checks that the spending preimage size is exactly 32B.
# 2. A `hash160` operation produces a 20B digest of the pre-image.
# 3. An equality check is performed for the hashed preimage and the hashlock digest.
# 
# Where: `hash160(data) = ripemd160(sha256(data))`
# 
# **Note:** The hashlock contains a size guard (1) to ensure that the preimage in the spending witness cannot be impractically large. Consider the example of an atomic swap between two chains. If the data push limits for the two chains differ, it will be possible that one transaction is spendable and the other is not, even though they feature identical hashlocks. The preimage may simply exceed the data push limit for one of the chains.
# 
# **A delay is implemented with an nSequence check:**
# 
# 1. The `nSequence` field in a spending transaction input encodes a minimum delay between the confirmation of the referenced output and its spending.
# 2. The spending transaction must be encoded with `version >= 2` to activate `nSequence` delay encoding.
# 3. A `checksequenceverify` opcode in a delay-enforcing output script will check the `nSequence` value of the spending transaction input.

# ### Pay-to-pubkey tapscript descriptors
# 
# Next, let us consider specific types of tapscript descriptors. The simplist form of tapscript descriptors are pay-to-pubkey tapscripts. They are spendable by a valid signature witness element, but can be combined with other locking conditions, such as hashlocks and time delays.
# 
# * `ts(pk(key))`
#     * Witness: `[signature]`
#     
#     
# * `ts(pk_hashlock(key, 20B-hash-digest))`
#     * Witness: `[signature]`,`[32B-preimage]`
#     * Hashlock: `hash160(32B-preimage)`
# 
# 
# * `ts(pk_delay(key, delay))`
#     * Witness: `[signature]`
#     * Spendable after delay (with `nSequence > delay`)
#     
#     
# * `ts(pk_hashlock_delay(key, 20B-hash-digest, delay))`
#     * Witness: `[signature]`,`[32B-preimage]`
#     * Hashlock: `hash160(32B-preimage)`
#     * Spendable after delay  (with `nSequence > delay`)

# We also provide pay-to-pubkey tapscript constructors for for the `TapLeaf` class. 
# 
# * `TapLeaf.construct_pk(ECPubKey)`
# * `TapLeaf.construct_pk_hashlock(ECPubKey, 20B-hash-digest)`
# * `TapLeaf.construct_pk_delay(ECPubKey, delay)`
# * `TapLeaf.construct_pk_hashlock_delay(ECPubKey, 20B-hash-digest, delay)`
# 
# The descriptor string can be recalled with:
# * `TapLeaf.desc`
# 
# **Note:** pubkeys in pay-to-pubkey tapscripts can be generated with multi-party schemes such as MuSig.

# #### 2.3.4 Example: Generating a `pk_delay` tapscript
# 
# We construct a `pk_delay` tapscript with the following locking conditions:
# 
# * 2-of-2 MuSig public key
# * Delay of 20 blocks

# In[ ]:


# Generate MuSig key
privkey1, pubkey1 = generate_key_pair()
privkey2, pubkey2 = generate_key_pair()
c_map, pk_musig = generate_musig_key([pubkey1, pubkey2])

if pk_musig.get_y()%2 != 0:
    pk_musig.negate()
    privkey1.negate()
    privkey2.negate()

# Generate pk_delay tapscript
pk_delay_tapscript = TapLeaf().construct_pk_delay(pk_musig, 20)
print("Tapscript descriptor:", pk_delay_tapscript.desc, "\n")

print("Tapscript operations:")
for op in pk_delay_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

print("\nSatisfying witness elements:")
for element, value in pk_delay_tapscript.sat:
    print("{}, {}".format(element, value.hex()))


# ### CHECKSIGADD tapscript descriptors
# 
# A CHECKSIGADD tapscript descriptor is proposed to have the following forms, and can also be combined with hashlocks and delays.
# 
# * `ts(csa(k, [key0, key1, ...]))`
#     * Witness: `[signature], [signature], ...`
#     * Note: for n < m, empty signature elements (zero) must be provided.
#     
# 
# 
# * `ts(csa_hashlock(k, [key0, key1, ...], hash, time))`
#     * Witness: `[signature], [signature], ..., [32B pre-image]`
#     * Hashlock: `hash160(32B-preimage)`
# 
# 
# 
# * `ts(csa_delay(k, [key0, key1, ...], hash, time))`
#     * Witness: `[signature], [signature], ...`
#     * Spendable after delay (with `nSequence > delay`)
# 
# 
# * `ts(csa_hashlock_delay(k, [key0, key1, ...], hash, time))`
#     * Witness: `[signature], [signature], ..., [32B pre-image]`
#     * Hashlock: `hash160(32B-preimage)`
#     * Spendable after delay (with `nSequence > delay`)

# We also provide checksigadd tapscript constructors for for the `TapLeaf` class. 
# 
# * `TapLeaf.construct_csa(k, [ECPubKey, ECPubKey, ...])`
# * `TapLeaf.construct_csa_hashlock(k, [ECPubKey, ECPubKey, ...], 20B-hash-digest)`
# * `TapLeaf.construct_csa_delay(k, [ECPubKey, ECPubKey, ...], delay)`
# * `TapLeaf.construct_csa_hashlock_delay(k, [ECPubKey, ECPubKey, ...], 20B-hash-digest, delay)`
# 
# **Note:** Any single public key in CSA tapscripts can be generated with multi-party schemes such as MuSig.

# #### 2.3.5 _Programming Exercise:_ Generate a 2-of-2 `csa_hashlock_delay` tapscript
# 
# Construct a `csa_hashlock_delay` tapscript with the following locking conditions:
# 
# * 2-of-2 public keys
# * `OP_HASH160` hashlock with the preimage `sha256(b'secret')`
#     * `OP_HASH160` is equivalent to `ripemd160(sha256(preimage))`
# * Delay of 20 blocks

# In[ ]:


# Generate key pairs
privkey1, pubkey1 = generate_bip340_key_pair()
privkey2, pubkey2 = generate_bip340_key_pair()

print("pubkey1: {}".format(pubkey1.get_bytes().hex()))
print("pubkey2: {}\n".format(pubkey2.get_bytes().hex()))

# Method: 32B preimage - sha256(bytes)
# Method: 20B digest - hash160(bytes)
secret = b'secret'
preimage =  # TODO: implement
digest =  # TODO: implement
delay =  # TODO: implement

# Construct tapscript
csa_hashlock_delay_tapscript =  # TODO: implement
print("Descriptor:", csa_hashlock_delay_tapscript.desc, "\n")

print("Tapscript operations:")
for op in csa_hashlock_delay_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

print("\nSatisfying witness elements:")
for element, value in csa_hashlock_delay_tapscript.sat:
    print("{}, {}".format(element, value.hex()))


# ## Part 3: Committing scripts into taptweaks
# 
# ### TapTweaks
# 
# In chapter 2.2, we learned that it is possible to make valid commitments to a public key, which are called taptweaks. A taptweak commitment is computed with a tagged hash using the **TapTweak** tag.
# 
# * **`TapTweak`** = `tagged_hash("TapTweak", commitment_hash)`

# ### Single tapleaf script commitments
# 
# In order to commit a _tapscript_ to a taptweak, we simply compute the `tagged_hash("TapLeaf")` for the tapscript, along with its tapleaf version and then commit the tapleaf to the taptweak.
# 
# * 1. **`TapLeaf`** = `sha256(sha256("TapLeaf") + sha256("TapLeaf") + version|size|script)`
# * 2. **`TapTweak`** = `sha256(sha256("TapTweak") + sha256("TapTweak") + internal_pubkey + TapLeaf)`
# 
# Initial tapscript version:
# * `0xc0`
# 
# Script compact size:
# * `ser_string(Cscript)` returns the `Cscript` with leading compact size bytes.
# * `TapLeaf.script` returns the cscript of the tapscript/tapleaf.

# #### _2.3.6 Programming Exercise:_ Compute the taptweak from a tapscript
# 
# * Use the `tagged_hash()` function to compute a tagged hash.
# * Generate an internal public key.
# * Compute the taptweak from a single `csa_hashlock_delay_tapscript` commitment.

# In[ ]:


privkey_internal, pubkey_internal =  # TODO: implement

# Method: ser_string(Cscript) prepends compact size.
TAPSCRIPT_VER = bytes([0xc0])
tapleaf =  # TODO: implement
taptweak =  # TODO: implement
print("Your constructed taptweak is: {}.".format(taptweak.hex()))


# #### 2.3.7 Example: Compare tagged hash with taptweak constructor
# 
# * A `TapTree()` object can be instantiated with the internal pubkey `key` and taptree root `root`.
# * The `TapTree.construct()` method constructs the triple: `segwit_v1_cscript`, `taptweak`, `cblock_map`.
# * Run the code below to generate the taptweak and compare with your taptweak computation.

# In[ ]:


taptree = TapTree(key=pubkey_internal, root=csa_hashlock_delay_tapscript)
segwit_v1_script, tap_tweak_constructed, control_map = taptree.construct()

assert taptweak == tap_tweak_constructed
print("Success! Your constructed taptweak is correct.")


# ### Spending a single tapscript script commitment
# 
# The witness which can spend a single committed tapscript requires witness data which provides the satisfying elements of the tapscript, and proof that the tapscript is committed to the witness program.
# 
# * `[Stack element(s) satisfying tapscript]`
# * `[Tapscript]`
# * `[Controlblock c]`
# 
# The controlblock c is a single stack element consisting of:
# * `[Tapscript version]`
#     * `0xfe & c[0]`
# * `[Parity bit (oddness of Q's y-coordinate)]`
#     * `0x01 & c[0]`
# * `[Internal Public Key]`
#     * `c[1:33]`
# 

# #### Example 2.3.8:  Generate a single tapscript segwit v1 address
# 
# In this example, we construct segwit v1 output for spending along the single script path. We will reuse the previously generated segwit v1 witness program which has the `csa_hashlock_delay` tapscript committed to it, and encode it to a bech32m address.

# In[ ]:


# Tweak the internal key to obtain the Segwit program 
# ([32B x-coordinate])
taproot_pubkey = pubkey_internal.tweak_add(taptweak) 
taproot_pubkey_b = taproot_pubkey.get_bytes()
program = taproot_pubkey_b
print("Witness program is {}\n".format(program.hex()))

# Create (regtest) bech32m address
version = 0x01
address = program_to_witness(1, program)
print("bech32m address is {}".format(address))


# #### Example 2.3.9: Start Bitcoin Core node and send coins to the taproot address
# 
# Only run setup once, or after a clean shutdown.

# In[ ]:


# Start node
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))


# #### Example 2.3.10: Construct `CTransaction` and populate fields
# 
# We use the `create_spending_transaction(node, txid, version, nSequence)` convenience function.
# 
# * Transaction version must set to 2 if the tapscript has set a spend delay.
# * The input sequence must be encoded with the required spend delay.

# In[ ]:


# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash, version=2, nSequence=delay)

print("Spending transaction:\n{}".format(spending_tx))


# #### _Programming Exercise 2.3.11:_ Sign the transaction
# 
# Note that we must pass the following arguments to `TaprootSignatureHash` for script path spending:
# * `scriptpath`: `True`
# * `tapscript`: `Cscript` of tapscript

# In[ ]:


# Generate the Taproot Signature Hash for signing
sighash = TaprootSignatureHash(spending_tx,
                               [tx.vout[0]],
                               SIGHASH_ALL_TAPROOT,
                               input_index=0,
                               scriptpath=  # TODO: implement
                               script=  # TODO: implement

# Sign with both privkeys
signature1 =  # TODO: implement
signature2 =  # TODO: implement

print("Signature1: {}".format(signature1.hex()))
print("Signature2: {}".format(signature2.hex()))


# #### _Programming Exercise 2.3.12:_ Add the witness and test acceptance of the transaction
# 
# Remember to revisit the satisfying witness elements for `csa_hashlock_delay_tapscript` constructed in exercise 2.3.5:
# * Preimage
# * Signature for pubkey2
# * Signature for pubkey1
# 
# Ensure that the time-lock performs as expected.

# In[ ]:


# Add witness to transaction
# Tip: Witness stack for script path - [satisfying elements for tapscript] [TapLeaf.script] [controlblock]
# Tip: Controlblock for a tapscript in control_map[TapLeaf.script]
witness_elements =  # TODO: implement
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))

print("Spending transaction:\n{}\n".format(spending_tx))

# Test mempool acceptance with and without delay
assert not node.test_transaction(spending_tx)
node.generate(delay)
assert node.test_transaction(spending_tx)

print("Success!")


# #### Example 2.3.13: Shutdown TestWrapper

# In[ ]:


# Shutdown
test.shutdown()


# **Congratulations!** In this chapter, you have:
# 
# - Learned how the tapscript semantics differ from legacy Bitcoin script semantics:
#     - `OP_CHECKSIG` opcodes verify BIP340 signatures instead of ecdsa signatures.
#     - `OP_CHECKMULTISIG` and `OP_CHECKMULTISIGVERIFY` are replaced by `OP_CHECKSIGADD`.
# - Converted a k-of-n threshold signing scheme into a tree of multiple k-of-k threshold signing schemes.
# - Learned how tapscript is versioned.
# - Used output descriptors to specify and construct a tapscript.
# - Learned how a tapscript can be committed as a tweak into a taproot internal public key.
# - Sent coins to a segwit v1 output with a tweaked public key committing to a tapscript, and later spent that output by using the script path.
