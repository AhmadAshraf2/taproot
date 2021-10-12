#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce
from test_framework.messages import CTxInWitness, sha256
from test_framework.musig import aggregate_musig_signatures, aggregate_schnorr_nonces, generate_musig_key, sign_musig
from test_framework.script import CScript, CScriptOp, hash160, OP_0, OP_2, OP_CHECKMULTISIG, SegwitV0SignatureHash, SIGHASH_ALL, SIGHASH_ALL_TAPROOT, TaprootSignatureHash


# # 2.1 Taproot Outputs
# 
# * Part 1 (Example): Sending to and spending from a single-signer segwit v1 output
# * Part 2 (Case Study): Migrating from a 2-of-2 P2WSH output to a MuSig segwit v1 output
# 
# In this chapter, we introduce segwit v1 outputs, which are defined in [BIP341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki). Segwit v1 outputs can be spent in two ways:
# 
# * **Key path** spending, which treats the witness program as a public key, and permits spending using a signature from that public key.
# * **Script path** spending, which allows a pre-committed script to be used to spend the output. Script path spending will be fully described in chapters 2.2, 2.3 and 2.4.
# 
# By using the MuSig pubkey and signature aggregation protocol described in chapter 1.2, key path spending can be used to encumber an output to an n-of-n multisig policy in a way that is indistinguishable from a single-key output and spend.
# 
# Part 1 of this chapter is an example of sending funds to a segwit v1 address using the Bitcoin Core wallet, and then manually constructing a transaction that spends that output using the new BIP341 key path spending rules.
# 
# Part 2 of this chapter is a case study, showing how using a segwit v1 output with MuSig can provide cost and privacy benefits over using a segwit P2WSH output.

# ## Part 1 (Example): Single-signer segwit v1 output
# 
# Segwit v1 follows the same output script pattern as segwit v0:
# 
# * Segwit output: **`[1B Version]` `[segwit program]`**
# * Segwit v0 output: **`[00]` `[20-Byte public key digest]`** (P2WPKH) or **`[00]` `[32-Byte script digest]`** (P2WSH)
# * Segwit v1 output: **`[01]` `[32-Byte public key]`**

# ### Spending a segwit v1 output with the key path
# 
# Unlike segwit v0 outputs, v1 outputs look the same for script or key paths(unlike v0 which separates into P2WPKH and P2WSH). In this chapter we will focus on spending the key path.
# 
# ![test](images/segwit_version1_0.jpg)
# 
# The output can be spent along the **key path** by providing a valid signature for the pubkey in the output's scriptPubKey. The spending witness is simply **`[sig]`**.
# 
# The output can be spent along the **script path** if public key was tweaked with a valid taproot. See chapters 2.2 and 2.3 for further details.

# #### 2.1.1 Example: Constructing a segwit v1 output
# 
# In this example, we construct segwit v1 output for spending along the key path. We generate a key pair, encode the public key using the BIP340 and BIP341 pubkey encoding rules, and then encode the witness version and witness program to a bech32m address.

# In[ ]:


# Key pair generation
privkey, pubkey = generate_bip340_key_pair()
print("Pubkey is {}\n".format(pubkey.get_bytes().hex()))

# Create witness program ([32B x-coordinate])
program = pubkey.get_bytes()
print("Witness program is {}\n".format(program.hex()))

# Create (regtest) bech32m address
version = 0x01
address = program_to_witness(version, program)
print("bech32m address is {}".format(address))


# ### Sending funds from the Bitcoin Core wallet
# 
# Next, we send funds to the segwit v1 address that we just generated. We'll create send the funds from a Bitcoin Core wallet, which is able to send outputs to segwit v1 addresses.

# #### Example 2.1.2: Start Bitcoin Core node and send coins to the taproot address
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


# ### Constructing a transaction to spend the segwit v1 output
# 
# We are now going to manually contruct, sign and broadcast a transaction which spends the segwit v1 output.
# 
# To do that we create a `CTransaction` object and populate the data members:
# 
#  * `nVersion`
#  * `nLocktime`  
#  * `tx_vin` (list of `CTxIn` objects)
#  * `tx_vout` (list of `CTxOut` objects)
#  * `tx.wit.vtxinwit` (list of `CTxInWitness` objects)

# #### Example 2.1.3: Construct `CTransaction` and populate fields
# 
# We use the `create_spending_transaction(node, txid)` convenience function.

# In[ ]:


# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash)
print("Spending transaction:\n{}".format(spending_tx))


# #### Example 2.1.4: Sign the transaction with a schnorr signature
# 
# BIP341 defines the following sighash flags:
# * Legacy sighash flags:
#   * `0x01` - **SIGHASH_ALL**
#   * `0x02` - **SIGHASH_NONE**
#   * `0x03` - **SIGHASH_SINGLE**
#   * `0x81` - **SIGHASH_ALL | SIGHASH_ANYONECANPAY**
#   * `0x82` - **SIGHASH_NONE | SIGHASH_ANYONECANPAY**
#   * `0x83` - **SIGHASH_SINGLE | SIGHASH_ANYONECANPAY**
# * New sighash flag:
#   * `0x00` - **SIGHASH_ALL_TAPROOT** same semantics `0x01` **SIGHASH_ALL**
# 
# Append the sighash flag to the signature `[R_x, s]` with the sighash byte if not `0x00`.

# In[ ]:


# Generate the taproot signature hash for signing
# SIGHASH_ALL_TAPROOT is 0x00
sighash = TaprootSignatureHash(spending_tx, [tx.vout[0]], SIGHASH_ALL_TAPROOT, input_index=0)
 
# All schnorr sighashes except SIGHASH_ALL_TAPROOT require
# the hash_type appended to the end of signature
sig = privkey.sign_schnorr(sighash)

print("Signature: {}".format(sig.hex()))


# #### Example 2.1.5: Add the witness and test acceptance of the transaction

# In[ ]:


# Construct transaction witness
spending_tx.wit.vtxinwit.append(CTxInWitness([sig]))

print("Spending transaction:\n{}\n".format(spending_tx))
 
# Test mempool acceptance
node.test_transaction(spending_tx)
print("Success!")


# #### Example 2.1.6: Shutdown the TestWrapper (and all bitcoind instances)

# In[ ]:


test.shutdown()


# ## Part 2 (Case Study): 2-of-2 multisig
# 
# Alice stores her bitcoin using a combination of an offline hardware wallet and online wallet. She currently uses P2WSH 2-of-2 multisig, which has some drawbacks:
# 
# - spending a P2WSH multisig output is more expensive than spending a single signature P2WPKH output, since multiple pubkeys and signatures need to be included in the witness
# - spending from the P2WSH output reveals that the coins were encumbered using a multisig setup. Anyone who transacted with Alice (paid or was paid by) can see this easily, and even entities who do not transact directly with Alice can discover this with some chain analysis. Revealing her wallet setup may be bad for Alice's privacy and safety.
# 
# In this chapter, we'll show how Alice can move to using a MuSig aggregated public key, eventually saving her transaction fees and protecting her privacy.

# ### Spending a segwit v0 P2SH 2-of-2 multisig
# 
# We'll first show Alice's current setup: P2WSH 2-of-2 multisig.

# #### Example 2.1.7: Construct a 2-of-2 P2WSH output
# 
# In this example, we'll construct a 2-of-2 P2WSH output and address

# In[ ]:


# Generate individual key pairs
privkey1, pubkey1 = generate_key_pair()
privkey2, pubkey2 = generate_key_pair()

# Create the spending script
multisig_script = CScript([CScriptOp(OP_2), pubkey1.get_bytes(bip340=False), pubkey2.get_bytes(bip340=False), CScriptOp(OP_2), CScriptOp(OP_CHECKMULTISIG)])

# Hash the spending script
script_hash = sha256(multisig_script)

# Generate the address
version = 0
address = program_to_witness(version, script_hash)
print("bech32m address is {}".format(address))


# #### Example 2.1.8: Start a Bitcoind node and send funds to the segwit v0 address
# 
# We'll use the `generate_and_send_coins()` function.

# In[ ]:


test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))


# #### Example 2.1.9 : Construct CTransaction, sign and check validity
# 
# In this example we:
# - create a `CTransaction` object
# - create signatures for both public keys
# - create a valid witness using those signatures and add it to the transaction
# - test transaction validity

# In[ ]:


# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash)

# Generate the segwit v0 signature hash for signing
sighash = SegwitV0SignatureHash(script=multisig_script,
                                txTo=spending_tx,
                                inIdx=0,
                                hashtype=SIGHASH_ALL,
                                amount=100_000_000)

# Sign using ECDSA and append the SIGHASH byte
sig1 = privkey1.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')
sig2 = privkey2.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')

print("Signatures:\n- {},\n- {}\n".format(sig1.hex(), sig2.hex()))

# Construct witness and add it to the script.
# For a multisig P2WSH input, the script witness is the signatures and the scipt
witness_elements = [b'', sig1, sig2, multisig_script]
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))

print("Spending transaction:\n{}\n".format(spending_tx))

print("Transaction weight: {}\n".format(node.decoderawtransaction(spending_tx.serialize().hex())['weight']))

# Test mempool acceptance
assert node.test_transaction(spending_tx)
print("Success!")


# #### Example 2.1.10: Shutdown the TestWrapper (and all bitcoind instances)

# In[ ]:


test.shutdown()


# ### Spending a segwit v1 output with a MuSig public key
# 
# Now, we'll use Alice's same keys to create a MuSig aggregate key, and spend a segwit v1 output using that aggregate key.

# #### 2.1.11 _Programming Exercise:_ Generate segwit v1 addresses for a 2-of-2 MuSig aggregate pubkey
# 
# In this exercise, we create a 2-of-2 aggregate MuSig public key

# In[ ]:


# Generate a 2-of-2 aggregate MuSig key using the same pubkeys as before
# Method: generate_musig_key(ECPubKey_list)
c_map, agg_pubkey =  # TODO: implement

# Multiply individual keys with challenges
privkey1_c =  # TODO: implement
privkey2_c =  # TODO: implement
pubkey1_c =  # TODO: implement
pubkey2_c =  # TODO: implement

# Negate the private and public keys if needed
if # TODO: implement
    # TODO: implement
    
# Create a segwit v1 address for the MuSig aggregate pubkey
# Method: address = program_to_witness(version_int, program_bytes)
program_musig =  # TODO: implement
address_musig =  # TODO: implement
print("2-of-2 musig: ", address_musig)


# #### Example 2.1.12: Create a transaction in the Bitcoin Core wallet sending an output to the segwit v1 addresses

# In[ ]:


test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address_musig)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address_musig))


# #### Example 2.1.13 : Construct CTransaction and populate fields

# In[ ]:


# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash)
print("Spending transaction:\n{}".format(spending_tx))


# #### 2.1.14 _Programming Exercise:_ Create a valid BIP340 signature for the MuSig aggregate pubkey
# 
# In this exercise, we create a signature for the aggregate pubkey, add it to the witness, and then test that the transaction is accepted by the mempool.

# In[ ]:


# Create sighash for ALL (0x00)
sighash_musig = TaprootSignatureHash(spending_tx, [tx.vout[0]], SIGHASH_ALL_TAPROOT, input_index=0)

# Generate individual nonces for participants and an aggregate nonce point
# Remember to negate the individual nonces if necessary
# Method: generate_schnorr_nonce()
# Method: aggregate_schnorr_nonces(nonce_list)
nonce1 = # TODO: implement
nonce2 = # TODO: implement
R_agg, negated =  # TODO: implement

# Create an aggregate signature
# Method: sign_musig(privkey, nonce, R_agg, agg_pubkey, sighash_musig)
# Method: aggregate_musig_signatures(partial_signature_list, R_agg)
s1 = # TODO: implement
s2 = # TODO: implement
sig_agg =  # TODO:implement
print("Aggregate signature is {}\n".format(sig_agg.hex()))

# Add witness to transaction
spending_tx.wit.vtxinwit.append(CTxInWitness(  # TODO: implement

# Get transaction weight
print("Transaction weight: {}\n".format(node.decoderawtransaction(spending_tx.serialize().hex())['weight']))

# Test mempool acceptance
assert node.test_transaction(spending_tx)
print("Success!")


# ### Benefits of using segwit v1 MuSig over segwit v0 P2WSH
# 
# You can see that the transaction weight of the transaction spending the v1 MuSig output is about 30% lower than the transaction spending the v0 P2WSH output. For larger n-of-n multisig, the weight savings is even larger. Since transaction fees are based on the transaction weight, these weight savings translate directly to fee savings.
# 
# In addition, by using a MuSig aggregate key and signature, Alice does not reveal that she is using a multisignature scheme, which is good for her privacy and security.

# #### Example 2.1.15: Shutdown the TestWrapper (and all bitcoind instances)

# In[ ]:


test.shutdown()


# **Congratulations!** In this chapter, you have:
# 
# - Learned how to create a segwit v1 output and derive its bech32m address.
# - Sent bitcoin to a segwit v1 address, and then constructed a transaction that spends the segwit v1 output back to the wallet using the key path.
# - Shown how using a segwit v1 MuSig output saves fees and improves privacy over using P2WSH multisig.
