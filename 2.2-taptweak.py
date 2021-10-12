#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import random
from io import BytesIO

import util
from test_framework.address import program_to_witness
from test_framework.key import ECKey, ECPubKey, SECP256K1_ORDER, generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce, int_or_bytes
from test_framework.messages import COutPoint, CTxIn, CTxInWitness, CTxOut, sha256
from test_framework.musig import generate_musig_key, aggregate_schnorr_nonces, sign_musig, aggregate_musig_signatures, musig_digest
from test_framework.script import CScript, CTransaction, OP_RETURN, SIGHASH_ALL_TAPROOT, TaprootSignatureHash, tagged_hash


# # 2.2 TapTweak
# 
# * Part 1: Tweaking the public key; commitment schemes with tweaks
# * Part 2: Spending a (tweaked) taproot output along the key path
# * Part 3 (Case Study): contract commitments
# 
# The linear property of BIP340 means that we can encode a commitment into a public key, and then reveal that commitment when signing with the private key. We do that by _tweaking_ the private key with the commitment, and using the associated _tweaked_ pubkey. When signing, we can reveal that the original keys were tweaked by the commitment.
# 
# In part 1, we'll learn about how private/public key pairs can be tweaked, and how we can use that to create a secure commitment scheme. In part 2, we'll create a segwit v1 output and spend it along the key path, using a tweaked private and public key. Part 3 of this chapter is a case study, showing how pay-to-contract with tweaked keys can be used instead of OP_RETURN outputs to create timestamped commitments.

# ## Part 1: Tweaking the public key
# 
# Instead of using our original public key as the witness program, we use a tweaked public key.
# 
# * `[01] [32B Tweaked Public Key]`
# 
# Tweaking a public key means to alter it with a value (the tweak) such that it remains spendable with knowledge of the original private key and tweak.
# 
# * `x` / `P`: Original private key / public key pair
# * `t` / `T`: Tweak value / tweak point
# * Output script: `[01] [P + T]` = `[01] [xG + tG]`
# * Spendable by the tweaked private key: `x + t`
# 
# An observer cannot distinguish between a tweaked and untweaked public key.

# #### Example 2.2.1: Signing with a tweaked keypair
# 
# In this example, we generate a key pair as before, and then tweak both the private key and public key. We then sign with the tweaked private key and verify that the signature is valid.
# 
# A _tweak_ is positive scalar value `t` where `0 < t < SECP256K1_ORDER`. There is an associated tweak point `T` such that `T = t*G`.
# 
# The private key is tweaked by the tweak scalar: `x' = x + t` and the public key is tweaked by the tweak point: `P' = P + T`.
# 
# The tweaked private key `x'` can be used to produce a valid signature for the tweaked pubkey `P'`.

# In[ ]:


# Generate a key pair
privkey, pubkey = generate_bip340_key_pair()

print("Private key: {}\nPublic key: {}\n".format(privkey.secret, pubkey.get_bytes().hex()))

# Generate a random tweak scalar 0 < t < SECP256K1_ORDER and derive its associated tweak point
tweak = random.randrange(1, SECP256K1_ORDER)
tweak_private = ECKey().set(tweak)
tweak_point = tweak_private.get_pubkey()
print("Tweak scalar: {}\nTweak point: {}\n".format(tweak_private.secret, tweak_point.get_bytes().hex()))

# Derive the tweaked private key and public key
privkey_tweaked = privkey + tweak_private
pubkey_tweaked = pubkey + tweak_point
print("Tweaked private key: {}\nTweaked pubkey: {}\n".format(privkey_tweaked.secret, pubkey_tweaked.get_bytes().hex()))

# Sign the message with tweaked key pair and verify the signature
msg = sha256(b'msg')
sig = privkey_tweaked.sign_schnorr(msg)
assert pubkey_tweaked.verify_schnorr(sig, msg)
print("Success!")


# #### _Programming Exercise 2.2.2:_  Signing with a tweaked 2-of-2 MuSig key pair
# 
# In this exercise, we tweak an MuSig aggregate pubkey, and then sign for it using the individual participant keys. The MuSig pubkey aggregation step is done for you.
# 
# _Question: How is the tweak incorporated into the final signature?_

# In[ ]:


# Generate key pairs
privkey1, pubkey1 = generate_key_pair()
privkey2, pubkey2 = generate_key_pair()

# Create an aggregate MuSig pubkey
c_map, agg_pubkey = generate_musig_key([pubkey1, pubkey2])

# Apply challenge factors to keys
privkey1_c = privkey1 * c_map[pubkey1]
privkey2_c = privkey2 * c_map[pubkey2]
pubkey1_c = pubkey1 * c_map[pubkey1]
pubkey2_c = pubkey2 * c_map[pubkey2]

# Negate if needed
if agg_pubkey.get_y()%2 != 0:
    agg_pubkey.negate()
    privkey1_c.negate()
    privkey2_c.negate()
    pubkey1_c.negate()
    pubkey2_c.negate()
    
# Tweak musig public key
# Method: ECPubKey.tweak_add()
tweak = random.randrange(1, SECP256K1_ORDER)
agg_pubkey_tweaked =  # TODO: implement

# Nonce generation & aggregation
# Remember to negate the individual nonce values if required
# Method: generate_schnorr_nonce()
# Method: aggregate_schnorr_nonces()
k1 =  # TODO: implement
k2 =  # TODO: implement
R_agg, negated =  # TODO: implement
if negated:
    # TODO: implement

# Signing and signature aggregation
msg = sha256(b'msg')

# Sign individually and then aggregate partial signatures. A factor (e * tweak)
# needs to be added to the list of partial signatures
# Method: sign_musig(private_key, nonce_key, nonce_point, public_key, msg)
# Method: aggregate_musig_signatures(partial_signature_list, aggregate nonce)
e = musig_digest(R_agg, agg_pubkey_tweaked, msg)
s1 =  # TODO: implement
s2 =  # TODO: implement
sig_agg =  # TODO: implement

assert agg_pubkey_tweaked.verify_schnorr(sig_agg, msg)
print("Success!")


# ## Commitment schemes with tweaks
# 
# Taproot uses the tweak as a commitment for spending script paths. However, simply applying the committed value as a public key tweak is not sufficient, as this does not represent a secure cryptographic commitment.
# 
# ![test](images/taptweak0.jpg)
# 
# Instead, the committed value must first be hashed with the untweaked public key point. This commitment scheme is called *pay-to-contract*. **It does not allow the modification of a committed value for a given public key point Q.**

# #### Example 2.2.3: Tweaking a public key Q with commitment data
# 
# In this example we demonstrate an insecure commitment scheme. The committed value `c` can be trivially modified to `c'`, and by setting `x'` to `x + c - c'`, the public key point equation `Q = x'G + c'G` still holds.
# 
# First, we commit a contract between Alice and Bob and then demonstrate how this unsafe commitment can be changed.
# 
# * The initial committed contract is: `Alice agrees to pay 10 BTC to Bob`

# In[ ]:


# Alice generates a key pair
x_key, P_key = generate_key_pair()
print("Private key: {}\nPublic key: {}\n".format(x_key.secret, P_key.get_bytes().hex()))

# Alice generates the tweak from the contract
contract = "Alice agrees to pay 10 BTC to Bob"
t = sha256(contract.encode('utf-8'))
print("Tweak from original contract: {}\n".format(t.hex()))

# Alice tweaks her key pair
Q_key = P_key.tweak_add(t)
q_key = x_key.add(t)
print("Tweaked private key: {}\nTweaked public key: {}\n".format(q_key.secret, Q_key.get_bytes().hex()))

# Alice produces a valid signature for this tweaked public key
msg = sha256(b'I agree to the committed contract')
sig = q_key.sign_schnorr(msg)

# Bob can verify that sig is a valid signature for the public key Q:
verify_sig = Q_key.verify_schnorr(sig, msg)
print("Alice has produced a valid signature for Q: {}".format(verify_sig))

# Alice provides the untweaked public key P to Bob.
# Bob believes he can verify that the signature committed to the tweak t:
verify_tweak = P_key.tweak_add(sha256(contract.encode('utf-8'))) == Q_key
print("The signature appears to commit to '{}': {}".format(contract, verify_tweak))


# #### Example 2.2.4: Modifying the commitment tweak of public key Q
# 
# However, note that is possible for Alice to modify this insecure commitment without changing the value of pub key `Q`.
# * The committed contract is changed to : `Alice agrees to pay 0.1 BTC to Bob`

# In[ ]:


# Alice modifies the contract and produces an alternative tweak
alternative_contract = "Alice agrees to pay 0.1 BTC to Bob"
t2 = sha256(alternative_contract.encode('utf-8'))
print("Tweak from original contract: {}".format(t.hex()))
print("Tweak from modified contract: {}\n".format(t2.hex()))

# Alice modifies her original private key and public key
# x2 = x - t2 + t
x_int = x_key.as_int()
t_int = int.from_bytes(t, "big") 
t2_int = int.from_bytes(t2, "big") 
x2_key, P2_key = generate_key_pair((x_int - t2_int + t_int) % SECP256K1_ORDER)

# Alice can still produce a valid signature for Q
msg2 = sha256(b'I agree to the committed contract')
sig2 = q_key.sign_schnorr(msg2)

# Bob can verify that sig is a valid signature for the public key Q:
verify_sig = Q_key.verify_schnorr(sig, msg)
print("Alice has produced a valid signature for Q: {}".format(verify_sig))

# Alice claims that P2 is the untweaked public key.
# Bob believes he can verify that the signature committed to the tweak t:
verify_tweak = P2_key.tweak_add(sha256(alternative_contract.encode('utf-8'))) == Q_key
print("The signature appears to commit to '{}': {}".format(alternative_contract, verify_tweak))


# #### Summary of 2.2.3, 2.2.4: Insecure practice of tweaking a public key with commitment data
# 
# We have demonstrated how a simple key tweak with commitment data does not work as a commitment scheme.
# * Tweaking the original public key `P` with commitment data hides the commitment.
# * However, the original public key `P` can be recomputed (`P2`) for any modified commitment, without altering the tweaked public key `Q`.
# 
# To any observer, both original and modified "commitments" appear to be valid for the same public key `Q`.

# #### Example 2.2.5 - Pay-to-contract: Tweaking the pubkey with `H(P|msg)`
# 
# In this example, we demonstrate a _secure_ commitment scheme called pay-to-contract. The private key is tweaked with the scalar `H(P|c)`. Since `P` appears both inside and outside the hash, it isn't possible to solve for a different contract `c` by modifying `x`.
# 
# * Alice can now no longer invalidate her previous contract commitment with Bob.

# In[ ]:


# Alice generates a key pair
x_key, P_key = generate_key_pair()
print("Private key: {}\nPublic key: {}\n".format(x_key.secret, P_key.get_bytes().hex()))

# Alice computes the tweak from H(P|msg)
contract = "Alice agrees to pay 10 BTC to Bob"
t = tagged_hash("TapTweak", P_key.get_bytes() + contract.encode('utf-8'))

# Alice tweaks her key pair
Q_key = P_key.tweak_add(t)
q_key = x_key.add(t)
print("Tweaked private key: {}\nTweaked public key: {}\n".format(q_key.secret, Q_key.get_bytes().hex()))

# Alice signs a valid message
msg = sha256(b'I agree to the committed contract')
sig = q_key.sign_schnorr(msg)

# Bob can verify that sig is a valid signature for the public key Q:
verify_sig = Q_key.verify_schnorr(sig, msg)
print("Alice has produced a valid signature for Q: {}".format(verify_sig))

# Alice provides the untweaked public key P to Bob.
# Bob believes he can verify that the signature committed to the tweak t:
verify_tweak = P_key.tweak_add(t) == Q_key
print("The signature commits to '{}': {}".format(contract, verify_tweak))


# ## Part 2: Spending a (tweaked) taproot output along the key path
# 
# In this exercise, we'll create a segwit v1 output that sends to a tweaked public key. We'll then spend that output along the key path using the tweaked private key.
# 
# Such as spend does not reveal the committed tweak to the observer and is indistinguishable from any other key path spend.

# #### _Programming Exercise 2.2.6:_ Construct taproot output with tweaked public key

# In[ ]:


# Example key pair
privkey = ECKey().set(102118636618570133408735518698955378316807974995033705330357303547139065928052)
internal_pubkey = privkey.get_pubkey()

if internal_pubkey.get_y()%2 != 0:
    privkey.negate()
    internal_pubkey.negate()

# Example tweak
taptweak = bytes.fromhex('2a2fb476ec9962f262ff358800db0e7364287340db73e5e48db36d1c9f374e30')

# Tweak the private key
# Method: ECKey.add()
tweaked_privkey = # TODO: implement

# Tweak the public key
# Method: use tweak_add()
taproot_pubkey =  # TODO: implement
taproot_pubkey_b =  # TODO: implement

# Derive the bech32 address
# Use program_to_witness(version_int, pubkey_bytes)
address =  # TODO: implement

assert address == "bcrt1pjnux0f7037ysqv2aycfntus0t606sjyu0qe2xqewlmhulpdujqeq2z4st9"
print("Success! Address: {}".format(address))


# #### Example 2.2.7: Start Bitcoin Core node and send coins to the taproot address
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


# #### Example 2.2.8: Construct `CTransaction` and populate inputs
# 
# We use the `create_spending_transaction(node, txid)` convenience function.

# In[ ]:


# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash)
print("Spending transaction:\n{}".format(spending_tx))


# #### _Programming Exercise 2.2.9:_ Spend taproot output with key path

# In[ ]:


# Sign transaction with tweaked private key
# Method: TaprootSignatureHash(tx, output_list, hash_type=int, input_index=int, scriptpath=bool)
sighash =  # TODO: implement
sig =  # TODO: implement

# Add witness to transaction
spending_tx.wit.vtxinwit.append(CTxInWitness([sig]))

# Test mempool acceptance
assert node.test_transaction(spending_tx)
print("Success!")


# #### _Shutdown TestWrapper_

# In[ ]:


# Shutdown
test.shutdown()


# ## Part 3 (Case Study): Contract commitments
# 
# Alice currently commits contracts with Bob to unspendable OP_RETURN outputs, which contain 32B proof-of-existence commitments. Although this is a standard output with a zero amount, several disadvantages remain:
# 
# * Committing data to an OP_RETURN output requires an additional output with a zero amount, resulting in a higher transaction fees.
# * The OP_RETURN output reveals the presence of a data commitment to any on-chain observer. This reduces the privacy of Alice's commitments.
# 
# In this chapter, we'll show how Alice can move her contract commitments to public key tweaks to reduce fees and improve the privacy of her commitments.

# ### Committing contract data to an OP_RETURN output
# 
# We'll first show Alice's current setup: An OP_RETURN script containing commitment data.

# #### Example 2.2.10: Create the contract commitment

# In[ ]:


contract_bytes = "Alice pays 10 BTC to Bob".encode('utf-8')
commitment_bytes = sha256(contract_bytes)
print("The contract commitment is: {}".format(commitment_bytes.hex()))


# #### Example 2.2.11: Start Bitcoin Core node and construct an unspent output
# 
# Only run once, or after a clean shutdown. This constructs an unspent outpoint for example 2.2.12. 

# In[ ]:


# Start node
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and send these to a new wallet address
node.generatetoaddress(101, node.getnewaddress(address_type="bech32"))

# Fetch the oldest unspent outpoint in the Bitcoin Core wallet
unspent_txid = node.listunspent(1)[-1]["txid"]
unspent_outpoint = COutPoint(int(unspent_txid,16), 0)

print("Unspent coin: txid:{}, n:{}".format(unspent_outpoint.hash, unspent_outpoint.n))


# #### Example 2.2.12: Create and broadcast a transaction with an OP_RETURN output
# 
# We now construct a zero-value OP_RETURN output which contains the commitment data of Alice's contract with Bob. We also add a regular P2WPKH output back to Alice to return the funds from the transaction input (less the transaction fee).

# In[ ]:


# Construct transaction spending previously generated outpoint
op_return_tx = CTransaction()
op_return_tx.nVersion = 1
op_return_tx.nLockTime = 0
op_return_tx_in = CTxIn(outpoint=unspent_outpoint, nSequence=0)
op_return_tx.vin = [op_return_tx_in]

# Output 0) Alice's change address
address_alice = node.getnewaddress(address_type="bech32")
p2wpkh_output_script = bytes.fromhex(node.getaddressinfo(address_alice)['scriptPubKey'])
p2wpkh_output_amount_sat = 4_950_000_000  # remove transaction fee from output amount
p2wpkh_output = CTxOut(nValue=p2wpkh_output_amount_sat, scriptPubKey=p2wpkh_output_script)

# Output 1) OP_RETURN with Alice's commitment
op_return_output_script = CScript([OP_RETURN, commitment_bytes])
op_return_output = CTxOut(nValue=0, scriptPubKey=op_return_output_script)

# Populate transaction with p2pkh and OP_RETURN outputs and add valid witness
op_return_tx.vout = [p2wpkh_output, op_return_output]
op_return_tx_hex_signed = node.signrawtransactionwithwallet(hexstring=op_return_tx.serialize().hex())['hex']

# Confirm details of the OP_RETURN output
op_return_tx_decoded = node.decoderawtransaction(op_return_tx_hex_signed)
op_return_vout = op_return_tx_decoded['vout'][1]
print("The OP_RETURN output script is: {}".format(op_return_vout['scriptPubKey']['asm']))
print("The OP_RETURN output value is: {}".format(int(op_return_vout['value'])))

# Note the total weight of the transaction with a dedicated OP_RETURN commitment output
print("The total transaction weight is: {}\n".format(op_return_tx_decoded['weight']))

# Test mempool acceptance
print(node.testmempoolaccept(rawtxs=[op_return_tx_hex_signed], maxfeerate=0))
assert node.testmempoolaccept(rawtxs=[op_return_tx_hex_signed], maxfeerate=0)[0]['allowed']
print("Success!")


# ### Committing contract data with the pay-to-contract scheme
# 
# Next, we will commit Alice's contract to a spendable pay-to-pubkey output with the pay-to-contract commitment scheme.

# #### _Programming Exercise 2.2.13:_ Generate segwit v1 address for a pay-to-contract public key
# 
# Commit the contract to Alice's public key with the pay-to-contract commitment scheme, and then generate the corresponding segwit v1 address.

# In[ ]:


# Generate a key pair
privkey, pubkey = generate_bip340_key_pair()

# Generate the pay-to-contract tweak
# Hint: Use tagged_hash("TapTweak", P + bytes)
contract_bytes = "Alice pays 10 BTC to Bob".encode('utf-8')
tweak = int_or_bytes( # TODO: implement
tweak_private, tweak_point = # TODO: implement

# Tweak Alice's key pair with the pay-to-contract tweak
tweaked_pubkey = # TODO: implement
tweaked_privkey = # TODO: implement

# Generate the segwit v1 address
tweaked_pubkey_data = # TODO: implement
tweaked_pubkey_program = # TODO: implement
version = 1
address = program_to_witness(version, tweaked_pubkey_program)
print("Address encoding the segwit v1 output: ", address)


# #### Example 2.2.14: Create a transaction with the Bitcoin Core wallet sending funds to the segwit v1 address
# 
# The pay-to-contract output encoded in the segwit v1 address holds spendable value just like a regular, untweaked public key. It can be spent with the tweaked private key, as we learned in part 2 of this chapter.

# In[ ]:


# Generate coins and send to segwit v1 address containing the pay-to-contract public key
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nSent to {}\n".format(tx.hash, address))
print("Transaction weight with pay-to-contract: {}".format(node.decoderawtransaction(tx.serialize().hex())['weight']))
print("Transaction weight with OP_RETURN: {}\n".format(op_return_tx_decoded['weight']))


# #### _Shutdown TestWrapper_

# In[ ]:


# Shutdown
test.shutdown()


# **Congratulations!** In this chapter, you have:
# 
# - Learned how to tweak a public/private key pair with a value.
# - Created an _insecure_ commitment scheme (by tweaking the keys with the raw commitment value) and a _secure_ commitment scheme (by tweaking with a hash of the commitment and the public key).
# - Sent coins to a segwit v1 output with a tweaked public key, and later spent that output by signing with the tweaked private key.
# - Improved cost and privacy of a contract commitment by moving it from an unspendable OP_RETURN output to a pay-to-contract public key.
