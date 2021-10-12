#!/usr/bin/env python
# coding: utf-8

# In[ ]:


from io import BytesIO
import random

import util
from test_framework.key import generate_key_pair, generate_bip340_key_pair, generate_schnorr_nonce, ECKey, ECPubKey, SECP256K1_FIELD_SIZE, SECP256K1, SECP256K1_ORDER
from test_framework.musig import aggregate_musig_signatures, aggregate_schnorr_nonces, generate_musig_key, musig_digest, sign_musig
from test_framework.script import TapLeaf, TapTree, TaprootSignatureHash, SIGHASH_ALL_TAPROOT
from test_framework.address import program_to_witness
from test_framework.messages import CTransaction, COutPoint, CTxIn, CTxOut, CTxInWitness
from test_framework.util import assert_equal


# ## 3.1 Degrading Multisig Output
# 
# In this case study, we consider a degrading multisig output, which provides recovery spending paths if the main wallet keys are lost or cannot sign. This output is expected to spent soon after being created. 
# The recovery spending paths include delays in case the back-up keys are compromised.

# ![test](images/degrading_multisig0.jpg)

# #### Locking conditions
# 
# * **multisig( 3/3 main wallet key )** - spendable immediately; or
# * **multisig( 2/3 main wallet keys + 1/2 backup keys )** - spendable after 3 days; or
# * **multisig( 1/3 main wallet keys + 2/2 backup keys )** - spendable after 10 days.
# 

# #### Signers
# 
# * **Main wallet keys** - Keys A, B, C
# * **Backup keys** - Keys D, E
# 
# #### Privacy Requirements
# 
# No unused public keys should be revealed during spending.
# 
# #### Other considerations
# 
# Since the backup keys are stored on simple HSMs, they are not able to interactively co-sign MuSig aggregate signatures.

# #### _Exercise 3.1.1:_ Determine different signing scenarios and their likelihoods
# 
# **(This is not a coding exercise)**
# 
# Before we construct the Taptree, sketch out different signing scenarios and their likelihoods.

# ##### Spending paths
# 
# _TODO: List spending paths in order of likelihood_
# 
# ##### Sketch out Taproot Descriptors
# 
# _TODO: Sketch out taproot descriptors_
# 

# #### Example 3.1.2: Set up keys for the taproot output
# 
# Here we prepare key pairs for all participants, and create an aggregate MuSig pubkey.

# In[ ]:


# Generate main wallet key pairs
main_privkeyA, main_pubkeyA = generate_bip340_key_pair()
main_privkeyB, main_pubkeyB = generate_bip340_key_pair()
main_privkeyC, main_pubkeyC = generate_bip340_key_pair()
main_pubkeys = [main_pubkeyA.get_bytes().hex(),
                main_pubkeyB.get_bytes().hex(), 
                main_pubkeyC.get_bytes().hex()]

print("Main pubkeys: {}\n".format(main_pubkeys))

# Generate back-up wallet key pairs
backup_privkeyD, backup_pubkeyD = generate_bip340_key_pair()
backup_privkeyE, backup_pubkeyE = generate_bip340_key_pair()
backup_pubkeys = [backup_pubkeyD.get_bytes().hex(),
                  backup_pubkeyE.get_bytes().hex()]

print("Backup pubkeys: {}\n".format(backup_pubkeys))

# 3-of-3 main key (MuSig public key)
c_map, musig_ABC = generate_musig_key([main_pubkeyA, main_pubkeyB, main_pubkeyC])
main_privkeyA_c = main_privkeyA.mul(c_map[main_pubkeyA])
main_privkeyB_c = main_privkeyB.mul(c_map[main_pubkeyB])
main_privkeyC_c = main_privkeyC.mul(c_map[main_pubkeyC])
main_pubkeyA_c = main_pubkeyA.mul(c_map[main_pubkeyA])
main_pubkeyB_c = main_pubkeyA.mul(c_map[main_pubkeyB])
main_pubkeyC_c = main_pubkeyA.mul(c_map[main_pubkeyC])

if musig_ABC.get_y()%2 != 0:
    musig_ABC.negate()
    main_privkeyA_c.negate()
    main_privkeyB_c.negate()
    main_privkeyC_c.negate()
    main_pubkeyA_c.negate()
    main_pubkeyB_c.negate()
    main_pubkeyC_c.negate()

print("MuSig pubkey: {}".format(musig_ABC.get_bytes().hex()))


# #### _Programming Exercise 3.1.3:_ Build a taproot output
# 
# In this exercise, we'll build a taptree according to the spending paths and their likelihoods, and then derive the segwit address for the taproot.

# In[ ]:


# Tapscripts - 2 main keys & 1 backup key
# Use construct_csa_delay() to construct the tapscript
delay =  # TODO: implement
tapscript_2a =  # TODO: implement
tapscript_2b =  # TODO: implement
...  # TODO: implement

# Tapscripts - 1 main keys & 2 backup keys
long_delay =  # TODO: implement
tapscript_3a =  # TODO: implement
tapscript_3b =  # TODO: implement
...  # TODO: implement

# Set list of backup tapscripts
# Suggestion: Include tapscripts with 3d timelocks first, then those with 10d timelocks
backup_tapscripts =  # TODO: implement
                                
assert len(backup_tapscripts) == 9

# Construct taptree with huffman constructor
tapscript_weights =  # TODO: implement
                                
multisig_taproot = TapTree(key=musig_ABC)
multisig_taproot.huffman_constructor(tapscript_weights)

print("Taproot descriptor {}\n".format(multisig_taproot.desc))

# Derive segwit v1 address
tapscript, taptweak, control_map = multisig_taproot.construct()
taptweak = int.from_bytes(taptweak, 'big')
output_pubkey = musig_ABC.tweak_add(taptweak)
output_pubkey_b = output_pubkey.get_bytes()
segwit_address =  # TODO: implement
print("Segwit Address:", segwit_address)


# #### Start TestNodes

# In[ ]:


test = util.TestWrapper()
test.setup()


# #### Generate Wallet Balance

# In[ ]:


test.nodes[0].generate(101)
balance = test.nodes[0].getbalance()
print("Balance: {}".format(balance))


# #### Send funds from the Bitcoin Core wallet to the taproot output

# In[ ]:


# Send funds to taproot output.
txid = test.nodes[0].sendtoaddress(address=segwit_address, amount=0.5, fee_rate=25)
print("Funding tx:", txid)

# Deserialize wallet transaction.
tx = CTransaction()
tx_hex = test.nodes[0].getrawtransaction(txid)
tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
tx.rehash()

print(tapscript.hex())

print(tx.vout)

# The wallet randomizes the change output index for privacy
# Loop through the outputs and return the first where the scriptPubKey matches the segwit v1 output
output_index, output = next(out for out in enumerate(tx.vout) if out[1].scriptPubKey == tapscript)
output_value = output.nValue

print("Segwit v1 output is {}".format(output))
print("Segwit v1 output value is {}".format(output_value))
print("Segwit v1 output index is {}".format(output_index))


# ## Test spending paths of the taproot
# 
# In the next section exercise, we'll construct three taproot spends:
# 
# - one using the 3-of-3 musig key spending path (exercise)
# - one using one of the 3-of-5 short delay backup script spending path (example)
# - one using one of the 3-of-5 long delay backup script spending path (exercise)
# 
# In each case we'll test the tx validity with the `testmempoolaccept()`, and verify that the timelock requirements work as intended. We'll also compute the weight of each spending transaction and compare.

# #### Construct a spending transaction

# In[ ]:


# Construct transaction
spending_tx = CTransaction()

# Populate the transaction version
spending_tx.nVersion = 1

# Populate the locktime
spending_tx.nLockTime = 0

# Populate the transaction inputs
outpoint = COutPoint(tx.sha256, output_index)
spending_tx_in = CTxIn(outpoint = outpoint)
spending_tx.vin = [spending_tx_in]

print("Spending transaction:\n{}".format(spending_tx))


# #### Populate outputs
# 
# We'll generate an output address in the Bitcoin Core wallet to send the funds to, determine the fee, and then populate the spending_tx with an output to that address.

# In[ ]:


# Generate new Bitcoin Core wallet address
dest_addr = test.nodes[0].getnewaddress(address_type="bech32")
scriptpubkey = bytes.fromhex(test.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])

# Determine minimum fee required for mempool acceptance
min_fee = int(test.nodes[0].getmempoolinfo()['mempoolminfee'] * 100000000)

# Complete output which returns funds to Bitcoin Core wallet
dest_output = CTxOut(nValue=output_value - min_fee, scriptPubKey=scriptpubkey)
spending_tx.vout = [dest_output]

print("Spending transaction:\n{}".format(spending_tx))


# #### 3.1.4 _Programming Exercise:_ Create a valid key path output
# 
# In this exercise, we'll spend the taproot output using the key path. Since the key path is used, there is no control block to indicate whether or not the public key (Q) has an even or odd y-coordinate and so it is assumed that the y-coordinate is odd. Therefore, if Q needs to be negated, then so do all the private keys as well as the tweak.

# In[ ]:


# Negate keys if necessary
output_keyPath = output_pubkey
privKeyA_keyPath = main_privkeyA_c
privKeyB_keyPath = main_privkeyB_c
privKeyC_keyPath = main_privkeyC_c
tweak_keyPath = taptweak

if output_keyPath.get_y()%2 != 0:
    output_keyPath.negate()
    privKeyA_keyPath.negate()
    privKeyB_keyPath.negate()
    privKeyC_keyPath.negate()
    tweak_keyPath = SECP256K1_ORDER - taptweak

# Create sighash for ALL
sighash_musig =  # TODO: implement
 
# Generate individual nonces for participants and an aggregate nonce point
# Remember to negate the individual nonces if necessary
R_agg =  # TODO: implement

# Create an aggregate signature.
# Remember to add a factor for the tweak
sig_agg =  # TODO: implement
print("Aggregate signature is {}\n".format(sig_agg.hex()))

assert output_keyPath.verify_schnorr(sig_agg, sighash_musig)

# Construct transaction witness
spending_tx.wit.vtxinwit.append(  # TODO: implement
 
print("spending_tx: {}\n".format(spending_tx))

# Test mempool acceptance
spending_tx_str = spending_tx.serialize().hex() 
assert test.nodes[0].testmempoolaccept([spending_tx_str])[0]['allowed']

print("Key path spending transaction weight: {}".format(test.nodes[0].decoderawtransaction(spending_tx_str)['weight']))

print("Success!")


# #### 3.1.5 Example: Create a valid script path output for a short delay script
# 
# In this example, we'll spend the output using a script path for the short delay script. This will not be accepted to the mempool initially, because the locktime has not been reached.

# In[ ]:


# Construct transaction
spending_tx = CTransaction()

spending_tx.nVersion = 2
spending_tx.nLockTime = 0
outpoint = COutPoint(tx.sha256, output_index)
spending_tx_in = CTxIn(outpoint=outpoint, nSequence=delay)
spending_tx.vin = [spending_tx_in]
spending_tx.vout = [dest_output]

sighash = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT, 0, scriptpath=True, script=tapscript_2a.script)

witness_elements = []

# Add signatures to the witness
# Remember to reverse the order of signatures
sigA = main_privkeyA.sign_schnorr(sighash)
sigB = main_privkeyB.sign_schnorr(sighash)
sigD = backup_privkeyD.sign_schnorr(sighash)

# Add witness to transaction
witness_elements = [sigD, sigB, sigA, tapscript_2a.script, control_map[tapscript_2a.script]]
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
spending_tx_str = spending_tx.serialize().hex()

# Test timelock
assert_equal(
    [{'txid': spending_tx.rehash(), 'allowed': False, 'reject-reason': 'non-BIP68-final'}],
    test.nodes[0].testmempoolaccept([spending_tx_str])
)

print("Short delay script path spending transaction weight: {}".format(test.nodes[0].decoderawtransaction(spending_tx_str)['weight']))

print("Success!")


# #### Generate enough blocks to satisfy timelock and retest mempool acceptance
# 
# Do not do this until you have completed the exercise above!

# In[ ]:


test.nodes[0].generate(delay - 1)

# Timelock not satisfied - transaction not accepted
assert not test.nodes[0].testmempoolaccept([spending_tx.serialize().hex()])[0]['allowed']

test.nodes[0].generate(1)

# Transaction should be accepted now that the timelock is satisfied
assert test.nodes[0].testmempoolaccept([spending_tx.serialize().hex()])[0]['allowed']

print("Success!")


# #### 3.1.6 _Programming Exercise:_ Create a valid script path output for a long delay script
# 
# In this exercise, we'll spend the output using a script path for the long delay script. This will not be accepted to the mempool initially, because the locktime has not been reached.

# In[ ]:


# Construct transaction
spending_tx = CTransaction()

spending_tx.nVersion = 2
spending_tx.nLockTime = 0
outpoint = COutPoint(tx.sha256, output_index)
spending_tx_in = CTxIn(outpoint=outpoint, nSequence=long_delay)
spending_tx.vin = [spending_tx_in]
spending_tx.vout = [dest_output]

# Derive the sighash. Use tapscript_3a.
sighash =  # TODO: implement

witness_elements = []

# Add signatures to the witness
# Remember to reverse the order of signatures
witness_elements =  # TODO: implement

# Construct transaction witness
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
spending_tx_str = spending_tx.serialize().hex()

# Test timelock
assert_equal(
    [{'txid': spending_tx.rehash(), 'allowed': False, 'reject-reason': 'non-BIP68-final'}],
    test.nodes[0].testmempoolaccept([spending_tx_str])
)

print("Long delay script path spending transaction weight: {}".format(test.nodes[0].decoderawtransaction(spending_tx_str)['weight']))

print("Success!")


# #### Generate enough blocks to satisfy timelock and retest mempool acceptance
# 
# Do not do this until you have completed the exercise above!

# In[ ]:


test.nodes[0].generate(long_delay - delay - 1)

# Timelock not satisfied - transaction not accepted
assert not test.nodes[0].testmempoolaccept([spending_tx.serialize().hex()])[0]['allowed'] 

test.nodes[0].generate(1)

# Transaction should be accepted now that the timelock is satisfied
assert test.nodes[0].testmempoolaccept([spending_tx.serialize().hex()])[0]['allowed']

print("Success!")


# #### Shutdown

# In[ ]:


test.shutdown()

