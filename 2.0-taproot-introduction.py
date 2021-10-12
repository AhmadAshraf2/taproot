#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair
from test_framework.messages import COutPoint, CTransaction, CTxIn, CTxOut, CTxInWitness
from test_framework.script import SegwitV0SignatureHash, SIGHASH_ALL, hash160, get_p2pkh_script


# # 2.0 Taproot Introduction
# 
# Over the following chapters, we introduce various aspects of the schnorr/taproot soft fork proposal. Each chapter is built around a case study, demonstrating how the technology can be used in world applications.
# 
# In each chapter, we first introduce the case study scenario and give an overview of the technology. We then demonstrate its use as follows:
# 
# 1. We first construct a segwit v1 witness program that implements the desired spending policy and derive the bech32m address for that witness program;
# 2. Then we start a Bitcoin Core full node, generate 101 blocks on the node (so that the node has a mature balance to spend), and spend coins from the Bitcoin Core wallet to the bech32m address from step (1);
# 3. Finally, we construct a transaction spending from the output created in step (2) back to the Bitcoin Core wallet. We sign the transaction and verify that the transaction is valid using the full node's `testmempoolaccept` RPC method.
# 
# This sequence of steps is illustrated below:

# ![test](images/segwit_version1_1.jpg)

# In each chapter, we'll implement the spending policy using both v0 (pre-taproot) segwit and v1 (taproot) segwit outputs, and highlight the differences in transaction weight and privacy.

# ## Transaction sequence
# 
# This chapter demonstrates the transaction sequence in full detail. Future chapters follow the same steps, but use convenience functions to abstract away the low-level details.

# #### Example 2.0.1 Generate a segwit v0 bech32 address
# 
# We generate an address *outside* the Bitcoin Core wallet, which we'll send funds to from Bitcoin Core.
# 
# In this example, we'll use a P2WPKH segwit output (not a taproot output).

# In[ ]:


# Generate a new key pair
privkey, pubkey = generate_key_pair()
print("Pubkey: {}\n".format(pubkey.get_bytes(bip340=False).hex()))

# Get the hash160 of the public key for the witness program
# Note that the function 'get_bytes(bip340=False)' is used to get the compressed DER encoding of the public key needed for 
# segwit v0.
program = hash160(pubkey.get_bytes(bip340=False))
print("Witness program: {}\n".format(program.hex()))

# Create (regtest) bech32 address
version = 0x00
address = program_to_witness(version, program)
print("bech32 address: {}".format(address))


# #### Example 2.0.2 Start a Bitcoin Core node, then generate blocks and send output to the bech32 address generated above
# 
# This functionality will be encapsulated in the `node.generate_and_send_coins(address)` method later.

# In[ ]:


# Start node
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

version = node.getnetworkinfo()['subversion']
print("\nClient version is {}\n".format(version))

# Generate 101 blocks
node.generate(101)
balance = node.getbalance()
print("Balance: {}\n".format(balance))

assert balance > 1

unspent_txid = node.listunspent(1)[-1]["txid"]
inputs = [{"txid": unspent_txid, "vout": 0}]

# Create a raw transaction sending 1 BTC to the address and then sign it.
tx_hex = node.createrawtransaction(inputs=inputs, outputs=[{address: 1}])
res = node.signrawtransactionwithwallet(hexstring=tx_hex)

tx_hex = res["hex"]
assert res["complete"]
assert 'errors' not in res

# Send the raw transaction. We haven't created a change output,
# so maxfeerate must be set to 0 to allow any fee rate.
txid = node.sendrawtransaction(hexstring=tx_hex, maxfeerate=0)

print("Transaction {}, output 0\nsent to {}".format(txid, address))


# #### Example 2.0.3 Construct a transaction to spend the coins back to the Bitcoin Core wallet
# 
# In this example, we'll manually construct a transaction which spends the output back to the Bitcoin Core wallet.
# 
# To do that we create a `CTransaction` object and populate the data members:
# 
#  * `nVersion`
#  * `nLocktime`  
#  * `tx_vin` (list of `CTxIn` objects)
#  * `tx_vout` (list of `CTxOut` objects)
# 
# This functionality will be encapsulated in the `test.create_spending_transaction(coin_txid, version)` method later.
# 
# The only item that we don't populate is the witness:
#  
#  * `tx.wit.vtxinwit` (list of `CTxInWitness` objects)
# 
# which we'll do later.

# In[ ]:


# Construct transaction
spending_tx = CTransaction()

# Populate the transaction version
spending_tx.nVersion = 1

# Populate the locktime
spending_tx.nLockTime = 0

# Populate the transaction inputs
outpoint = COutPoint(int(txid, 16), 0)
spending_tx_in = CTxIn(outpoint)
spending_tx.vin = [spending_tx_in]

# Generate new Bitcoin Core wallet address
dest_addr = node.getnewaddress(address_type="bech32")
scriptpubkey = bytes.fromhex(node.getaddressinfo(dest_addr)['scriptPubKey'])

# Complete output which returns 0.5 BTC to Bitcoin Core wallet
amount_sat = int(0.5 * 100_000_000)
dest_output = CTxOut(nValue=amount_sat, scriptPubKey=scriptpubkey)
spending_tx.vout = [dest_output]

print("Spending transaction:\n{}".format(spending_tx))


# #### Example 2.0.4 Generate signature for transaction, add it to the witness, and test mempool acceptance.
# 
# In this example, we sign the transaction, add the signature to the transaction's witness, and then use `testmempoolaccept` to verify that the transaction is valid. Later on, we'll use the `node.test_transaction()` convenience method to test mempool acceptance.

# In[ ]:


# Generate the segwit v0 signature hash for signing
sighash = SegwitV0SignatureHash(script=get_p2pkh_script(program),
                                txTo=spending_tx,
                                inIdx=0,
                                hashtype=SIGHASH_ALL,
                                amount=100_000_000)

# Sign using ECDSA and append the SIGHASH byte
sig = privkey.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')

print("Signature: {}\n".format(sig.hex()))

# Add a witness to the transaction. For a P2WPKH, the witness field is the signature and pubkey
spending_tx.wit.vtxinwit.append(CTxInWitness([sig, pubkey.get_bytes(bip340=False)]))

print("Spending transaction:\n{}\n".format(spending_tx))
 
# Serialize signed transaction for broadcast
spending_tx_str = spending_tx.serialize().hex()
 
# Test mempool acceptance
assert node.testmempoolaccept(rawtxs=[spending_tx_str], maxfeerate=0)[0]['allowed']
print("Success!")


# #### Example 2.0.5 Shutdown the node
# 
# Finally we run `test.shutdown()` to end the test and shutdown the node.

# In[ ]:


test.shutdown()


# #### Example 2.0.6 Repeat the steps using convenience functions
# 
# We'll repeat the set of steps using the convenience functions:
# 
# 1. Start the node and create an output that we can spend using `node.generate_and_send_coins(address)`
# 2. Create a `CTransaction` object that spends the output back to the Bitcoin Core wallet using `test.create_spending_transaction(coin_txid, version)`
# 3. Manually sign the transaction and add the witness
# 4. Test mempool acceptance using `node.test_transaction()`

# In[ ]:


# Start node
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))

# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash)
print("Spending transaction:\n{}\n".format(spending_tx))

# Sign the spending transaction and append the witness
sighash = SegwitV0SignatureHash(script=get_p2pkh_script(program),
                                txTo=spending_tx,
                                inIdx=0,
                                hashtype=SIGHASH_ALL,
                                amount=100_000_000)
sig = privkey.sign_ecdsa(sighash) + chr(SIGHASH_ALL).encode('latin-1')
spending_tx.wit.vtxinwit.append(CTxInWitness([sig, pubkey.get_bytes(bip340=False)]))

# Test mempool acceptance
assert node.test_transaction(spending_tx)
print("Success!")


# #### Example 2.0.7 Shutdown the node
# 
# As always, we finish by shutting down the node.

# In[ ]:


test.shutdown()


# **Congratulations!** In this chapter, you have:
# 
# - Started a Bitcoin Core full node (in regtest mode), generated 101 blocks and sent a transaction output to a segwit address
# - Constructed a transaction that spends the segwit output back to the wallet, and tested that it is accepted by the mempool
# - Repeated the same steps using the `generate_and_send_coins()` and `create_spending_transaction()` convenience functions
# 
# We'll use exactly the same sequence of steps in future chapters to spend to and from segwit v1 addresses.
