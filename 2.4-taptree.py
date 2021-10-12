#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import util
from test_framework.address import program_to_witness
from test_framework.key import ECPubKey, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string
from test_framework.script import tagged_hash, Tapbranch, TapTree, TapLeaf, CScript, TaprootSignatureHash, OP_CHECKSIG, SIGHASH_ALL_TAPROOT


# # 2.4 TapTree
# 
# In this chapter we consider how to commit multiple tapscripts to a taptweak. This can be achieved with a binary tree commitment structure. We will also introduce taproot descriptors, which are composed of tapscript descriptors and reflect the binary tree commitment structure of a taproot output.
# 
# * **Part 1 - Constructing a taptree**
#     * Taptree commitments
#     * Taproot descriptors
#     * Taptree construction
#     
# In part 2, we consider spending the taproot output along the script path for taproot outputs with taptree commitments, which have more than 1 commited tapscript. This requires an inclusion proof for the tapscript being spent.
# 
# * **Part 2 - Taproot script path**
#     * Script path spending for taptrees

# ## Part 1: Constructing a taptree
# 
# ### Taptree binary tree commitments
# 
# Committing multiple tapscripts requires a commitment structure resembling merkle tree construction.
# 
# **The TapTree is different than the header merkle tree in the following ways:**
# 
# * Tapleaves can be located at different heights.
# * Ordering of TapLeaves is determined lexicograpically.
# * Location of nodes are tagged (No ambiguity of node type).
#  
# Internal nodes are called tapbranches, and are also computed with the `tagged_hash("Tag", input_data)` function.
#  
# Tagged hashes are particularly useful when building a taptree commitment. They prevent node height ambiguity currently found in the transaction merkle tree, which allows an attacker to create a node which can be reinterpreted as either a leaf or internal node. Tagged hashes ensure that a tapleaf cannot be misinterpreted as an internal node and vice versa.

# ![test](images/taptree0.jpg)

# #### _Programming Exercise 2.4.1:_ Compute a taptweak from a taptree
# 
# In the cell below, we will commit three pay-to-pubkey scripts to a taptweak and then derive the bech32m address. We will use the same merkle tree structure as in the previous illustration.
# 
# 1. Compute TapLeaves A, B and C.
# 2. Compute Internal TapBranch AB.
# 3. Compute TapTweak
# 4. Derive the bech32m address.

# In[ ]:


TAPSCRIPT_VER = bytes([0xc0])  # See tapscript chapter for more details.
internal_pubkey = ECPubKey()
internal_pubkey.set(bytes.fromhex('03af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3'))

# Derive pay-to-pubkey scripts
privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
scriptA = CScript([pubkeyA.get_bytes(), OP_CHECKSIG])
scriptB = CScript([pubkeyB.get_bytes(), OP_CHECKSIG])
scriptC = CScript([pubkeyC.get_bytes(), OP_CHECKSIG])

# Method: Returns tapbranch hash. Child hashes are lexographically sorted and then concatenated.
# l: tagged hash of left child
# r: tagged hash of right child
def tapbranch_hash(l, r):
    return tagged_hash("TapBranch", b''.join(sorted([l,r])))

# 1) Compute TapLeaves A, B and C.
# Method: ser_string(data) is a function which adds compactsize to input data.
hash_inputA =  # TODO: implement
hash_inputB =  # TODO: implement
hash_inputC =  # TODO: implement
taggedhash_leafA =  # TODO: implement
taggedhash_leafB =  # TODO: implement
taggedhash_leafC =  # TODO: implement

# 2) Compute Internal node TapBranch AB.
# Method: use tapbranch_hash() function
internal_nodeAB = # TODO: implement

# 3) Compute TapTweak.
rootABC =  # TODO: implement
taptweak =  # TODO: implement
print("TapTweak:", taptweak.hex())

# 4) Derive the bech32m address.
taproot_pubkey_b = internal_pubkey.tweak_add(taptweak).get_bytes()
bech32m_address = program_to_witness(1, taproot_pubkey_b)
print('Bech32m address:', bech32m_address)


# #### Example 2.4.2: Compute a taptweak with the TapTree class
# 
# Run the cell below to validate your your taptree commitment in 2.4.1.
# 
# * The `TapTree` class allows us to build a taptree structures from `TapLeaf` objects. It can be instantiated with an internal pubkey `key` and a taptree root `root`.
#     * `TapTree.root` is the root node of the merkle binary tree.
#     * `TapBranch` objects represents internal tapbranches, and have `Tapbranch.left` and `Tapbranch.right` members.
#     * `TapTree.construct()` returns the triple `segwit_v1_script`, `tweak`, `control_map`.
#         * `segwit_v1_script` - segwit v1 output script.
#         * `tweak` with the committed taptree.
#         * `control_map` stores Cscript - controlblock pairs for spending committed tapscripts.

# In[ ]:


# Construct tapleaves
tapleafA = TapLeaf().construct_pk(pubkeyA)
tapleafB = TapLeaf().construct_pk(pubkeyB)
tapleafC = TapLeaf().construct_pk(pubkeyC)

# Construct taptree nodes.
tapbranchAB = Tapbranch(tapleafA, tapleafB)
tapbranchABC = Tapbranch(tapbranchAB, tapleafC)

# Construct the taptree.
taptree = TapTree(key=internal_pubkey, root=tapbranchABC)

segwit_v1_script, tweak, control_map = taptree.construct()
print("Your taptweak computed in 2.4.1 is correct:", tweak == taptweak)


# ### Taproot descriptors
# 
# For taproot, we propose a taproot descriptor expression which can be composed from its individual tapscripts. The structure of the taptree is not unique to set of tapscripts, and so must also be captured by the taproot descriptor. Consider the example below with 5 `ts(pk(key))` tapscripts.

# ![test](images/taptree1.jpg)

# A taproot descriptor consist of:
# 
# * `tp(internal_key, [tapscript, [tapscript', tapscript'']])`
# * `tp(internal_key, [tapscript])` for single tapscript commitments.
# * Each node is represented as a tuple of its children, and can be nested within other node expressions.
# * The left or right ordering of the children is not unique, since they are ultimately ordered lexicographically when computing the taptweak.

# #### Example 2.4.3 - Constructing a taptree from a descriptor.

# ![test](images/taptree2.jpg)

# In this example, we will construct the taptree shown in the descriptor string above. This can be conveniently done by parsing the descriptor string.
# 
# * **Class: `TapTree`**
#     * Construct from descriptor:
#         * `TapTree.from_desc(descriptor_string)`
#     * Serialize back to descriptor:
#         * `TapTree.desc`

# In[ ]:


# Generate internal key pairs
privkey_internal, pubkey_internal = generate_bip340_key_pair()
pk_hex = pubkey_internal.get_bytes().hex()

# Construct descriptor string
ts_desc_A = 'ts(pk({}))'.format(pubkeyA.get_bytes().hex())
ts_desc_B = 'ts(pk({}))'.format(pubkeyB.get_bytes().hex())
ts_desc_C = 'ts(pk({}))'.format(pubkeyC.get_bytes().hex())
tp_desc = 'tp({},[[{},{}],{}])'.format(pk_hex,
                                       ts_desc_A,
                                       ts_desc_B,
                                       ts_desc_C)
print("Raw taproot descriptor: {}\n".format(tp_desc))

# Generate taptree from descriptor
taptree = TapTree()
taptree.from_desc(tp_desc)

# This should match the descriptor we built above
assert taptree.desc == tp_desc

# Compute taproot output
taproot_script, tweak, control_map = taptree.construct()

print("Taproot script hex (Segwit v1):", taproot_script.hex())


# ### Taptree construction with the Huffman constructor
# 
# Huffman encoding can optimize the taptree structure, and thus potentially lower the size of revealed branches, by taking into account the estimated frequency by which each TapLeaf will occur. Since some spending scenarios are more likely to occur than others, ideally we would optimize the tree structure such that those spends appear closer to the root of the tree, and therefore require a smaller merkle proof when spending.
# 
# For more details on how the Huffman encoder constructs the taptree, see optional chapter 2.5.
# 
# #### Example 2.4.4 - Building a TapTree with the huffman constructor
# 
# We reconstruct the same taptree from the above examples using the `huffman_constructor()`. That function takes a list of `(weight,tapleaf)` tuples, where `weight` is an `int` and `tapleaf` is a `TapLeaf` object. A higher weight:
#    
# * Indicates a higher likelihood of execution
# * Means the script will be placed closer to the root if possible
# * Results in a smaller inclusion proof and lower spending fees
# 
# Note that the internal pubkey still needs to be provided when instantiating the `TapTree` object. `huffman_constructor()` only constructs the script tree.

# In[ ]:


taptree3 = TapTree(key=pubkey_internal)
taptree3.huffman_constructor([(1, tapleafA), (1, tapleafB), (2, tapleafC)])
print("taptree3 descriptor: {}\n".format(taptree3.desc))

# Compare the resulting taproot script with that from example 2.4.3.
taproot_script3, tweak3, control_map3 = taptree3.construct()
assert taproot_script3 == taproot_script
print("Success!")


# ## Part 2: Spending along the Script Path
# 
# A Taproot output is spent along the script path with the following witness pattern:
# 
# * Witness to spend TapScript_A:
# 
#     * `[Stack element(s) satisfying TapScript_A]`
#     * `[TapScript_A]` 
#     * `[Controlblock c]`
# 
# Compared to the script spend path of a taproot with a single committed tapscript, the controlblock spending a taproot containing multiple tapscripts will also include a script inclusion proof.
# 
# * Controlblock c contains:
# 
#     * `[Tapscript Version]` 
#         * `0xfe & c[0]`
#     * `[Parity bit (oddness of Q's y-coordinate)]`
#         * `0x01 & c[0]` 
#     * `[Internal Public Key]` 
#         * `c[1:33]`
#     * `[Script Inclusion Proof]` 
#         * `n x 32Bytes`
#         
# Note that this script inclusion proof is a 32B multiple and its size will depend on the position of tapscript in the taptree structure.

# ![test](images/taptree5.jpg)

# **Generating the Controlblock**
# 
# We use the the taptree construct method to generate the taproot output, tweak and controlblocks for all tapscripts.
# 
# **`TapTree.construct()` returns the tuple:**
# * `taproot_output_script`, `tweak`, `control_block_map`
# * `control_block_map` has key-value pairs: 
#     * `tapscript.script` - `controlblock`        

# #### _Programming Exercise 2.4.5_ - Constructing a taproot output from a taptree
# 
# In the following exercise, please construct the output and bech32m address for a taptree with 4 leaves using with the huffman taptree constructor, so that it results in a balanced tree. Please generate new keys for the internal key and pay-to-pubkey tapscripts.

# In[ ]:


# Generate key pairs for internal pubkey and pay-to-pubkey tapscripts
privkey_internal, pubkey_internal = generate_bip340_key_pair()

privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
privkeyD, pubkeyD = generate_bip340_key_pair()

# Construct pay-to-pubkey tapleaves and taptree
TapLeafA =  # TODO: implement
TapLeafB =  # TODO: implement
TapLeafC =  # TODO: implement
TapLeafD =  # TODO: implement

# Create a taptree with tapleaves and huffman constructor
# Method: TapTree.huffman_constructor(tuple_list)
taptree =  # TODO: implement
taptree.huffman_constructor(  # TODO: implement

# Generate taproot tree with the `construct()` method, then use the taproot bytes to create a bech32m address
taproot_script, tweak, control_map = taptree.construct()
taproot_pubkey = pubkey_internal.tweak_add(tweak) 
program = taproot_pubkey.get_bytes()
address = program_to_witness(1, program)
print("Address: {}".format(address))


# ### Exercise - Spending a taproot output along a script path
# 
# In this exercise, we will send funds to the previously generated address in exercise 2.4.6, and spend this output along the `TapScript0` path.

# #### Example 2.4.6: Start Bitcoin Core node and send coins to the taproot address
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


# #### Example 2.4.7: Construct `CTransaction` and populate fields
# 
# We use the `create_spending_transaction(node, txid)` convenience function.

# In[ ]:


# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash, version=2)

print("Spending transaction:\n{}".format(spending_tx))


# #### _Programming Exercise 2.4.8:_ Sign the transaction for `TapLeafA` 
# 
# Note that we must pass the following arguments to `TaprootSignatureHash` for script path spending:
# * `scriptpath`: `True`
# * `script`: `Cscript` of tapscript

# In[ ]:


# Generate the taproot signature hash for signing
sighashA = TaprootSignatureHash(spending_tx,
                               [tx.vout[0]],
                               SIGHASH_ALL_TAPROOT,
                               input_index=0,
                               scriptpath=  # TODO: implement
                               script=  # TODO: implement

signatureA =  # TODO: implement

print("Signature for TapLeafA: {}\n".format(signatureA.hex()))


# #### _Programming Exercise  2.4.9:_ Construct the witness, add it to the transaction and verify mempool acceptance

# In[ ]:


# Add witness to transaction
# Tip: Witness stack for script path - [satisfying elements for tapscript] [TapLeaf.script] [controlblock]
# Tip: Controlblock for a tapscript in control_map[TapLeaf.script]
witness_elements =  # TODO: implement
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))

# Test mempool acceptance
assert node.test_transaction(spending_tx)
print("Success!")


# #### Shutdown TestWrapper

# In[ ]:


test.shutdown()


# **Congratulations!** In this chapter, you have:
# 
# - Constructed a binary tree of individual tapscripts into a taptree.
# - Computed the hash commitment of that taptree and used it to tweak the internal taproot public key.
# - Used descriptors to specify and construct a taptree of scripts.
# - Sent coins to a segwit v1 output with a tweaked public key committing to a taptree, and later spent that output by using the script path to an individual tapscript.
