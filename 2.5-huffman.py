#!/usr/bin/env python
# coding: utf-8

# In[ ]:


import util
from test_framework.key import ECKey, ECPubKey, generate_key_pair, generate_bip340_key_pair
from test_framework.script import Tapbranch, TapLeaf, TapTree


# # 2.5 Huffman TapTree Constructor
# 
# When constructing a TapTree, we can optimize the tree structure to minimize the expected witness weight when spending along the script path. The **expected witness weight** is determined by summing up all probability-adjusted witness weights of the TapScripts in the TapTree.
# 
# For example, for a TapTree with TapLeaves A, B, and C, the expected witness weight is determined as follows:
# 
# ```
# Expected-witness-weight =
#       Probability-of-A * Witness-weight-A
#     + Probability-of-B * Witness-weight-B
#     + Probability-of-C * Witness-weight-C
# ```
# 
# In order to minimize the expected witness weight for the script path, we can try to reduce the size of the required **inclusion proof** for those TapScripts which have a higher probability by placing these closer to the root of the tree.

# ## Part 1: Huffman Algorithm
# 
# We can use [Huffman's algorithm](https://en.wikipedia.org/wiki/Huffman_coding) to build tree structures from their leaves and assigned frequencies. The assigned frequency of each leaf is based on its expected probability of execution. Note that it is the ratios between the assigned leaf frequencies which determine the resulting tree structure, not their absolute values.
# 
# The Huffman algorithm to construct a TapTree structure can be described as follows:
# 
# * Place all leaves in a queue and sort by ascending frequency
# * While length(queue) > 1 :
#     * Pop the two elements with the lowest frequencies
#     * Generate the parent tapbranch with a frequency equal to the sum of the child frequencies
#     * Add parent tapbranch to queue and re-sort
# * Tree root is represented by final queue element

# ![test](images/huffman_intro0.jpg)

# **Note:** If more than 2 leaves or tapbranches share the same assigned frequency during construction with the Huffman algorithm, the selection of the two queue elements to generate the next parent becomes ambiguous. In our implementation, we first sort our queue by **assigned frequency**, then by **tagged hash** value. This way, the sorting of the queue is always unambiguous given a distinct set of leaves. _This secondary, arbitrary sorting criteria does not affect the expected witness weight of spending along the script path, since the assigned frequencies of the leaves or tapbranches in question are equal._

# #### Example 2.5.1: Construct a TapTree with the Huffman algorithm
# 
# * We manually construct the TapTree from a set of 5 pay-to-pubkey TapLeaves with assigned frequencies as shown in the image above.

# In[ ]:


internal_pubkey = ECPubKey()
internal_pubkey.set(bytes.fromhex('af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3'))

# Derive pay-to-pubkey tapleaves
privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
privkeyD, pubkeyD = generate_bip340_key_pair()
privkeyE, pubkeyE = generate_bip340_key_pair()

tapleafA = TapLeaf().construct_pk(pubkeyA)
tapleafB = TapLeaf().construct_pk(pubkeyB)
tapleafC = TapLeaf().construct_pk(pubkeyC)
tapleafD = TapLeaf().construct_pk(pubkeyD)
tapleafE = TapLeaf().construct_pk(pubkeyE)

# Sorted queue: (5, A), (4, B), (3, C), (2, D), (1, E)
# Tapbranch DE = parent(D,E)
# Assigned frequency of DE = 2 + 1 = 3
tapbranchDE = Tapbranch(tapleafD, tapleafE)

# Sorted queue: (5, A), (4, B), (3, C), (3, DE), 
# Tapbranch CDE = parent(C, DE)
# Assigned frequency of CDE = 3 + 3 = 6
tapbranchCDE = Tapbranch(tapleafC, tapbranchDE)

# Sorted queue: (6, CDE), (5, A), (4, B)
# Tapbranch AB = parent(A,B)
# Assigned frequency of AB = 5 + 4 = 9
tapbranchAB = Tapbranch(tapleafA, tapleafB)

# Sorted queue: (9, AB), (6, CDE)
# Tapbranch ABCDE = parent(AB, CDE)
tapbranchABCDE = Tapbranch(tapbranchAB, tapbranchCDE)

# Tree construction
taptree = TapTree(key=internal_pubkey, root=tapbranchABCDE)

segwit_v1_script, tweak, control_map = taptree.construct()
print("Taptree descriptor: {}\n".format(taptree.desc))


# ## Part 2: Huffman TapTree Constructor Method
# 
# We reconstruct the same TapTree from the example above using the `TapTree.huffman_constructor()` method. 
# 
# * That function takes a list of `(assigned_frequency,tapleaf)` tuples, where:
#     * `assigned_frequency` is an `int` 
#     * `tapleaf` is a `TapLeaf` object
#    

# #### Example 2.5.2: Construct a TapTree with the Huffman constructor method
# * We compare the resulting TapTree with the one constructed manually in example 2.5.1

# In[ ]:


taptree2 = TapTree()
taptree2.key = internal_pubkey
taptree2.huffman_constructor([(5, tapleafA), (4, tapleafB), (3, tapleafC), (2, tapleafD), (1, tapleafE)])
print("Taptree descriptor: {}\n".format(taptree2.desc))

segwit_v1_script2, tweak2, control_map2 = taptree2.construct()
print("TapTrees are identical: {}".format(tweak == tweak2))


# #### _Programming Exercise 2.5.3:_ Assign the leaf frequencies for this tree structure
# 
# Given the TapTree structure shown below, try to assign compatible leaf frequencies for the Huffman constructor. In other words, try to follow the Huffman algorithm from the lowest depth of the tree and determine what frequency values would be necessary in order to construct the tree depicted in the image below.
# 
# For TapLeaves A through F:
# * Generate `pk` TapScripts for each.
# * Assign their frequencies so that the TapTree resulting from the Huffman constructor has the desired tree structure.

# ![test](images/huffman_intro1.jpg)

# In[ ]:


internal_pubkey = ECPubKey()
internal_pubkey.set(bytes.fromhex('af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3'))

# Derive pay-to-pubkey TapLeaves
privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
privkeyD, pubkeyD = generate_bip340_key_pair()
privkeyE, pubkeyE = generate_bip340_key_pair()
privkeyF, pubkeyF = generate_bip340_key_pair()

tapleafA = TapLeaf().construct_pk(pubkeyA)
tapleafB = TapLeaf().construct_pk(pubkeyB)
tapleafC = TapLeaf().construct_pk(pubkeyC)
tapleafD = TapLeaf().construct_pk(pubkeyD)
tapleafE = TapLeaf().construct_pk(pubkeyE)
tapleafF = TapLeaf().construct_pk(pubkeyF)

# Assign frequencies to the TapLeaves to generate the desired tree
weightA = # TODO: Implement
weightB = # TODO: Implement
weightC = # TODO: Implement
weightD = # TODO: Implement
weightE = # TODO: Implement
weightF = # TODO: Implement

# Construct TapTree with Huffman constructor
taptree = TapTree()
taptree.key = internal_pubkey
taptree.huffman_constructor([(weightA, tapleafA), (weightB, tapleafB), (weightC, tapleafC), (weightD, tapleafD), (weightE, tapleafE), (weightF, tapleafF)])
print("Taptree descriptor: {}\n".format(taptree.desc))


# #### _Check the leaf depths in your constructed Taptree._
# 
# Run the cell below to check if you have constructed the correct tree structure with your assigned frequencies.

# In[ ]:


tapleaves = [("A", tapleafA, 4),              ("B", tapleafB, 4),              ("C", tapleafC, 4),              ("D", tapleafD, 4),              ("E", tapleafE, 2),              ("F", tapleafF, 1)]

segwit_v1_script, tweak, control_map = taptree.construct()

for leaf_label, tapleaf, depth in tapleaves:
    controlblock = control_map[tapleaf.script]
    print("TapLeaf{} is located at depth {}".format(leaf_label, depth))
    assert int((len(controlblock) - 33)/32) == depth
    
print("Your constructed TapTree is correct!")


# **Congratulations!** In this chapter, you have:
# 
# - Learned how to optimize the expected witness weight for a script path spend.
# - Learned how a TapTree is constructed with the Huffman algorithm.
#     - TapLeaves which are assigned higher frequencies are closer to the tree root.
#     - TapLeaves closer to the TapTree root are cheaper to spend, as the inclusion proof is smaller.
# - Learned how a TapTree is constructed with the `TapTree.huffman_contructor()` method.
# - Assigned frequencies to TapLeaves to construct a specific tree structure with the Huffman algorithm.
