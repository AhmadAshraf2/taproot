import util
from test_framework.address import program_to_witness
from test_framework.key import ECPubKey, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string
from test_framework.script import tagged_hash, Tapbranch, TapTree, TapLeaf, CScript, TaprootSignatureHash, OP_CHECKSIG, SIGHASH_ALL_TAPROOT

privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
privkey_internal, pubkey_internal = generate_bip340_key_pair()

# Generate internal key pairs
def generate_tap_tree():
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

    return taptree


def generate_taptree_with_huffman():
    tapleafA = TapLeaf().construct_pk(pubkeyA)
    tapleafB = TapLeaf().construct_pk(pubkeyB)
    tapleafC = TapLeaf().construct_pk(pubkeyC)
    taptree3 = TapTree(key=pubkey_internal)
    taptree3.huffman_constructor([(1, tapleafA), (1, tapleafB), (2, tapleafC)])
    print("taptree3 descriptor: {}\n".format(taptree3.desc))

    # Compare the resulting taproot script with that from example 2.4.3.
    taproot_script, tweak3, control_map3 = taptree3.construct()
    print("Taproot script hex (Segwit v1):", taproot_script.hex())
    print("Success!")

generate_tap_tree()
generate_taptree_with_huffman()