import util
from test_framework.address import program_to_witness
from test_framework.key import ECPubKey, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string
from test_framework.script import tagged_hash, Tapbranch, TapTree, TapLeaf, CScript, TaprootSignatureHash, OP_CHECKSIG, SIGHASH_ALL_TAPROOT


internal_pubkey = ECPubKey()
privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()

# Method: Returns tapbranch hash. Child hashes are lexographically sorted and then concatenated.
# l: tagged hash of left child
# r: tagged hash of right child
def tapbranch_hash(l, r):
    return tagged_hash("TapBranch", b''.join(sorted([l, r])))


def compute_taptweak():
    TAPSCRIPT_VER = bytes([0xc0])  # See tapscript chapter for more details.
    internal_pubkey.set(bytes.fromhex('03af455f4989d122e9185f8c351dbaecd13adca3eef8a9d38ef8ffed6867e342e3'))

    # Derive pay-to-pubkey scripts
    scriptA = CScript([pubkeyA.get_bytes(), OP_CHECKSIG])
    scriptB = CScript([pubkeyB.get_bytes(), OP_CHECKSIG])
    scriptC = CScript([pubkeyC.get_bytes(), OP_CHECKSIG])


    # 1) Compute TapLeaves A, B and C
    # Method: ser_string(data) is a function which adds compactsize to input data.
    hash_inputA = TAPSCRIPT_VER + ser_string(scriptA)
    hash_inputB = TAPSCRIPT_VER + ser_string(scriptB)
    hash_inputC = TAPSCRIPT_VER + ser_string(scriptC)
    taggedhash_leafA = tagged_hash("TapLeaf", hash_inputA)
    taggedhash_leafB = tagged_hash("TapLeaf", hash_inputB)
    taggedhash_leafC = tagged_hash("TapLeaf", hash_inputC)

    # 2) Compute Internal node TapBranch AB
    # Method: use tapbranch_hash() function
    internal_nodeAB = tapbranch_hash(taggedhash_leafA, taggedhash_leafB)

    # 3) Compute TapTweak
    rootABC = tapbranch_hash(internal_nodeAB, taggedhash_leafC)
    taptweak = tagged_hash("TapTweak", internal_pubkey.get_bytes() + rootABC)
    print("TapTweak:", taptweak.hex())

    return taptweak


def compute_segwit_address():
    # 4) Derive the segwit output address
    taptweak = compute_taptweak()
    taproot_pubkey_b = internal_pubkey.tweak_add(taptweak).get_bytes()
    segwit_address = program_to_witness(1, taproot_pubkey_b)
    print('Segwit address:', segwit_address)

    return segwit_address


def compute_taptweak_with_class():
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
    print("Your taptweak computed is {}".format(tweak.hex()))

compute_segwit_address()
compute_taptweak_with_class()