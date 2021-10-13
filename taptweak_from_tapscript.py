import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string, sha256
from test_framework.musig import generate_musig_key
from test_framework.script import hash160, SIGHASH_ALL_TAPROOT, tagged_hash, TapLeaf, TaprootSignatureHash, TapTree
from csa_hashlock_delay_tapscript_2_of_2 import csa_hash_block

privkey_internal, pubkey_internal = generate_bip340_key_pair()
csa_hashlock_delay_tapscript = csa_hash_block()


def taptweak_from_tapscript():
    # Method: ser_string(Cscript) prepends compact size.
    TAPSCRIPT_VER = bytes([0xc0])
    tapleaf = tagged_hash("TapLeaf", TAPSCRIPT_VER + ser_string(csa_hashlock_delay_tapscript.script))
    taptweak = tagged_hash("TapTweak", pubkey_internal.get_bytes() + tapleaf)
    print("Your constructed taptweak is: {}.".format(taptweak.hex()))
    return taptweak


def tagged_hash_with_taptweak():
    taptweak = taptweak_from_tapscript()
    taptree = TapTree(key=pubkey_internal, root=csa_hashlock_delay_tapscript)
    segwit_v1_script, tap_tweak_constructed, control_map = taptree.construct()
    assert taptweak == tap_tweak_constructed
    print("Success! Your constructed taptweak is correct.")


tagged_hash_with_taptweak()
