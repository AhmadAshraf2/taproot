import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string, sha256
from test_framework.musig import generate_musig_key
from test_framework.script import hash160, SIGHASH_ALL_TAPROOT, tagged_hash, TapLeaf, TaprootSignatureHash, TapTree
from taptweak_from_tapscript import taptweak_from_tapscript
from csa_hashlock_delay_tapscript_2_of_2 import csa_hash_block

privkey_internal, pubkey_internal = generate_bip340_key_pair()

def single_tapscript_v1_address():
    # Tweak the internal key to obtain the Segwit program
    # ([32B x-coordinate])
    taptweak = taptweak_from_tapscript()
    taproot_pubkey = pubkey_internal.tweak_add(taptweak)
    taproot_pubkey_b = taproot_pubkey.get_bytes()
    program = taproot_pubkey_b
    print("Witness program is {}\n".format(program.hex()))

    # Create (regtest) bech32m address
    version = 0x01
    address = program_to_witness(1, program)
    print("bech32m address is {}".format(address))
    return address


def start_node_send_coins(address):
    # Start node
    test = util.TestWrapper()
    test.setup()
    node = test.nodes[0]
    # Generate coins and create an output
    tx = node.generate_and_send_coins(address)
    print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))
    return test, tx


def construct_c_transaction(test, tx):
    delay = 20
    spending_tx = test.create_spending_transaction(tx.hash, version=2, nSequence=delay)
    print("Spending transaction:\n{}".format(spending_tx))
    return spending_tx


def sign_transaction(spending_tx, tx):
    # Generate the Taproot Signature Hash for signing
    csa_hashlock_delay_tapscript = csa_hash_block()
    sighash = TaprootSignatureHash(spending_tx,
                                   [tx.vout[0]],
                                   SIGHASH_ALL_TAPROOT,
                                   input_index=0,
                                   scriptpath=True,
                                   script=csa_hashlock_delay_tapscript.script)

    # Sign with both privkeys
    privkey1, pubkey1 = generate_bip340_key_pair()
    privkey2, pubkey2 = generate_bip340_key_pair()

    signature1 = privkey1.sign_schnorr(sighash)
    signature2 = privkey2.sign_schnorr(sighash)

    print("Signature1: {}".format(signature1.hex()))
    print("Signature2: {}".format(signature2.hex()))

    return signature1, signature2


address = single_tapscript_v1_address()
test, tx = start_node_send_coins(address)
spending_tx = construct_c_transaction(test, tx)
sig1, sig2 = sign_transaction(spending_tx, tx)
test.shutdown()