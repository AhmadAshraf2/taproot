import util
from test_framework.address import program_to_witness
from test_framework.key import generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string, sha256
from test_framework.script import hash160, SIGHASH_ALL_TAPROOT, tagged_hash, TapLeaf, TaprootSignatureHash, TapTree

privkey_internal, pubkey_internal = generate_bip340_key_pair()
privkey1, pubkey1 = generate_bip340_key_pair()
privkey2, pubkey2 = generate_bip340_key_pair()
privkey3, pubkey3 = generate_bip340_key_pair()
privkey4, pubkey4 = generate_bip340_key_pair()


def generate_tapscript():
    csa_tapscript = TapLeaf().construct_csa(2, [pubkey1, pubkey2, pubkey3, pubkey4])
    return csa_tapscript


def taptweak_from_tapscript():
    tapscript = generate_tapscript()
    TAPSCRIPT_VER = bytes([0xc0])
    tapleaf = tagged_hash("TapLeaf", TAPSCRIPT_VER + ser_string(tapscript.script))
    taptweak = tagged_hash("TapTweak", pubkey_internal.get_bytes() + tapleaf)
    return taptweak, tapscript


def multisig_tapscript_address():
    taptweak, tapscript = taptweak_from_tapscript()
    taproot_pubkey = pubkey_internal.tweak_add(taptweak)
    taproot_pubkey_b = taproot_pubkey.get_bytes()
    program = taproot_pubkey_b
    # print("Witness program is {}\n".format(program.hex()))

    # Create (regtest) bech32m address
    version = 0x01
    address = program_to_witness(1, program)
    # print("bech32m address is {}".format(address))
    return address, tapscript


def start_node_send_coins(address):
    # Start node
    test = util.TestWrapper()
    test.setup()
    node = test.nodes[0]
    # Generate coins and create an output
    tx = node.generate_and_send_coins(address)
    print("first transaction:\n{}".format(tx))

    balance = node.getbalance()
    print("Balance: {}\n".format(balance))
    return test, tx


def construct_c_transaction(test, tx):
    spending_tx = test.create_spending_transaction(tx.hash)
    print("Spending transaction:\n{}".format(spending_tx))

    return spending_tx


def sign_transaction(spending_tx, tx, tapscript):
    sighash = TaprootSignatureHash(spending_tx,
                                   [tx.vout[0]],
                                   SIGHASH_ALL_TAPROOT,
                                   input_index=0,
                                   scriptpath=True,
                                   script=tapscript.script)

    # Sign with both privkeys
    signature1 = privkey1.sign_schnorr(sighash)
    signature2 = privkey2.sign_schnorr(sighash)

    # print("Signature1: {}".format(signature1.hex()))
    # print("Signature2: {}".format(signature2.hex()))

    return signature1, signature2


def add_witness_and_test_transaction(test, spending_tx):
    node = test.nodes[0]
    witness_elements = [sig2, sig1, tapscript.script, control_map[tapscript.script]]
    spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))

    print("Spending transaction:\n{}\n".format(spending_tx))

    node.test_transaction(spending_tx)
    # print("Success!")


address, tapscript = multisig_tapscript_address()
taptree = TapTree(key=pubkey_internal, root=tapscript)
_, _, control_map = taptree.construct()
test, tx = start_node_send_coins(address)
spending_tx = construct_c_transaction(test, tx)
sig1, sig2 = sign_transaction(spending_tx, tx, tapscript)
add_witness_and_test_transaction(test, spending_tx)
test.shutdown()
