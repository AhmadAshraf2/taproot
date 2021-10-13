import util
from test_framework.address import program_to_witness
from test_framework.key import ECPubKey, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string
from test_framework.script import tagged_hash, Tapbranch, TapTree, TapLeaf, CScript, TaprootSignatureHash, OP_CHECKSIG, SIGHASH_ALL_TAPROOT

# Generate key pairs for internal pubkey and pay-to-pubkey tapscripts
privkey_internal, pubkey_internal = generate_bip340_key_pair()

privkeyA, pubkeyA = generate_bip340_key_pair()
privkeyB, pubkeyB = generate_bip340_key_pair()
privkeyC, pubkeyC = generate_bip340_key_pair()
privkeyD, pubkeyD = generate_bip340_key_pair()

# Construct Pay-to-Pubkey TapLeaves and Taptree.
TapLeafA = TapLeaf().construct_pk(pubkeyA)
TapLeafB = TapLeaf().construct_pk(pubkeyB)
TapLeafC = TapLeaf().construct_pk(pubkeyC)
TapLeafD = TapLeaf().construct_pk(pubkeyD)


def generate_taproot_address():

    # Create a Taptree with tapleaves and huffman constructor.
    # Method: TapTree.huffman_constructor(tuple_list)
    taptree = TapTree(key=pubkey_internal)
    taptree.huffman_constructor([(1, TapLeafA), (1, TapLeafB), (1, TapLeafC), (1, TapLeafD)])

    # Generate taproot tree with the `construct()` method, then use the taproot bytes to create a segwit address
    taproot_script, tweak, control_map = taptree.construct()
    taproot_pubkey = pubkey_internal.tweak_add(tweak)
    program = taproot_pubkey.get_bytes()
    address = program_to_witness(1, program)
    print("Address: {}".format(address))
    return address


def start_node():
    # Start node
    test = util.TestWrapper()
    test.setup()
    return test


def generate_coin(test):
    # Generate coins and create an output
    node = test.nodes[0]
    address = generate_taproot_address()
    tx = node.generate_and_send_coins(address)
    print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))
    return tx


def spend_tx(test, tx):
    # Create a spending transaction
    spending_tx = test.create_spending_transaction(tx.hash, version=2)
    print("Spending transaction:\n{}".format(spending_tx))
    return spending_tx


def sign_tx(spending_tx, tx):
    # Generate the taproot signature hash for signing
    sighashA = TaprootSignatureHash(spending_tx,
                                    [tx.vout[0]],
                                    SIGHASH_ALL_TAPROOT,
                                    input_index=0,
                                    scriptpath=True,
                                    script=TapLeafA.script)

    signatureA = privkeyA.sign_schnorr(sighashA)

    print("Signature for TapLeafA: {}\n".format(signatureA.hex()))


test = start_node()
tx = generate_coin(test)
spending_tx = spend_tx(test, tx)
sign_tx(spending_tx, tx)
test.shutdown()