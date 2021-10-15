import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair
from test_framework.messages import CTxInWitness, ser_string, sha256
from test_framework.musig import generate_musig_key
from test_framework.script import hash160, SIGHASH_ALL_TAPROOT, tagged_hash, TapLeaf, TaprootSignatureHash, TapTree


# Generate key pairs
privkey1, pubkey1 = generate_bip340_key_pair()
privkey2, pubkey2 = generate_bip340_key_pair()

print("pubkey1: {}".format(pubkey1.get_bytes().hex()))
print("pubkey2: {}\n".format(pubkey2.get_bytes().hex()))

# Method: 32B preimage - sha256(bytes)
# Method: 20B digest - hash160(bytes)
secret = b'secret'
preimage = sha256(secret)
digest = hash160(preimage)
delay = 20

# Construct tapscript
csa_hashlock_delay_tapscript = TapLeaf().construct_csa_hashlock_delay(2, [pubkey1, pubkey2], digest, delay)
print("Descriptor:", csa_hashlock_delay_tapscript.desc, "\n")

print("Tapscript operations:")
for op in csa_hashlock_delay_tapscript.script:
    print(op.hex()) if isinstance(op, bytes) else print(op)

print("\nSatisfying witness elements:")
for element, value in csa_hashlock_delay_tapscript.sat:
    print("{}, {}".format(element, value.hex()))


privkey_internal, pubkey_internal = generate_bip340_key_pair()

# Method: ser_string(Cscript) prepends compact size.
TAPSCRIPT_VER = bytes([0xc0])
tapleaf = tagged_hash("TapLeaf", TAPSCRIPT_VER + ser_string(csa_hashlock_delay_tapscript.script))
taptweak = tagged_hash("TapTweak", pubkey_internal.get_bytes() + tapleaf)
print("Your constructed taptweak is: {}.".format(taptweak.hex()))



taptree = TapTree(key=pubkey_internal, root=csa_hashlock_delay_tapscript)
segwit_v1_script, tap_tweak_constructed, control_map = taptree.construct()

assert taptweak == tap_tweak_constructed
print("Success! Your constructed taptweak is correct.")



taproot_pubkey = pubkey_internal.tweak_add(taptweak)
taproot_pubkey_b = taproot_pubkey.get_bytes()
program = taproot_pubkey_b
print("Witness program is {}\n".format(program.hex()))

# Create (regtest) bech32m address
version = 0x01
address = program_to_witness(1, program)
print("bech32m address is {}".format(address))


# Start node
test = util.TestWrapper()
test.setup()
node = test.nodes[0]

# Generate coins and create an output
tx = node.generate_and_send_coins(address)
print("Transaction {}, output 0\nsent to {}\n".format(tx.hash, address))

# Create a spending transaction
spending_tx = test.create_spending_transaction(tx.hash, version=2, nSequence=delay)
print("Spending transaction:\n{}".format(spending_tx))

# Generate the Taproot Signature Hash for signing
sighash = TaprootSignatureHash(spending_tx,
                               [tx.vout[0]],
                               SIGHASH_ALL_TAPROOT,
                               input_index=0,
                               scriptpath=True,
                               script=csa_hashlock_delay_tapscript.script)

# Sign with both privkeys
signature1 = privkey1.sign_schnorr(sighash)
signature2 = privkey2.sign_schnorr(sighash)
print("Signature1: {}".format(signature1.hex()))
print("Signature2: {}".format(signature2.hex()))


# #### _Programming Exercise 2.3.12:_ Add the witness and test acceptance of the transaction
witness_elements = [preimage, signature2, signature1, csa_hashlock_delay_tapscript.script, control_map[csa_hashlock_delay_tapscript.script]]
spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
print("Spending transaction:\n{}\n".format(spending_tx))
# Test mempool acceptance with and without delay
assert not node.test_transaction(spending_tx)
node.generate(delay)
assert node.test_transaction(spending_tx)
print("Success!")

# Shutdown
test.shutdown()
