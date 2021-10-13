from test_framework.key import generate_bip340_key_pair
from test_framework.messages import sha256
from test_framework.script import hash160, TapLeaf


def csa_hash_block():
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

    return csa_hashlock_delay_tapscript


csa_hash_block()
