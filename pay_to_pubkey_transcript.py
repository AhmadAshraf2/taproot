from test_framework.key import generate_bip340_key_pair
from test_framework.script import TapLeaf


def pay_to_public_transcript():
# Generate key pair
    privkey, pubkey = generate_bip340_key_pair()

    # Generate tapscript
    pk_tapscript = TapLeaf().construct_pk(pubkey)

    print("Tapscript operations:")
    for op in pk_tapscript.script:
        print(op.hex()) if isinstance(op, bytes) else print(op)

    print("\nSatisfying witness element:")
    for element, value in pk_tapscript.sat:
        print("Witness element type is: {}".format(element))
        print("Signature corresponds to pubkey: {}".format(value.hex()))


pay_to_public_transcript()