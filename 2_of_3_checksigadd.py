from test_framework.key import generate_bip340_key_pair
from test_framework.script import TapLeaf


def checksigadd_2_of_3():
    # Generate key pairs
    privkey1, pubkey1 = generate_bip340_key_pair()
    privkey2, pubkey2 = generate_bip340_key_pair()
    privkey3, pubkey3 = generate_bip340_key_pair()

    # Generate tapscript
    csa_tapscript = TapLeaf().construct_csa(2, [pubkey1, pubkey2, pubkey3])

    print("CSA tapscript operations:")
    for op in csa_tapscript.script:
        print(op.hex()) if isinstance(op, bytes) else print(op)

    # Satisfying witness element.
    print("\nSatisfying witness elements:")
    for element, value in csa_tapscript.sat:
        print("Witness element type is: {}".format(element))
        print("Signature corresponds to pubkey: {}".format(value.hex()))


checksigadd_2_of_3()