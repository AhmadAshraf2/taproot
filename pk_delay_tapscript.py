from test_framework.key import generate_key_pair
from test_framework.musig import generate_musig_key
from test_framework.script import TapLeaf


def pk_delay_script():
    # Generate MuSig key
    privkey1, pubkey1 = generate_key_pair()
    privkey2, pubkey2 = generate_key_pair()
    c_map, pk_musig = generate_musig_key([pubkey1, pubkey2])

    if pk_musig.get_y() % 2 != 0:
        pk_musig.negate()
        privkey1.negate()
        privkey2.negate()

    # Generate pk_delay tapscript
    pk_delay_tapscript = TapLeaf().construct_pk_delay(pk_musig, 20)
    print("Tapscript descriptor:", pk_delay_tapscript.desc, "\n")

    print("Tapscript operations:")
    for op in pk_delay_tapscript.script:
        print(op.hex()) if isinstance(op, bytes) else print(op)

    print("\nSatisfying witness elements:")
    for element, value in pk_delay_tapscript.sat:
        print("{}, {}".format(element, value.hex()))

pk_delay_script()