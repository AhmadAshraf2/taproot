from test_framework.key import generate_bip340_key_pair
from test_framework.script import TapLeaf


def multisig_2_of_3():
    # Generate key pairs
    privkey1, pubkey1 = generate_bip340_key_pair()
    privkey2, pubkey2 = generate_bip340_key_pair()
    privkey3, pubkey3 = generate_bip340_key_pair()

    # Generate tapscripts
    pubkeys = [pubkey1, pubkey2, pubkey3]
    tapscripts = TapLeaf.generate_threshold_csa(2, pubkeys)

    print("2-of-3 multisig expressed as 2-of-2 checkigadd tapscripts:")
    for ts in tapscripts:
        print(ts.desc)

multisig_2_of_3()
