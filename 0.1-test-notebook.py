
from util import TestWrapper
test = TestWrapper()
test.setup()
version = test.nodes[0].getnetworkinfo()['subversion']
print("Client version is {}".format(version))
assert "Satoshi" in version

blockchain_info = test.nodes[0].getblockchaininfo()
assert 'taproot' in blockchain_info['softforks']
assert blockchain_info['softforks']['taproot']['active']

test.shutdown()
