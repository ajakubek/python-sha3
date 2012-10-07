#!/usr/bin/env python
# -*- coding: utf-8 -*-
import binascii
import unittest
from sha3 import sha224, sha256, sha384, sha512

def digest2hex(digest):
    return binascii.hexlify(digest).decode()

class test_sha3(unittest.TestCase):

    def test_init(self):
        self.assertNotEqual(self.sha(), None)

    def test_empty_hash(self):
        self.assertEqual(self.h.hexdigest(), self.empty_hexdigest)

    def test_str(self):
        self.assertTrue(isinstance(str(self.h), str))

    def test_repr(self):
        self.assertTrue(isinstance(repr(self.h), str))

    def test_digest_size(self):
        self.assertEqual(self.h.digest_size, self.digest_size)
        self.assertEqual(len(self.h.digest()), self.h.digest_size)

    def test_hexdigest_size(self):
        self.assertEqual(len(self.h.hexdigest()), self.digest_size * 2)

    def test_block_size(self):
        self.assertEqual(self.h.block_size, self.block_size)

    def test_rate(self):
        self.assertEqual(self.h.rate, self.rate)

    def test_capacity(self):
        self.assertEqual(self.h.capacity, self.capacity)

    def test_invalid_message(self):
        invalid_types = [None, 0, 1.0, [], set()]
        for message in invalid_types:
            self.assertRaises(TypeError, self.h.update, message)

    def test_vectors_bytes(self):
        for message, hex_digest in self.vectors:
            h = self.sha()
            h.update(message.encode())
            self.assertEqual(h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(h.digest()), hex_digest)
            # make sure that subsequent finish calls do not modify digest
            self.assertEqual(h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(h.digest()), hex_digest)

    def test_vectors_bytes_extended(self):
        for message, hex_digest in self.vectors_extended:
            self.h.update(message.encode())
            self.assertEqual(self.h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(self.h.digest()), hex_digest)
            # make sure that subsequent finish calls do not modify digest
            self.assertEqual(self.h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(self.h.digest()), hex_digest)

    def test_vectors_unicode(self):
        for message, hex_digest in self.vectors:
            h = self.sha()
            h.update(message)
            self.assertEqual(h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(h.digest()), hex_digest)
            # make sure that subsequent finish calls do not modify digest
            self.assertEqual(h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(h.digest()), hex_digest)

    def test_vectors_unicode_extended(self):
        for message, hex_digest in self.vectors_extended:
            self.h.update(message)
            self.assertEqual(self.h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(self.h.digest()), hex_digest)
            # make sure that subsequent finish calls do not modify digest
            self.assertEqual(self.h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(self.h.digest()), hex_digest)

    def test_copy(self):
        copy = self.h.copy()
        h_orig_digest = self.h.hexdigest()
        copy_orig_digest = copy.hexdigest()
        self.assertEqual(h_orig_digest, copy_orig_digest)
        self.assertEqual(self.h.digest_size, copy.digest_size)
        self.assertEqual(self.h.block_size, copy.block_size)
        self.assertEqual(self.h.rate, copy.rate)
        self.assertEqual(self.h.capacity, copy.capacity)
        for message, hex_digest in self.vectors_extended:
            self.h.update(message)
            self.assertEqual(copy.hexdigest(), copy_orig_digest)
            self.assertEqual(digest2hex(copy.digest()), copy_orig_digest)
            self.assertEqual(self.h.hexdigest(), hex_digest)
            self.assertEqual(digest2hex(self.h.digest()), hex_digest)


class test_sha_224(test_sha3):

    def setUp(self):
        self.sha = sha224
        self.h = sha224()
        self.digest_size = 224 / 8
        self.block_size = 1152 / 8
        self.rate = 1152
        self.capacity = 448
        self.empty_hexdigest = 'f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd'
        self.vectors = [
            ('', 'f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd'),
            ('abcd', 'be2ec6c1cce305a0ba88300bfcad0ab0b9f480f964be34b2cd253199'),
            ('abcdefgh', '6b1f16d8ad4d5f51fe46d837480011df14fa2864a89dc887ee3d7134'),
            ('a'*1024*1024, '9318ddf4f64d3b24162ac76957c4ae7ea7e90d2ebb7c40d1ab19fb72'),
            ('\0'*1024*1024, 'c9f87efa6f26a8cdad2afd78d876e13a018938e21c3b0c05d110585b'),
        ]
        self.vectors_extended = [
            ('', 'f71837502ba8e10837bdd8d365adb85591895602fc552b48b7390abd'),
            ('abcd', 'be2ec6c1cce305a0ba88300bfcad0ab0b9f480f964be34b2cd253199'),
            ('efgh', '6b1f16d8ad4d5f51fe46d837480011df14fa2864a89dc887ee3d7134'),
            ('a'*1024*1024, '0dc0c7ae839ed2bc898ee69e84ab71f10b046d84d98f65c2be699a1a'),
            ('\0'*1024*1024, 'd62e3fde25c81a0ccff379075ba3385148d0da2b163c14ca194cf28a'),
        ]

class test_sha_256(test_sha3):

    def setUp(self):
        self.sha = sha256
        self.h = sha256()
        self.digest_size = 256 / 8
        self.block_size = 1088 / 8
        self.rate = 1088
        self.capacity = 512
        self.empty_hexdigest = 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'
        self.vectors = [
            ('', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
            ('abcd', '48bed44d1bcd124a28c27f343a817e5f5243190d3c52bf347daf876de1dbbf77'),
            ('abcdefgh', '48624fa43c68d5c552855a4e2919e74645f683f5384f72b5b051b71ea41d4f2d'),
            ('a'*1024*1024, 'f5f3e54ad3d703f8e9edfd7ce79341b1d9286a692fa6c13ff13ee6ea94dbf97d'),
            ('\0'*1024*1024, '7b6ff0a03e9c5a8e77a2059bf28e26a7f0e8d3939a7cfe2193908ad8d683be90'),
        ]
        self.vectors_extended = [
            ('', 'c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470'),
            ('abcd', '48bed44d1bcd124a28c27f343a817e5f5243190d3c52bf347daf876de1dbbf77'),
            ('efgh', '48624fa43c68d5c552855a4e2919e74645f683f5384f72b5b051b71ea41d4f2d'),
            ('a'*1024*1024, '5b43799db735425a91016fb82240b775337a8c92e58512bf107f61b8342a4b95'),
            ('\0'*1024*1024, 'bf7c1b61e4568cc09140b0543a1be49989b0b9145d15e1a395d57939d5642580'),
        ]

class test_sha_384(test_sha3):

    def setUp(self):
        self.sha = sha384
        self.h = sha384()
        self.digest_size = 384 / 8
        self.block_size = 832 / 8
        self.rate = 832
        self.capacity = 768
        self.empty_hexdigest = '2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff'
        self.vectors = [
            ('', '2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff'),
            ('abcd', '565c4034428749960ad82523596b0bb422986c1941463ce4678e81391c6eb3e47be5d85b9394217dc7d25dda8328f392'),
            ('abcdefgh', '3f57fa1fe45b9dbfdd3c0e07fe5807c2c70ee6935bd35b2cf35750b52b15bdbbde372d8c4aee50013326fec4d86af805'),
            ('a'*1024*1024, 'a31e9cc5636b078739005e5ba799adc81c00121c9155e754e84a0efcd9b48f5144abf40ab5cfeea7f0045e9076dfe547'),
            ('\0'*1024*1024, '0f2e8d8c47013f356a5d9efc5a754e2c826aa3b411e549ab193cc30a49b1a3e984ff7a065306ce30834e1176331ec8b7'),

        ]
        self.vectors_extended = [
            ('', '2c23146a63a29acf99e73b88f8c24eaa7dc60aa771780ccc006afbfa8fe2479b2dd2b21362337441ac12b515911957ff'),
            ('abcd', '565c4034428749960ad82523596b0bb422986c1941463ce4678e81391c6eb3e47be5d85b9394217dc7d25dda8328f392'),
            ('efgh', '3f57fa1fe45b9dbfdd3c0e07fe5807c2c70ee6935bd35b2cf35750b52b15bdbbde372d8c4aee50013326fec4d86af805'),
            ('a'*1024*1024, '0eb8a277dcec02b31fa3c0559da769a2b8d91bb4837946e06ad4aa0b06f93d3cd424c0e17d4e419033aa9c0107ca63f7'),
            ('\0'*1024*1024, 'ab1dcde267d73b300f72c1085232b64791c50dac240da2102dd159195406e8b0363cfff4c68bf0241d384f0d8ef7d351'),
        ]

class test_sha_512(test_sha3):

    def setUp(self):
        self.sha = sha512
        self.h = sha512()
        self.digest_size = 512 / 8
        self.block_size = 576 / 8
        self.rate = 576
        self.capacity = 1024
        self.empty_hexdigest = '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e'
        self.vectors = [
            ('', '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e'),
            ('abcd', 'e4a7e8f5572f4853ef26a862f31687c249b1cd7922df2aac1f4348d8ceef944c74d1949e3465704a5f3f89fb53e0dcce3ea142c90af04c84cc7e548f144f8f0b'),
            ('abcdefgh', 'c96950698dd2e6e2051637687d676a64bf7170908d69004cab008fb4d5d25d780be1e0ca503f947f07859dd477249787705ef813b64abb6477a22aa1fb908d1d'),
            ('a'*1024*1024, 'b978f7ddb14b67d6ab89bc659be206cf3438cefe386bd9e025a7f7706759a6c25be415aebfbda582a446a45cbd5da03ea20197263907a7b2fe5002d1c2bcbee2'),
            ('\0'*1024*1024, '696adf53f32a68f4f5d92b44c2b46127b05dd2f4c590d09314949a68dc73384b7ecbd371dc3ff5896d2c49ab69d906116bd047fc29fa7f426843011819440396'),
        ]
        self.vectors_extended = [
            ('', '0eab42de4c3ceb9235fc91acffe746b29c29a8c366b7c60e4e67c466f36a4304c00fa9caf9d87976ba469bcbe06713b435f091ef2769fb160cdab33d3670680e'),
            ('abcd', 'e4a7e8f5572f4853ef26a862f31687c249b1cd7922df2aac1f4348d8ceef944c74d1949e3465704a5f3f89fb53e0dcce3ea142c90af04c84cc7e548f144f8f0b'),
            ('efgh', 'c96950698dd2e6e2051637687d676a64bf7170908d69004cab008fb4d5d25d780be1e0ca503f947f07859dd477249787705ef813b64abb6477a22aa1fb908d1d'),
            ('a'*1024*1024, 'c909d64f3a3b448f008f10fe7e3363e42dc3c798a8ae70f0c20e727abbd01923bd98beb6a9e62494b432ce567887800c500e808d7d1c1e91bd023600ac184a80'),
            ('\0'*1024*1024, 'ba9e08b95ca58a296e74593614ffc9601c4d1911027d010b3a49b211577d73af7f60e9c5490309a1ee64c7bbcbf37a967b3aef4b3a126d107f75041a36359585'),
        ]


def suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(test_sha_224))
    suite.addTest(unittest.makeSuite(test_sha_256))
    suite.addTest(unittest.makeSuite(test_sha_384))
    suite.addTest(unittest.makeSuite(test_sha_512))
    return suite


if __name__ == '__main__':
    unittest.TextTestRunner(verbosity=2).run(suite())
