'''
Created on 29 nov. 2012

@author: Alexis
'''
import unittest
import cPickle

from tlslite.pickable.pureSha1 import sha1
from tlslite.pickable.pureMd5 import md5


class RecoveryTest(unittest.TestCase):
    
    def testRecoverSha(self):
        self._test(sha1)
        
    def testRecoverMD5(self):
        self._test(md5)
        
    def _test(self, klass):
        sentences = ["this is a short test", "9", "yy" * 120, "mp12" * 256, "pop" * 1027]
        for sentence in sentences:
            m1 = klass()
            m1.update(sentence[:len(sentence) / 2])
            
            pickled = cPickle.dumps(m1)
            m2 = cPickle.loads(pickled)
            
            m2.update(sentence[len(sentence) / 2:])
            self.assertEqual(m2.hexdigest(), klass(sentence).hexdigest())
