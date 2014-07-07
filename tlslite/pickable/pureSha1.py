'''
Created on 12 juin 2013

@author: Alexis
'''
import binascii


class sha1(object):
    """
    Inspired from:
    http://www.tamale.net/sha1/sha1-0.2/
    But fixed:
    - can call hexdigest multiple times
    - add new, copy, digest methods
    
    Copyright (c) 2005 Michael D. Leonhard
     
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:
     
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
     
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
    """
    digest_size = 20
    block_size = 64
    
    @staticmethod
    def lrot(num, b):
        return ((num << b) & 0xFFFFFFFF) | (num >> 32 - b)
    
    @staticmethod
    def BE32(byteData):
        return (ord(byteData[0]) << 24) | (ord(byteData[1]) << 16) | (ord(byteData[2]) << 8) | ord(byteData[3])
    
    @staticmethod
    def intTo4Bytes(num):
        return chr(num >> 24) + chr((num >> 16) & 0xFF) + chr((num >> 8) & 0xFF) + chr(num & 0xFF)
    
    @staticmethod
    def process(block, state):
        assert(len(block) == 64)
        # copy initial values
        a, b, c, d, e = state
        
        # expand message into W
        W = []
        for t in range(16):
            W.append(sha1.BE32(block[t * 4:t * 4 + 4]))
        for t in range(16, 80):
            W.append(sha1.lrot(W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16], 1))
        # do rounds
        for t in range(80):
            if t < 20:
                K = 0x5a827999
                f = (b & c) | ((b ^ 0xFFFFFFFF) & d)
            elif t < 40:
                K = 0x6ed9eba1
                f = b ^ c ^ d
            elif t < 60:
                K = 0x8f1bbcdc
                f = (b & c) | (b & d) | (c & d)
            else:
                K = 0xca62c1d6
                f = b ^ c ^ d
            TEMP = (sha1.lrot(a, 5) + f + e + W[t] + K) & 0xFFFFFFFF
            e = d
            d = c
            c = sha1.lrot(b, 30)
            b = a
            a = TEMP
        # add result
        a = (state[0] + a) & 0xFFFFFFFF
        b = (state[1] + b) & 0xFFFFFFFF
        c = (state[2] + c) & 0xFFFFFFFF
        d = (state[3] + d) & 0xFFFFFFFF
        e = (state[4] + e) & 0xFFFFFFFF
        return (a, b, c, d, e)
        
    @classmethod
    def new(cls, initial=None):
        return cls(initial)
    
    def __init__(self, newBytes=None):
        self.unprocessedBytes = ""
        self.size = 0
        self.state = (0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)
        
        if newBytes is not None:
            self.update(newBytes)
    
    def update(self, newBytes):
        self.size += len(newBytes)
        self.unprocessedBytes = self.unprocessedBytes + newBytes
        while len(self.unprocessedBytes) >= 64:
            self.state = self.process(self.unprocessedBytes[:64], self.state)
            self.unprocessedBytes = self.unprocessedBytes[64:]
            
    def digest(self):
        return binascii.a2b_hex(self.hexdigest())
        
    def hexdigest(self):
        # don't update our state - in case digest is called multiple times
        finalState = self.state

        # append 1 and seven 0 bits
        byteData = self.unprocessedBytes + chr(0x80)
        
        # no space for 8 length byteData
        if len(byteData) > 56:
            # fill it with zeros
            while len(byteData) < 64:
                byteData = byteData + chr(0)
            # process the filled block
            finalState = self.process(byteData, finalState)
            # now use an empty block
            byteData = ""
        # fill with zeros but leave space for 8 length byteData
        while len(byteData) < 56:
            byteData = byteData + chr(0)
        # append length
        numBits = self.size * 8
        byteData = byteData + self.intTo4Bytes((numBits >> 32) & 0xFFFFFFFF) + self.intTo4Bytes(numBits & 0xFFFFFFFF)
        # process this final block
        finalState = self.process(byteData, finalState)
        
        return "%08x%08x%08x%08x%08x" % finalState
    
    def copy(self):
        newOne = self.__class__()
        newOne.unprocessedBytes = self.unprocessedBytes
        newOne.size = self.size
        newOne.state = self.state
        return newOne
