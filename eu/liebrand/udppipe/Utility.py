"""
Created on 29.12.2010

@author: mark
"""
import sys
import traceback


class SockIOException(Exception):

    def __init__(self):
        return


class SockIOData:
    typeString = 1
    typeNumber = 2
    typeCommand = 3
    typeBinary = 4
    typeLongDirect = 64


class SockWrite(SockIOData):
    '''
    classdocs
    '''

    def __init__(self):
        pass

    def writeString(self, key, value, bytesIO):
        bytesIO.write(bytes([SockIOData.typeString]))
        self.__writeRawString(key, bytesIO)
        self.__writeRawString(value, bytesIO)

    def __writeRawString(self, strg, bytesIO):
        length = len(strg)
        hiByte = int(abs(length / 256))
        loByte = length % 256
        bytesIO.write(bytes([hiByte, loByte]))
        bytesIO.write(strg.encode('UTF-8'))

    def writeLongDirect(self, value, bytesIO):
        bytesIO.write(bytes([SockIOData.typeLongDirect]))
        Byte0 = int(abs(value / 16777216))
        value = value % 16777216
        Byte1 = int(abs(value / 65536))
        value = value % 65536
        Byte2 = int(abs(value / 256))
        Byte3 = value % 256
        bytesIO.write(bytes([Byte0, Byte1, Byte2, Byte3]))

    def writeBinaryDirect(self, value, bytesIO):
        bytesIO.write(value)

    def writeBinary(self, key, value, bytesIO):
        bytesIO.write(bytes([SockIOData.typeBinary]))
        self.__writeRawString(key, bytesIO)
        ln = len(value)
        Byte0 = int(abs(ln / 16777216))
        ln = ln % 16777216
        Byte1 = int(abs(ln / 65536))
        ln = ln % 65536
        Byte2 = int(abs(ln / 256))
        Byte3 = ln % 256
        bytesIO.write(bytes([Byte0, Byte1, Byte2, Byte3]))
        bytesIO.write(value)

    def writeLong(self, key, value, bytesIO):
        bytesIO.write(bytes([SockIOData.typeNumber]))
        self.__writeRawString(key, bytesIO)
        Byte0 = int(abs(value / 16777216))
        value = value % 16777216
        Byte1 = int(abs(value / 65536))
        value = value % 65536
        Byte2 = int(abs(value / 256))
        Byte3 = value % 256
        bytesIO.write(bytes([Byte0, Byte1, Byte2, Byte3]))


class SockRead(SockIOData):

    ###
    # Returns a tuple
    # dataType, key, value
    def read(self, bytesIO):
        typ = int.from_bytes(bytesIO.read(1))
        if typ==0:
            raise SockIOException
        key, value = {SockIOData.typeString: lambda: (self.__readRawString(bytesIO), self.__readRawString(bytesIO)),
                      SockIOData.typeNumber: lambda: (self.__readRawString(bytesIO), self.__readRawLong(bytesIO)),
                      SockIOData.typeBinary: lambda: (self.__readRawString(bytesIO), self.__readRawBinary(bytesIO)),
                      SockIOData.typeLongDirect: lambda: ("", self.__readRawLong(bytesIO))
                      }[typ]()
        return typ, key, value

    def __readRawString(self, bytesIO):
        hiByte = ord(bytesIO.read(1))
        loByte = ord(bytesIO.read(1))
        length = (hiByte << 8) + loByte
        strg = bytesIO.read(length).decode('utf-8')
        return strg

    def __readRawLong(self, bytesIO):
        byte0 = ord(bytesIO.read(1))
        byte1 = ord(bytesIO.read(1))
        byte2 = ord(bytesIO.read(1))
        byte3 = ord(bytesIO.read(1))
        value = (byte0 * 16777216) + (byte1 * 65536) + (byte2 * 256) + byte3
        return value

    def __readRawBinary(self, bytesIO):
        length = self.__readRawLong(bytesIO)
        binary = bytesIO.read(length)
        return binary


class ReadDictionary:

    def __init__(self):
        pass

    def read(self, data):
        d = {}
        sockRd = SockRead()
        dumpBytes(data)
        buf = BytesIO(data)
        try:
            while True:
                _, key, value = sockRd.read(buf)
                d[key] = value
        except SockIOException:
            pass
        buf.close()
        return d


class WriteDictionary:

    def write(self, data):
        sockWt = SockWrite()
        buf = StringIO(data)
        for k in data.keys:
            if type(data[k]) is int:
                sockWt.writeLong(k, data[k], buf)
            if type(data[k]) is str:
                sockWt.writeString(k, data[k], buf)
            if type(data[k] is dict):
                sockWt.writeBinary(k, self.write(data[k]), buf)


import binascii
from io import StringIO, BytesIO


class PKCS7Encoder(object):
    '''
    RFC 2315: PKCS#7 page 21
    Some content-encryption algorithms assume the
    input length is a multiple of k octets, where k > 1, and
    let the application define a method for handling inputs
    whose lengths are not a multiple of k octets. For such
    algorithms, the method shall be to pad the input at the
    trailing end with k - (l mod k) octets all having value k -
    (l mod k), where l is the length of the input. In other
    words, the input is padded at the trailing end with one of
    the following strings:
 
             01 -- if l mod k = k-1
            02 02 -- if l mod k = k-2
                        .
                        .
                        .
          k k ... k k -- if l mod k = 0
 
    The padding can be removed unambiguously since all input is
    padded and no padding string is a suffix of another. This
    padding method is well-defined if and only if k < 256;
    methods for larger k are an open issue for further study.
    '''

    def __init__(self, k=16):
        self.k = k

    ## @param text The padded text for which the padding is to be removed.
    # @exception ValueError Raised when the input padding is missing or corrupt.
    def decode(self, text):
        '''
        Remove the PKCS#7 padding from a text string
        '''
        nl = len(text)
        val = int(binascii.hexlify(text[-1]), 16)
        if val > self.k:
            raise ValueError('Input is not padded or padding is corrupt')

        l = nl - val
        return text[:l]

    ## @param text The text to encode.
    def encode(self, text):
        '''
        Pad an input string according to PKCS#7
        '''
        l = len(text)
        output = StringIO()
        val = self.k - (l % self.k)
        for _ in range(val):
            output.write('%02x' % val)
        return text + binascii.unhexlify(output.getvalue())


def formatExceptionInfo(log, maxTBlevel=5):
    cla, exc, trbk = sys.exc_info()
    excName = cla.__name__
    try:
        excArgs = exc.__dict__["args"]
    except KeyError:
        excArgs = "<no args>"
    excTb = traceback.format_tb(trbk, maxTBlevel)
    log.debug(excName)
    log.debug(excArgs)
    log.debug(excTb)


FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])


def dump(src, length=8):
    N = 0;
    result = ''
    while src:
        s, src = src[:length], src[length:]
        hexa = ' '.join(["%02X" % x for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length * 3, hexa, s)
        N += length
    return result

def dumpBytes(bts):
    print(bts.hex(sep=' '))