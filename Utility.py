'''
Created on 29.12.2010

@author: mark
'''
import cStringIO
import exceptions
import sys
import traceback

class SockIOException(exceptions.Exception):
    
    def __init__(self):
        return

class SockIOData:

    typeString=1
    typeNumber=2
    typeCommand=3
    typeBinary=4
    typeLongDirect=64
    
        

    

class SockWrite(SockIOData):
    '''
    classdocs
    '''
    def __init__(self):
        pass

    
    def writeString(self, key, value, strgIO):
        strgIO.write(chr(SockIOData.typeString))
        self.__writeRawString(key, strgIO)
        self.__writeRawString(value, strgIO)
    
    def __writeRawString(self, strg, strgIO):
        length=len(strg)
        hiByte=abs(length / 256)
        loByte=length % 256
        strgIO.write(chr(hiByte))
        strgIO.write(chr(loByte))
        strgIO.write(strg)
        
    def writeLongDirect(self, value, strgIO):
        strgIO.write(chr(SockIOData.typeLongDirect))
        Byte0=abs(value / 16777216)
        value=value % 16777216
        Byte1=abs(value / 65536)
        value=value % 65536
        Byte2=abs(value / 256)
        Byte3=value % 256
        strgIO.write(chr(Byte0))
        strgIO.write(chr(Byte1))
        strgIO.write(chr(Byte2))
        strgIO.write(chr(Byte3))

        
    def writeBinaryDirect(self, value, strgIO):
        strgIO.write(value)
        
    def writeBinary(self, key, value, strgIO):
        strgIO.write(chr(SockIOData.typeBinary))
        self.__writeRawString(key, strgIO)
        ln=len(value)
        Byte0=abs(ln / 16777216)
        ln=ln % 16777216
        Byte1=abs(ln / 65536)
        ln=ln % 65536
        Byte2=abs(ln / 256)
        Byte3=ln % 256
        strgIO.write(chr(Byte0))
        strgIO.write(chr(Byte1))
        strgIO.write(chr(Byte2))
        strgIO.write(chr(Byte3))
        strgIO.write(value)
        
    def writeLong(self, key, value, strgIO):
        strgIO.write(chr(SockIOData.typeNumber))
        self.__writeRawString(key, strgIO)
        Byte0=abs(value / 16777216)
        value=value % 16777216
        Byte1=abs(value / 65536)
        value=value % 65536
        Byte2=abs(value / 256)
        Byte3=value % 256
        strgIO.write(chr(Byte0))
        strgIO.write(chr(Byte1))
        strgIO.write(chr(Byte2))
        strgIO.write(chr(Byte3))
        
        
class SockRead(SockIOData):
    
    
    ###
    # Returns a tuple
    # dataType, key, value
    def read(self, strgIO):
        tmp=strgIO.read(1)
        if len(tmp)==0:
            raise SockIOException()
        typ=ord(tmp)    
        key, value = { SockIOData.typeString : lambda : (self.__readRawString(strgIO), self.__readRawString(strgIO)),
                       SockIOData.typeNumber : lambda : (self.__readRawString(strgIO), self.__readRawLong(strgIO)),
                       SockIOData.typeBinary : lambda : (self.__readRawString(strgIO), self.__readRawBinary(strgIO)),
                       SockIOData.typeLongDirect : lambda : ( "", self.__readRawLong(strgIO))
                      } [typ]()
        return (typ, key, value)
    
    
    def __readRawString(self, strgIO):
        hiByte=ord(strgIO.read(1))
        loByte=ord(strgIO.read(1))
        length=(hiByte<<8)+loByte
        strg=strgIO.read(length)
        return (strg)

    def __readRawLong(self, strgIO):
        byte0=ord(strgIO.read(1))
        byte1=ord(strgIO.read(1))
        byte2=ord(strgIO.read(1))
        byte3=ord(strgIO.read(1))
        value=(byte0 * 16777216) + (byte1*65536) + (byte2*256) + byte3
        return value

    def __readRawBinary(self, strgIO):
        length=self.__readRawLong(strgIO)
        binary=strgIO.read(length)
        return binary

    
class ReadDictionary:
    
    def __init__(self):
        pass
    
    def read(self, data):
        d={}
        sockRd=SockRead()
        buf=cStringIO.StringIO(data)
        try:
            while True:                            
                _, key, value=sockRd.read(buf)
                d[key]=value
        except SockIOException:
            pass
        buf.close()
        return d

class WriteDictionary:
    
    def write(self, data):
        sockWt=SockWrite()
        buf=cStringIO.StringIO(data)
        for k in data.keys:
            if (type(data[k]) is int) or (type(data[k]) is long):
                sockWt.writeLong(k, data[k], buf)
            if type(data[k]) is str:
                sockWt.writeString(k, data[k], buf)
            if type(data[k] is dict):
                sockWt.writeBinary(k, WriteDictionary.write(data[k]), buf)
                
            
        
import binascii
import StringIO
 
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
        output = StringIO.StringIO()
        val = self.k - (l % self.k)
        for _ in xrange(val):
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
    
 
FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def dump(src, length=8):
    N=0; result=''
    while src:
        s,src = src[:length],src[length:]
        hexa = ' '.join(["%02X"%ord(x) for x in s])
        s = s.translate(FILTER)
        result += "%04X   %-*s   %s\n" % (N, length*3, hexa, s)
        N+=length
    return result
       
    