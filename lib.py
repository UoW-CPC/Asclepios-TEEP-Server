"""
Python bindings to the functions in demolib.so
"""

import ctypes
from ctypes import *
from base64 import b64encode,b64decode
import logging

# Get an instance of a logger
logger = logging.getLogger(__name__)

c_uint8_p = POINTER(c_uint8)
c_uchar_p = POINTER(c_ubyte)

libc = cdll.LoadLibrary('libc.so.6')

oe = cdll.LoadLibrary('host/demolib.so')

oe.oe_result_str.argtypes = [c_int32]
oe.oe_result_str.restype = c_char_p

oe.create_enclave_bytes.restype = c_void_p
oe.create_enclave_bytes.argtypes = [c_char_p, c_size_t]

oe.terminate_enclave.restype = c_int32
oe.terminate_enclave.argtypes = [c_void_p]

oe.get_remote_report_with_pubkey.restype = c_int32
oe.get_remote_report_with_pubkey.argtypes = [
    c_void_p, POINTER(c_int32),
    POINTER(c_uint8_p), POINTER(c_size_t),
    POINTER(c_uint8_p), POINTER(c_size_t)]

oe.verify_report_and_set_pubkey.argtypes = [
    c_void_p, POINTER(c_int32),
    c_uint8_p, c_size_t,
    c_uint8_p, c_size_t]


oe.seal_bytes.restype = c_int32
oe.seal_bytes.argtypes = [c_void_p, POINTER(c_int32),
                   c_char_p, c_size_t,
                   POINTER(c_uint8_p), POINTER(c_size_t) ]

oe.unseal_bytes.restype = c_int32
oe.unseal_bytes.argtypes = [c_void_p, POINTER(c_int32),
                   c_char_p, c_size_t,
                   POINTER(c_uint8_p), POINTER(c_size_t) ]

#oe.encrypt_block.restype = c_void
oe.encrypt_block.argtypes = [c_void_p,
                   c_bool, c_uchar_p, 
                   POINTER(c_uchar_p),c_size_t,
                   POINTER(c_size_t) ]

#oe.initialize_encryptor.restype = c_void
#oe.initialize_encryptor.argtypes = [c_void_p, c_bool, c_uchar_p,c_size_t] # POINTER(c_uchar_p) ] # AES CBC
oe.initialize_encryptor.argtypes = [c_void_p, c_uchar_p,c_size_t] # POINTER(c_uchar_p) ]
oe.close_encryptor.argtypes = [c_void_p]
#oe.initialize_encryptor_sealkey.argtypes = [c_void_p, c_bool, c_uchar_p, c_size_t ] # POINTER(c_uchar_p) ] # AES CBC
oe.initialize_encryptor_sealkey.argtypes = [c_void_p, c_uchar_p, c_size_t]#,POINTER(c_uchar_p) ] # AES CCM

def seal_bytes(enclave, b:bytes) -> int:
    ret = c_int32(123)
    output = c_uint8_p()
    output_size = c_size_t(0)
    
    res = oe.seal_bytes(enclave, byref(ret), b, len(b), byref(output), byref(output_size))
    res = oe.oe_result_str(res)
    ret = ret.value
    assert res == b'OE_OK' and ret == 0, f"Couldn't call seal_bytes ({res}, {ret})."
    out = bytes(output[:output_size.value])
    libc.free(output)
    return out

def unseal_bytes(enclave, b:bytes) -> int:
    ret = c_int32(123)
    output = c_uint8_p()
    output_size = c_size_t(0)
    res = oe.unseal_bytes(enclave, byref(ret), b, len(b), byref(output), byref(output_size))
    res = oe.oe_result_str(res)
    ret = ret.value
    assert res == b'OE_OK' and ret == 0, f"Couldn't call unseal_bytes ({res}, {ret})."
    out = bytes(output[:output_size.value])
    libc.free(output)
    return out


def create_enclave(b:bytes):
    return oe.create_enclave_bytes(b, len(b))

def terminate_enclave(e):
    return oe.terminate_enclave(e)

def get_remote_report_with_pubkey(enclave:c_void_p) -> (bytes, bytes):
    """wrapper for the function defined in ecalls.cpp
       and declared in remoteattestation.edl
    """
    key = c_uint8_p()
    ret = c_int32(123)
    keylen = c_size_t(0)
    report = c_uint8_p()
    reportlen = c_size_t(0)

    res = oe.get_remote_report_with_pubkey(
        enclave, byref(ret),
        byref(key), byref(keylen),
        byref(report), byref(reportlen)
    )

    res = oe.oe_result_str(res)
    ret = ret.value

    assert res == b'OE_OK' and ret == 0, f"Couldn't get_remote_report_with_pubkey ({res}, , {ret})."

    b = bytes(key[0:keylen.value])
    r = bytes(report[0:reportlen.value])

    libc.free(key)
    libc.free(report)

    return b, r


def verify_report_and_set_pubkey(enclave : c_void_p, key:bytes, report : bytes):
    ret = c_int32(123)

    res = oe.verify_report_and_set_pubkey(
        enclave, byref(ret),
        cast(key, c_uint8_p), len(key),
        cast(report, c_uint8_p), len(report))

    res = oe.oe_result_str(res)
    ret = ret.value

    assert res == b'OE_OK', f"Couldn't call verify_report_and_set_pubkey ({res}, {ret})."
    return ret



def pad(b:bytes, padding=16):
    m = len(b) % padding
    pad = b'\0' * ((padding - m) - 1)
    return b + pad + bytes([padding-m])

def unpad(b:bytes):
    return b[:-b[-1]]

#def encrypt(enclave:c_void_p,enc:c_bool,key:c_uchar_p,message:c_uchar_p) -> (bytes,int):   
def encrypt(enclave,enc:bool,key,message) -> (bytes,int):    
    """wrapper for the function defined in ecalls.cpp
       and declared in remoteattestation.edl
    """
    logger.debug("in lib.py - encrypt:%d, enclave:%d, key:%s, data:%s, key size:%d",enc,enclave,key,message,len(key))

    output_buf = c_uchar_p()
    size =len(message)

    #output_key = c_uchar_p()
    size_key=len(key) + 1 #plus 1 for the null char at the end of the key string 
    # oe.initialize_encryptor(enclave,enc,ctypes.cast(key,ctypes.POINTER(ctypes.c_ubyte)),size_key)#,byref(output_key)) # AES CBC
    oe.initialize_encryptor(enclave,ctypes.cast(key,ctypes.POINTER(ctypes.c_ubyte)),size_key) # AES CCM
    #print("in lib.py - output key:",cast(output_key,c_char_p).value)

    # encryption
    output_len=c_size_t(0)
    oe.encrypt_block(enclave,enc,ctypes.cast(message,ctypes.POINTER(ctypes.c_ubyte)),byref(output_buf),size,byref(output_len))
    
    oe.close_encryptor(enclave)
    if(enc):
        logger.debug("in lib.py: ciphertext:%s,length:%s",cast(output_buf,c_char_p).value,output_len.value)
        length=output_len.value
        message_output = bytes(output_buf[0:length])
    else:
        logger.debug("in lib.py: plaintext: %s, length: %s",cast(output_buf,c_char_p).value,output_len.value)
        message_output = cast(output_buf,c_char_p).value#bytes(output_buf)
    """
    # decryption - for testing only
    pt = c_uchar_p()
    pt_data_len=c_size_t(0)
    ct=output_buf
    ct_data_len = output_len.value
    oe.initialize_encryptor(enclave,False,ctypes.cast(key,ctypes.POINTER(ctypes.c_ubyte)),size_key)
    oe.encrypt_block(enclave,False,ct,byref(pt),ct_data_len,byref(pt_data_len))
    print("in lib.py: plaintext:",cast(pt,c_char_p).value[0:pt_data_len.value])
    print("in lib.py: len of plaintext:",pt_data_len.value)
    
    oe.close_encryptor(enclave)
    """
    return message_output,output_len.value

def encrypt_with_sealkey(enclave,enc:bool,sealed_key,message) -> (bytes,int):
    #output_key = c_uchar_p()
    size = len(sealed_key)
    #oe.initialize_encryptor_sealkey(enclave,enc,cast(sealed_key,POINTER(ctypes.c_ubyte)),size)#,byref(output_key)) # AES CBC
    oe.initialize_encryptor_sealkey(enclave,cast(sealed_key,POINTER(ctypes.c_ubyte)),size)#,byref(output_key)) # AES CCM
    #logger.debug("in lib.py - encrypted_with_sealkey func - sealed key:{} (length:{}),unsealed key:{} (length:{})",sealed_key,len(sealed_key),cast(output_key,c_char_p).value,len(cast(output_key,c_char_p).value))
    
    # encryption
    output_buf = c_uchar_p()
    size_msg =len(message)
    output_len=c_size_t(0)
    oe.encrypt_block(enclave,enc,ctypes.cast(message,ctypes.POINTER(ctypes.c_ubyte)),byref(output_buf),size_msg,byref(output_len))
    oe.close_encryptor(enclave)

    if(enc):
        length = output_len.value
        logger.debug("teep server - lib.py: plaintext:%s,ciphertext:%s,length:%d",message,cast(output_buf,c_char_p).value,length)
        message_output = bytes(output_buf[0:length])
    else:
        logger.debug("teep server - lib.py: plaintext:%s, length:%s",cast(output_buf,c_char_p).value,output_len.value)
        message_output = cast(output_buf,c_char_p).value
   
    return message_output,output_len.value
