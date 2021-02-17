"""
Python bindings to the functions in demolib.so
"""

import ctypes
from ctypes import *
c_uint8_p = POINTER(c_uint8)

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

