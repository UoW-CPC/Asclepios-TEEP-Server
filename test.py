import ctypes
from ctypes import *
c_uint8_p = POINTER(c_uint8)

libc = cdll.LoadLibrary('libc.so.6')

oe = cdll.LoadLibrary('host/demolib.so')

oe.create_enclave_bytes.restype = c_void_p
oe.create_enclave_bytes.argtypes = [c_char_p, c_size_t]

oe.getpubkey.argtypes = [
    c_void_p,
    POINTER(c_uint8_p), POINTER(c_size_t),
    POINTER(c_uint8_p), POINTER(c_size_t)]

oe.verifyreport.argtypes = [
    c_void_p,
    c_uint8_p, c_size_t,
    c_uint8_p, c_size_t]

def new_enclave(b:bytes):
    return oe.create_enclave_bytes(b, len(b))

def getpubkey(enclave:c_void_p) -> (bytes, bytes):
    key = c_uint8_p()
    keylen = c_size_t(0)
    report = c_uint8_p()
    reportlen = c_size_t(0)
    ret = oe.getpubkey(
        enclave,
        byref(key), byref(keylen),
        byref(report), byref(reportlen))
    assert ret == 0, "Couldn't getpubkey."
    b = bytes(key[0:keylen.value])
    r = bytes(report[0:reportlen.value])
    libc.free(key)
    libc.free(report)
    return b, r

def verifyreport(enclave : c_void_p, key:bytes, report : bytes):
    return oe.verifyreport(enclave,
        cast(key, c_uint8_p), len(key),
        cast(report, c_uint8_p), len(report))
    
with open('enclave_a/enclave_a.signed', 'rb') as f:
    ea = new_enclave(f.read())
with open('enclave_b/enclave_b.signed', 'rb') as f:
    eb = new_enclave(f.read())

pa, ra = getpubkey(ea)
assert verifyreport(eb, pa, ra) == 0, "enclave b couldn't attest a"
pb, rb = getpubkey(eb)
assert verifyreport(ea, pb, rb) == 0, "enclave a couldn't attest b"

print("Both sides attested correctly.")
