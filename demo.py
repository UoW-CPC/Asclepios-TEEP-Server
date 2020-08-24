import ctypes
from ctypes import *
c_uint8_p = POINTER(c_uint8)

libc = cdll.LoadLibrary('libc.so.6')

oe = cdll.LoadLibrary('host/demolib.so')

oe.oe_result_str.argtypes = [c_int32]
oe.oe_result_str.restype = c_char_p

oe.create_enclave_bytes.restype = c_void_p
oe.create_enclave_bytes.argtypes = [c_char_p, c_size_t]

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

with open('enclave_a/enclave_a.signed', 'rb') as f:
    ea = create_enclave(f.read())
    
with open('enclave_a/enclave_a.signed', 'rb') as f:
    ea2 = create_enclave(f.read())

with open('enclave_b/enclave_b.signed', 'rb') as f:
    eb = create_enclave(f.read())

# ask the enclave about its public key and get a report
pa, ra = get_remote_report_with_pubkey(ea)
# ask the other enclave to verify the report and store the pubkey
res = verify_report_and_set_pubkey(eb, pa, ra) 
assert res == 0, "enclave b couldn't attest a"

# and the same the other way around
pb, rb = get_remote_report_with_pubkey(eb)
res = verify_report_and_set_pubkey(ea, pb, rb)
assert res == 0, "enclave a couldn't attest b"

print("Both sides attested correctly.")

if False:
    """this is how the MRSIGNER is computed in crypto.cpp; 
         as the SHA256 of the public key modulus in little endian"""
    import Crypto.PublicKey.RSA as RSA
    import Crypto.Hash.SHA256 as SHA256
    import binascii
    from math import log
    pak = RSA.importKey(pa[:pa.find(b'\0')])
    modulus = pak.n
    modulus_len = 1+int(log(modulus)/log(256))
    modulus_bytes_le = bytes([(modulus>>(8*i))%256 for i in range(modulus_len)])
    s = SHA256.new(); s.update(modulus_bytes_le); d = s.digest()
    print(binascii.hexlify(d).decode())



def pad(b:bytes, padding=16):
    m = len(b) % padding
    pad = b'\0' * ((padding - m) - 1)
    return b + pad + bytes([padding-m])

def unpad(b:bytes):
    return b[:-b[-1]]


# seal data to enclaves that uses ea's code

s = seal_bytes(ea, pad('kalle anka satt på en planka'.encode(), 16))
print('ea2 sees: ', unpad(unseal_bytes(ea2, s)).decode())
print('eb sees:  ', unpad(unseal_bytes(eb, s)).decode())
