import asyncio
import aiocoap
import aiocoap.resource
import cbor
import binascii

import Crypto.Hash.SHA256 as SHA256
import Crypto.PublicKey.RSA as RSA
import Crypto.Cipher.PKCS1_OAEP as PKCS1_OAEP # or PKCS1_v1_5

from lib import *

def catcher(f):
    try: return f()
    except: return None


### Server

class myresource(aiocoap.resource.Resource):
    cnt = 0
    enclaves = []
    async def render_put(self, request):
        input = cbor.loads(request.payload)
        output = cbor.dumps({'error':1})
        if 'install' in input:
            e_binary = input['install']
            s = SHA256.new(); s.update(e_binary); h = s.digest()
            e = create_enclave(e_binary)
            id = len(self.enclaves)
            self.enclaves.append((s,e))
            if e != None:
                r = get_remote_report_with_pubkey(e)
                if r != None:
                    output = cbor.dumps({'key':r[0], 'report': r[1], 'id':id, 'sha':h})

        elif 'seal' in input:
            (s, e) = self.enclaves[input['id']]
            sd = seal_bytes(e, pad(input['seal'], 16))
            output = cbor.dumps({'sealed': sd})
            
        elif 'unseal' in input:
            (s, e) = self.enclaves[input['id']]
            d = unpad(unseal_bytes(e, input['unseal']))
            print(d)
            output = cbor.dumps({'data': d})
            
        return aiocoap.Message(code=aiocoap.CONTENT, payload=output)

def start_server():
    root = aiocoap.resource.Site()
    root.add_resource(['teep'], myresource())
    e = asyncio.get_event_loop()
    ctx = aiocoap.Context.create_server_context(root)
    e = asyncio.get_event_loop()
    e.create_task(ctx)
    e.run_forever()


### Client

async def put_coap(uri, data:bytes):
    msg = aiocoap.Message(uri=uri,
        code=aiocoap.PUT,
        payload=data)
        
    ctx = await aiocoap.Context.create_client_context()
    return await ctx.request(msg).response

def ask(query={'donald':'duck'}):
    uri = 'coap://127.0.0.1/teep'
    response = asyncio.run(put_coap(uri, cbor.dumps(query)))
    return cbor.loads(response.payload)
    
def install(filename):
    with open(filename, 'rb') as f: binary = f.read()
    uri = 'coap://127.0.0.1/teep'
    response = asyncio.run(put_coap(uri, cbor.dumps({'install':binary})))
    return cbor.loads(response.payload)


"""
python -c 'import simple; simple.start_server()' & 
python -c 'import simple; print(simple.ask({"hello":"word"}))'
"""    


"""
python -c 'import simple; simple.test()'
"""
def test():
    # Ask the remote TEEP agent to create a new instance.
    # It returns a pubkey and report from that instance
    ans = install('enclave_a/enclave_a.signed')
    
    # Create a local enclave_b instance that can verify that we are talking to
    # a true enclave_a instance with that pubkey.
    with open('enclave_b/enclave_b.signed','rb') as f: e_binary = f.read()
    e = create_enclave(e_binary)
    res = verify_report_and_set_pubkey(e, ans['key'], ans['report'])
    assert res == 0, f'could not attest that the remote machine runs in a secure environment'

    # send over some data to the remote instance that only it can decrypt
    data = f'These are my secrets encrypted to to instance {ans["id"]}'.encode()
    pk = ans['key']; pk = pk[:pk.find(b'\0')]; pk = RSA.importKey(pk)
    c = PKCS1_OAEP.new(pk).encrypt(data)

    # we can get data back in a sealed format that it can only be
    # unpacked by instances of type enclave_a
    s = ask({'id':ans['id'], 'seal':c})['sealed']
    
    print(ask({'unseal':s, 'id':ans['id']})['data'])