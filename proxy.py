import json
from mitmproxy import ctx
from mitmproxy import http
import zlib
import gnupg

MY_GPG_USERNAME="" #need this so we can encrypt outgoing messages to ourselves as well so we can decrypt later

decompressor = zlib.decompressobj()
compressor=zlib.compressobj(wbits=-15)

gpg=gnupg.GPG(gnupghome="<path here>/.gnupg/")
recipients=dict([x.rstrip("\n").split(",") for x in open("recipients.csv").readlines()])


def zlib_decomp(data: bytes):
    try:
        decompressed = decompressor.decompress(data)
        if decompressed:
            return decompressed.decode(errors="replace")
    except Exception as e:
        print(f"Decompression failed: {e}")

def zlib_comp(data):
    try:
        compressed = compressor.compress(data)+compressor.flush(zlib.Z_SYNC_FLUSH)
        if compressed:
            return compressed
    except Exception as e:
        print(f"Compression failed: {e}")

def gpg_encrypt(message,channel_id,myself):
    if(str(channel_id) in recipients):
        return gpg.encrypt(message,[MY_GPG_USERNAME,recipients[str(channel_id)]]).data.decode("utf-8")
    return ""

def try_decrypt_message(message):
    if("-----BEGIN PGP MESSAGE-----" in message[:28]):
        decrypted=gpg.decrypt(message)
        if(decrypted.ok):
            return decrypted.data.decode("utf-8")
    return None

class Injector:

    def response(self, flow: http.HTTPFlow) -> None:
        address=flow.server_conn.address[0]
        if address.split(".")[-2]=="discord":
            if(flow.websocket!=None):
                print("found websocket")

    def request(self,flow: http.HTTPFlow):
        address=flow.server_conn.address[0]
        path=flow.request.path
        if address.split(".")[-2]=="discord":
            if(flow.request.method=="POST"):
                if(path.split("/")[-1]=="messages"):
                    data=json.loads(flow.request.content)
                    channel_id=path.split("/")[-2]
                    print(path)
                    print(data["content"])
                    if(channel_id in recipients):
                        data["content"]=gpg_encrypt(data["content"],channel_id,True)
                    flow.request.content=bytes(json.dumps(data),"utf-8")



    def websocket_message(self,flow: http.HTTPFlow):
        message=flow.websocket.messages[-1]
        address=flow.server_conn.address[0]

        if address.split(".")[-2]!="discord":
            return
        data=None
        if((message.from_client)==0):
            data=zlib_decomp(message.content)
            ws_json=json.loads(data)
            if(ws_json["t"]=="MESSAGE_CREATE"):
                newdata=try_decrypt_message(ws_json["d"]["content"])
                if(newdata != None):
                    ws_json["d"]["content"]=str(newdata)
                    flow.websocket.messages[-1].content=zlib_comp(bytes(json.dumps(ws_json),"utf-8"))

addons = [Injector()]

