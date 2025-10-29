from flask import Flask, request, Response
import asyncio, json, binascii, requests, aiohttp, urllib3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
from google.protobuf.message import DecodeError
import like_pb2, like_count_pb2, uid_generator_pb2
from config import URLS_INFO, URLS_LIKE, FILES
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False  # Permite caracteres especiais (como nomes com emojis ou símbolos)

def carregar_tokens(servidor):
    arquivos = FILES
    caminho = f"tokens/{arquivos.get(servidor, 'token_br.json')}"
    return json.load(open(caminho, encoding="utf-8"))

def gerar_cabecalhos(token):
    return {
        "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
        "Connection": "Keep-Alive",
        "Accept-Encoding": "gzip",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/x-www-form-urlencoded",
        "Expect": "100-continue",
        "X-Unity-Version": "2018.4.11f1",
        "X-GA": "v1 1",
        "ReleaseVersion": "OB50",
    }

def criptografar_mensagem(dados):
    cifra = AES.new(b'Yg&tc%DEuh6%Zc^8', AES.MODE_CBC, b'6oyZDr22E3ychjM%')
    return binascii.hexlify(cifra.encrypt(pad(dados, AES.block_size))).decode()

def criar_like(uid, regiao):
    msg = like_pb2.like()
    msg.uid, msg.region = int(uid), regiao
    return msg.SerializeToString()

def criar_uid(uid):
    msg = uid_generator_pb2.uid_generator()
    msg.saturn_, msg.garena = int(uid), 1
    return msg.SerializeToString()

async def enviar(token, url, dados):
    cabecalhos = gerar_cabecalhos(token)
    async with aiohttp.ClientSession() as s:
        try:
            async with s.post(url, data=bytes.fromhex(dados), headers=cabecalhos) as r:
                return await r.text() if r.status == 200 else None
        except:
            return None

async def enviar_multiplos(uid, servidor, url):
    enc = criptografar_mensagem(criar_like(uid, servidor))
    tokens = carregar_tokens(servidor)
    tarefas = [enviar(tokens[i % len(tokens)]['token'], url, enc) for i in range(105)]
    await asyncio.gather(*tarefas, return_exceptions=True)

def obter_info(enc, servidor, token):
    urls = URLS_INFO
    r = requests.post(
        urls.get(servidor, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow"),
        data=bytes.fromhex(enc),
        headers=gerar_cabecalhos(token),
        verify=False,
    )
    try:
        p = like_count_pb2.Info()
        p.ParseFromString(r.content)
        return p
    except DecodeError:
        return None

@app.route("/like")
def curtidas():
    uid = request.args.get("uid")
    servidor = request.args.get("server", "").upper()

    if not uid or not servidor:
        return Response(
            json.dumps({"erro": "É necessário informar UID e servidor."}, ensure_ascii=False),
            mimetype="application/json",
            status=400
        )

    tokens = carregar_tokens(servidor)
    enc = criptografar_mensagem(criar_uid(uid))

    antes, token_valido = None, None
    for t in tokens[:10]:
        antes = obter_info(enc, servidor, t["token"])
        if antes:
            token_valido = t["token"]
            break

    if not antes:
        return Response(
            json.dumps({"erro": "Jogador não encontrado."}, ensure_ascii=False),
            mimetype="application/json",
            status=500
        )

    antes_json = json.loads(MessageToJson(antes))
    curtidas_antes = int(antes_json.get('AccountInfo', {}).get('Likes', 0))

    urls = URLS_LIKE
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(enviar_multiplos(uid, servidor, urls.get(servidor, "https://clientbp.ggblueshark.com/LikeProfile")))
    loop.close()

    depois_json = json.loads(MessageToJson(obter_info(enc, servidor, token_valido)))
    curtidas_depois = int(depois_json.get('AccountInfo', {}).get('Likes', 0))

    resposta = {
        "créditos": "come_primas",
        "likes_enviadas": curtidas_depois - curtidas_antes,
        "likes_antes": curtidas_antes,
        "likes_depois": curtidas_depois,
        "jogador": depois_json.get('AccountInfo', {}).get('PlayerNickname', ''),
        "uid": depois_json.get('AccountInfo', {}).get('UID', 0),
        "status": 1 if curtidas_depois - curtidas_antes > 0 else 2
    }

    return Response(json.dumps(resposta, ensure_ascii=False, indent=2), mimetype='application/json')

@app.route("/")
def home():
    return "Serviço rodando no Render! 🚀"

port = int(os.environ.get("PORT", 10000))
app.run(host="0.0.0.0", port=port)
