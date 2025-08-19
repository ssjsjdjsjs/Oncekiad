import requests
import logging
import json
import random
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
import concurrent.futures
from typing import Dict, Optional, Tuple

# urllib3 uyarılarını devre dışı bırak
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Loglama ayarları
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Flask uygulaması
app = Flask(__name__)

# Sabitler
REQ_AES_KEY = b'Yg&tc%DEuh6%Zc^8'
REQ_AES_IV = b'6oyZDr22E3ychjM%'
STATIC_GUEST_UID = "4105269376"
STATIC_GUEST_PASSWORD = "SENTEZISM"

# Rastgele User-Agent listesi
USER_AGENTS = [
    "Opera/9.80 (Android; Opera Mini/7.5/34.1088; U; tr) Presto/2.8 Sürüm/11.10",
    "Mozilla/5.0 (Android; Mobil; rv:27.0) Gecko/27.0 Firefox/27.0",
    "Opera/9.80 (Android; Opera Mini/7.5/35.3956; U; tr) Presto/2.8 Sürüm/11.10",
    "Opera/9.80 (Android; Opera Mini/7.5/34.1697; U; tr) Presto/2.8 Sürüm/11.10",
    "Opera/9.80 (Android; Opera Mini/7.5/34.1244; U; tr) Presto/2.8 Sürüm/11.10",
    "Opera/9.80 (Android; Opera Mini/7.5/34.2003; U; tr) Presto/2.8 Sürüm/11.10",
    "Mozilla/5.0 (Linux; Android 6.0.1; SM-N9100 Build/LRX22C) AppleWebKit/600.1.4 (KHTML, Gecko gibi) Mobile/12B466 Tx(Tx/5.4.3) WindVane/8.0.0 750x1334",
    "Mozilla/5.0 (Linux; Android 5.0.2; SM-A5000 Build/LRX22C) AppleWebKit/602.4.6 (KHTML, Gecko gibi) Mobile/14D27 Tx(Tx/6.1.0) WindVane/8.1.0 750x1334",
]

def get_random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def get_garena_token(uid: str, password: str) -> Tuple[Optional[str], Optional[str]]:
    url = "https://100067.connect.garena.com/oauth/guest/token/grant"
    headers = {"User-Agent": get_random_user_agent()}
    data = {
        "uid": uid,
        "password": password,
        "response_type": "token",
        "client_type": "2",
        "client_id": "100067",
        "client_secret": "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3"
    }
    try:
        response = requests.post(url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        json_data = response.json()
        return json_data.get('open_id'), json_data.get('access_token')
    except requests.RequestException as e:
        logging.error(f"Garena token alınırken hata: {e}")
        return None, None

def dict_to_protobuf_bytes(data: Dict) -> bytes:
    def encode_varint(n: int) -> bytes:
        buf = bytearray()
        while True:
            towrite = n & 0x7F
            n >>= 7
            if n:
                buf.append(towrite | 0x80)
            else:
                buf.append(towrite)
                break
        return bytes(buf)

    p = bytearray()
    for k, v in sorted(data.items()):
        f = int(k)
        if isinstance(v, int):
            p += encode_varint((f << 3)) + encode_varint(v)
        elif isinstance(v, (str, bytes)):
            val = v.encode() if isinstance(v, str) else v
            p += encode_varint((f << 3) | 2) + encode_varint(len(val)) + val
    return bytes(p)

def encrypt_message(b: bytes) -> bytes:
    return AES.new(REQ_AES_KEY, AES.MODE_CBC, REQ_AES_IV).encrypt(pad(b, AES.block_size))

def decrypt_message(b: bytes) -> Optional[bytes]:
    try:
        if len(b) % 16 != 0:
            logging.warning("Yanıt 16 byte sınırına uygun değil, şifresiz olabilir.")
            return b
        return unpad(AES.new(REQ_AES_KEY, AES.MODE_CBC, REQ_AES_IV).decrypt(b), AES.block_size)
    except Exception as e:
        logging.error(f"Şifre çözme hatası: {e}")
        return b

def decode_varint(data: bytes, index: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if index >= len(data):  # Güvenlik kontrolü
            return 0, index
        byte = data[index]
        index += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, index
        shift += 7

def parse_protobuf_bytes(data_bytes: bytes) -> Dict:
    index = 0
    result_dict = {}

    while index < len(data_bytes):
        try:
            tag, new_index = decode_varint(data_bytes, index)
            if new_index == index:  # No progress, break to avoid infinite loop
                break
            index = new_index

            field_number = tag >> 3
            wire_type = tag & 0x07

            if field_number == 0:  # Skip invalid field numbers
                continue

            if wire_type == 0:  # Varint
                value, index = decode_varint(data_bytes, index)
                result_dict[field_number] = value

            elif wire_type == 2:  # Length-delimited (string, bytes, or nested message)
                length, index = decode_varint(data_bytes, index)
                if index + length > len(data_bytes):
                    break
                payload = data_bytes[index:index + length]
                index += length
                try:
                    result_dict[field_number] = payload.decode('utf-8')
                except UnicodeDecodeError:
                    result_dict[field_number] = parse_protobuf_bytes(payload)  # Recursive parsing for nested messages

            elif wire_type == 1:  # 64-bit
                if index + 8 > len(data_bytes):
                    break
                index += 8

            elif wire_type == 5:  # 32-bit
                if index + 4 > len(data_bytes):
                    break
                index += 4

            else:
                continue
        except IndexError:
            break

    return result_dict

def universal_packet_decoder(full_packet_hex: str) -> Optional[Dict]:
    if not isinstance(full_packet_hex, str) or len(full_packet_hex) == 0:
        return None

    try:
        packet_bytes = bytes.fromhex(full_packet_hex)
    except ValueError:
        return None

    best_result = None
    max_score = -1

    # Try offsets up to 16 bytes to skip potential headers
    for offset in range(min(16, len(packet_bytes))):
        try:
            decoded_data = parse_protobuf_bytes(packet_bytes[offset:])

            if decoded_data:
                # Score based on JSON serialization length
                score = len(json.dumps(decoded_data))

                if score > max_score:
                    max_score = score
                    best_result = decoded_data
        except Exception as e:
            logging.debug(f"Offset {offset} decoding failed: {e}")
            continue

    return best_result

def get_dynamic_jwt() -> Optional[str]:
    open_id, token = get_garena_token(STATIC_GUEST_UID, STATIC_GUEST_PASSWORD)
    if not open_id or not token:
        logging.error("JWT token alınamadı.")
        return None

    data = {
        "7": "1.114.6",
        "21": "tr",
        "23": "4",
        "57": "1ac4b80ecf0478a44203bf8fac6120f5",
        "99": "4",
        "100": "4",
        "22": open_id,
        "29": token
    }
    encrypted = encrypt_message(dict_to_protobuf_bytes(data))

    headers = {
        'User-Agent': get_random_user_agent(),
        'X-Ga': 'v1 1',
        'Releaseversion': 'OB50',
        'Content-Type': 'application/octet-stream',
        'X-Unity-Version': '2022.3.47f1',
    }

    try:
        response = requests.post(
            "https://loginbp.common.ggbluefox.com/MajorLogin",
            data=encrypted,
            headers=headers,
            verify=False,
            timeout=15
        )
        response.raise_for_status()
        decrypted = decrypt_message(response.content)
        parsed = parse_protobuf_bytes(decrypted)
        return parsed.get(8)
    except requests.RequestException as e:
        logging.error(f"JWT istek hatası: {e}")
        return None

def try_get_jwt() -> Optional[str]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(get_dynamic_jwt) for _ in range(5)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                # Cancel other futures
                for f in futures:
                    if not f.done():
                        f.cancel()
                return result
    return None

def aes_cbc_encrypt(plaintext: bytes) -> bytes:
    cipher = AES.new(REQ_AES_KEY, AES.MODE_CBC, REQ_AES_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size, style='pkcs7'))

def encode_varint(value: int) -> bytes:
    buf = b""
    while True:
        towrite = value & 0x7F
        value >>= 7
        if value:
            buf += bytes((towrite | 0x80,))
        else:
            buf += bytes((towrite,))
            break
    return buf

def create_request_payload(target_uid: int) -> bytes:
    tag1, val1 = b'\x08', encode_varint(target_uid)
    tag2, val2 = b'\x10', encode_varint(7)
    return tag1 + val1 + tag2 + val2

def extract_player_info(profile_data: Dict) -> Dict:
    try:
        player_name = profile_data.get(3, 'Bilinmeyen Oyuncu') if isinstance(profile_data, dict) else 'Bilinmeyen Oyuncu'

        return {
            'player_name': player_name,
        }
    except Exception as e:
        logging.error(f"Oyuncu bilgisi çıkarılırken hata: {e}")
        return {'player_name': 'Bilinmeyen Oyuncu'}
        
@app.route('/oncekiad', methods=['GET'])
def get_player_info():
    """Oyuncu bilgilerini çeken API endpoint'i."""
    try:
        target_uid_str = request.args.get('uid')
        if not target_uid_str:
            return jsonify({'error': 'UID parametresi eksik.'}), 400
        if not target_uid_str.isdigit():
            return jsonify({'error': 'Geçerli bir sayısal UID girin.'}), 400
        target_uid = int(target_uid_str)

        jwt_token = try_get_jwt()
        if not jwt_token:
            logging.error("JWT token alınamadı.")
            return jsonify({'error': 'JWT token alınamadı.'}), 500

        headers = {
            'User-Agent': get_random_user_agent(),
            'Connection': 'Keep-Alive',
            'Accept-Encoding': 'gzip',
            'Authorization': f'Bearer {jwt_token}',
            'Content-Type': 'application/octet-stream',
            'Expect': '100-continue',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB50'
        }
        api_url = "https://clientbp.ggblueshark.com/GetAccountInfoByAccountID"

        plaintext_payload = create_request_payload(target_uid)
        encrypted_body = aes_cbc_encrypt(plaintext_payload)

        logging.info(f"İstek gönderiliyor: UID={target_uid}")

        response = requests.post(
            api_url,
            headers=headers,
            data=encrypted_body,
            timeout=15,
            verify=False
        )

        logging.info(f"Sunucu yanıt kodu: {response.status_code}")

        if response.status_code == 200 and response.content:
            decrypted_data = decrypt_message(response.content)
            full_profile_data = parse_protobuf_bytes(decrypted_data)
            player_info = extract_player_info(full_profile_data)
            return jsonify({
                'status': 'success',
                'data': player_info
            }), 200
        elif not response.content:
            logging.info("Sunucudan boş yanıt alındı.")
            return jsonify({'error': 'Sunucudan boş yanıt alındı.'}), 500
        else:
            logging.error(f"Sunucudan hata alındı: {response.text}")
            return jsonify({'error': f"Sunucudan hata: {response.status_code}"}), response.status_code

    except Exception as e:
        logging.error(f"API hatası: {e}", exc_info=True)
        return jsonify({'error': str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000, debug=True)
