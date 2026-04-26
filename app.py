import logging
import sys
import binascii
from datetime import datetime
from flask import Flask, request, jsonify
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import jwt
from urllib.parse import urlparse, parse_qs

# Protobuf imports
import FreeFire_pb2
import data_pb2
import encode_id_clan_pb2
import reqClan_pb2

# ====================
# Logging Setup
# ====================
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# ====================
# Config
# ====================
AES_KEY = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
AES_IV = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])

api_endpoints = {
    "IND": "https://client.ind.freefiremobile.com",
    "AMERICAS": "https://client.us.freefiremobile.com", 
    "DEFAULT": "https://clientbp.ggpolarbear.com"
}

# ====================
# Helper Functions
# ====================
def encrypt_message(plaintext):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    padded = pad(plaintext, AES.block_size)
    return cipher.encrypt(padded)

def get_oauth_token(uid, password):
    """Step 1: Get access_token and open_id using guest login"""
    logger.info(f"OAuth request for uid={uid}")
    url = "https://100067.connect.garena.com/api/v2/oauth/guest/token:grant"
    payload = {
        'uid': uid,
        'password': password,
        'response_type': "token",
        'client_type': "2",
        'client_secret': "2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3",
        'client_id': "100067"
    }
    headers = {
        'User-Agent': "GarenaMSDK/4.0.19P9(SM-M526B ;Android 13;pt;BR;)",
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip"
    }
    try:
        resp = requests.post(url, data=payload, headers=headers, timeout=10)
        logger.debug(f"OAuth status: {resp.status_code}")
        if resp.status_code == 200:
            data = resp.json()
            if 'access_token' in data and 'open_id' in data:
                logger.info("OAuth success")
                return data, None
        logger.error(f"OAuth failed: {resp.text[:200]}")
        return None, f"OAuth HTTP {resp.status_code}"
    except Exception as e:
        logger.exception("OAuth exception")
        return None, str(e)

# ====================
# EAT -> Access Token
# ====================
def get_access_token_from_eat(eat_token):
    """EAT token ko use karke access_token aur open_id nikalna"""
    logger.info(f"Converting EAT token to access_token")
    try:
        url = f"https://api-otrss.garena.com/support/callback/?access_token={eat_token}"
        # Important: allow_redirects=True, verify=False for self-signed?
        response = requests.get(url, allow_redirects=True, timeout=30, verify=False)
        
        # Redirect final URL mein access_token milega
        if 'help.garena.com' in response.url:
            parsed = urlparse(response.url)
            params = parse_qs(parsed.query)
            if 'access_token' in params:
                access_token = params['access_token'][0]
                # Ab is access_token ko inspect karke open_id aur platform nikalte hain
                return inspect_access_token(access_token)
        return {'success': False, 'error': 'Invalid EAT token - no redirect'}
    except Exception as e:
        logger.exception("EAT conversion exception")
        return {'success': False, 'error': str(e)}

# ====================
# Access Token Inspect
# ====================
def inspect_access_token(access_token):
    """Access token ko inspect karke open_id, platform return karega"""
    try:
        url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
        resp = requests.get(url, timeout=15, verify=False)
        if resp.status_code == 200:
            data = resp.json()
            if 'open_id' in data:
                return {
                    'success': True,
                    'access_token': access_token,
                    'open_id': data['open_id'],
                    'platform_type': data.get('platform', 4)   # default 4
                }
        return {'success': False, 'error': 'Inspect failed'}
    except Exception as e:
        return {'success': False, 'error': str(e)}

# ====================
# Major Login using FreeFire_pb2
# ====================
def major_login_with_freefire_pb(access_token, open_id, platform_type=4):
    logger.info(f"MajorLogin with open_id={open_id}, platform={platform_type}")
    try:
        login_req = FreeFire_pb2.LoginReq()
        login_req.open_id = open_id
        login_req.open_id_type = str(platform_type)   # 🔥 YEH FIX
        login_req.login_token = access_token
        login_req.client_version = "1.123.1"
        login_req.origin_platform_type = str(platform_type)
        login_req.release_channel = "Official"

        serialized = login_req.SerializeToString()
        encrypted = encrypt_message(serialized)
        hex_encrypted = binascii.hexlify(encrypted).decode()

        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)",
            "Content-Type": "application/octet-stream",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53"
        }
        resp = requests.post(url, data=bytes.fromhex(hex_encrypted), headers=headers, timeout=10)
        
        # 🔥 Agar status code 200 nahi hai, to raw text return karo
        if resp.status_code != 200:
            logger.error(f"MajorLogin HTTP {resp.status_code}: {resp.text[:500]}")
            return None, f"HTTP {resp.status_code}: {resp.text[:200]}"
        
        # Parse only on success
        login_res = FreeFire_pb2.LoginRes()
        login_res.ParseFromString(resp.content)
        if login_res.token:
            logger.info("MajorLogin success, JWT obtained")
            return {'token': login_res.token, 'account_id': login_res.account_id}, None
        else:
            # Token missing – maybe server returned error proto
            return None, f"No token in response: {resp.text[:200]}"
            
    except Exception as e:
        logger.exception("MajorLogin exception")
        return None, str(e)

# ====================
# Main JWT Token Resolution
# ====================
def get_jwt_token_from_params(params):
    """Handle all auth methods and return JWT token"""
    token = params.get('token')
    eat_token = params.get('eat_token')
    access_token_raw = params.get('access_token')
    uid = params.get('uid')
    password = params.get('password')

    # 1) Direct JWT
    if token:
        return token, None

    # 2) EAT token -> inspect -> access_token + open_id -> major_login
    if eat_token:
        logger.info("Processing EAT token")
        eat_result = get_access_token_from_eat(eat_token)
        if eat_result.get('success'):
            access_token = eat_result['access_token']
            open_id = eat_result['open_id']
            platform = eat_result.get('platform_type', 4)
            jwt_result, err = major_login_with_freefire_pb(access_token, open_id, platform)
            if jwt_result:
                return jwt_result['token'], None
            return None, f"MajorLogin failed after EAT: {err}"
        return None, f"EAT conversion failed: {eat_result.get('error')}"

    # 3) Access token directly (with inspect)
    if access_token_raw:
        logger.info("Processing access_token")
        inspect_res = inspect_access_token(access_token_raw)
        if inspect_res.get('success'):
            access_token = inspect_res['access_token']
            open_id = inspect_res['open_id']
            platform = inspect_res.get('platform_type', 4)
            jwt_result, err = major_login_with_freefire_pb(access_token, open_id, platform)
            if jwt_result:
                return jwt_result['token'], None
            return None, f"MajorLogin failed after access_token: {err}"
        return None, f"Access token inspect failed: {inspect_res.get('error')}"

    # 4) UID + Password -> OAuth -> access_token + open_id (platform=4)
    if uid and password:
        logger.info("Processing uid/password")
        oauth_data, err = get_oauth_token(uid, password)   # pehle se hai
        if err:
            return None, f"OAuth failed: {err}"
        access_token = oauth_data['access_token']
        open_id = oauth_data['open_id']
        jwt_result, err = major_login_with_freefire_pb(access_token, open_id, 4)
        if jwt_result:
            return jwt_result['token'], None
        return None, f"MajorLogin failed after OAuth: {err}"

    return None, "No valid authentication method provided"

def get_jwt_from_credentials(uid, password):
    """Complete flow: OAuth -> MajorLogin -> JWT"""
    oauth_data, err = get_oauth_token(uid, password)
    if err:
        return None, err
    
    access_token = oauth_data['access_token']
    open_id = oauth_data['open_id']
    
    login_result, err = major_login_with_freefire_pb(access_token, open_id, 4)
    if err:
        return None, err
    
    return login_result['token'], None


def get_region_from_jwt(jwt_token):
    try:
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        region = decoded.get('lock_region', 'IND')
        return region.upper() if region else 'IND'
    except:
        return 'IND'

def get_region_type(region):
    region = region.upper()
    if region == "IND":
        return "IND"
    elif region in ["BR", "US", "NA", "SAC"]:
        return "AMERICAS"
    else:
        return "DEFAULT"

def create_clan_payload(clan_id):
    """Create encrypted payload for clan requests (Join/Quit)"""
    try:
        msg = reqClan_pb2.MyMessage()
        msg.field_1 = int(clan_id)
        serialized = msg.SerializeToString()
        encrypted = encrypt_message(serialized)
        return encrypted, None
    except Exception as e:
        logger.exception("Payload creation failed")
        return None, str(e)

def make_clan_request(jwt_token, clan_id, endpoint):
    try:
        region = get_region_from_jwt(jwt_token)
        region_type = get_region_type(region)
        base_url = api_endpoints.get(region_type, api_endpoints["DEFAULT"])
        
        encrypted_data, err = create_clan_payload(clan_id)
        if err:
            return None, err, None
        
        url = f"{base_url}/{endpoint}"
        headers = {
            "Expect": "100-continue",
            "Authorization": f"Bearer {jwt_token}",
            "X-Unity-Version": "2018.4.11f1",
            "X-GA": "v1 1",
            "ReleaseVersion": "OB53",
            "Content-Type": "application/octet-stream",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 11; SM-A305F Build/RP1A.200720.012)",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip"
        }
        
        logger.info(f"Sending {endpoint} request for clan_id={clan_id}")
        response = requests.post(url, headers=headers, data=encrypted_data, timeout=30)
        
        # 🔥 Agar status code 200 nahi hai, to raw text return karo
        if response.status_code != 200:
            error_text = response.text[:500]
            logger.error(f"Clan request failed: {response.status_code} - {error_text}")
            return response, f"HTTP {response.status_code}: {error_text}", None
        
        # Try to parse protobuf only on success
        try:
            resp_info = data_pb2.response()
            resp_info.ParseFromString(response.content)
            result = {}
            for field in ['id', 'special_code', 'status_code', 'error_code']:
                if hasattr(resp_info, field):
                    val = getattr(resp_info, field)
                    if val and val != 0:
                        result[field] = val
            return response, None, result
        except Exception as parse_err:
            # Protobuf parse fail – show raw hex/text
            logger.warning(f"Protobuf parse failed: {parse_err}")
            return response, None, {"raw_text": response.text[:500], "raw_hex": response.content.hex()[:200]}
            
    except Exception as e:
        logger.exception("Clan request exception")
        return None, str(e), None

def get_guild_name(jwt_token, guild_id):
    """Get guild name using GetClanInfoByClanID"""
    try:
        region = get_region_from_jwt(jwt_token)
        region_type = get_region_type(region)
        base_url = api_endpoints.get(region_type, api_endpoints["DEFAULT"])
        
        my_data = encode_id_clan_pb2.MyData()
        my_data.field1 = int(guild_id)
        my_data.field2 = 1
        data_bytes = my_data.SerializeToString()
        
        # Custom encryption for this endpoint
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        encrypted = cipher.encrypt(pad(data_bytes, AES.block_size))
        encrypted_hex = encrypted.hex()
        
        url = base_url + "/GetClanInfoByClanID"
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Authorization': f'Bearer {jwt_token}',
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB53',
        }
        
        response = requests.post(url, headers=headers, data=bytes.fromhex(encrypted_hex), timeout=8)
        if response.status_code == 200:
            msg = data_pb2.response()
            msg.ParseFromString(response.content)
            return getattr(msg, "special_code", "Unknown")
        return "Unknown"
    except Exception as e:
        logger.warning(f"Could not fetch guild name: {e}")
        return "Unknown"

# ====================
# Flask Routes
# ====================
@app.route("/join", methods=["GET"])
def join_guild():
    return handle_clan_request("RequestJoinClan")

@app.route("/leave", methods=["GET"])
def leave_guild():
    return handle_clan_request("QuitClan")

def handle_clan_request(endpoint):
    try:
        guild_id = request.args.get("guild_id")
        if not guild_id:
            return jsonify({"success": False, "error": "guild_id required"}), 400
        
        try:
            guild_id = int(guild_id)
        except:
            return jsonify({"success": False, "error": "guild_id must be integer"}), 400
        
        params = {
            'token': request.args.get("token"),
            'eat_token': request.args.get("eat_token"),
            'access_token': request.args.get("access_token"),
            'uid': request.args.get("uid"),
            'password': request.args.get("password")
        }
        
        jwt_token, error = get_jwt_token_from_params(params)
        if error:
            return jsonify({"success": False, "error": f"Auth failed: {error}"}), 400
        
        region = get_region_from_jwt(jwt_token)
        guild_name = get_guild_name(jwt_token, guild_id)
        
        response, error, raw = make_clan_request(jwt_token, guild_id, endpoint)
        
        if error:
            return jsonify({
                "success": False,
                "error": error,
                "guild_id": guild_id,
                "guild_name": guild_name,
                "region": region,
                "raw": raw
            }), 400
        
        return jsonify({
            "success": True,
            "message": f"Success for {endpoint}",
            "guild_id": guild_id,
            "guild_name": guild_name,
            "region": region,
            "raw_response": raw
        })
        
    except Exception as e:
        logger.exception("Request handler exception")
        return jsonify({"success": False, "error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=False, host='0.0.0.0', port=5001)