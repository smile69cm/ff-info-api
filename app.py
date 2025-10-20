from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request, Response
from google.protobuf.json_format import MessageToDict
import threading
import time
from datetime import datetime

# Import Protobuf Definitions (These files must be in the same directory)
from data_pb2 import AccountPersonalShowInfo
import uid_generator_pb2
import GetWishListItems_pb2 # Included for completeness

app = Flask(__name__)

# --- Global State and Constants ---
jwt_token = None
key = 'FF7B12C12D345E67890ABCDEF1234567' # Default AES Key (32 Hex Chars)
iv = 'A1B2C3D4E5F67890' # Default AES IV (32 Hex Chars)

# --- 1. JWT Token Acquisition ---
def get_jwt_token_sync(region):
    """Fetches a new JWT token if the current one is expired or missing."""
    global jwt_token

    # Use cached token if available
    if jwt_token:
        return jwt_token

    endpoints = {
        "IND": "https://jwt-chi-seven.vercel.app/api/token?uid=4230185186&password=9D349A6F71884312658E1D5CDC3333A7AF382A77F71CED1ADAB39C4CFC285B6B",
        "BR": "https://projects-fox-x-get-jwt.vercel.app/get?uid=3787481313&password=JlOivPeosauV0l9SG6gwK39l",
        # Add other regions as needed
    }
    
    config = endpoints.get(region, endpoints["IND"])
    
    try:
        response = requests.get(config, timeout=10)
        response.raise_for_status() # Raise exception for bad status codes (4xx or 5xx)
        data = response.json()
        
        # Check based on known API structures
        if region == "IND" and data.get('status') in ['success', 'live'] and data.get('token'):
            jwt_token = data['token']
        elif region in ["BR", "US", "SAC", "NA"] and isinstance(data, dict) and 'token' in data:
            jwt_token = data['token']
        elif data.get('token'):
             jwt_token = data['token']
        
        if jwt_token:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] JWT token fetched successfully for region {region}.")
            return jwt_token
        else:
            print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Error: Token not found in response for region {region}: {data}")
            return None
            
    except requests.exceptions.RequestException as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] HTTP Request error during JWT fetch for {region}: {e}")
        return None
    except Exception as e:
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] General error during JWT fetch for {region}: {e}")
        return None

# --- 2. AES Encryption ---
def encrypt_aes(hex_data, key_hex, iv_hex):
    """Encrypts hex data using AES-128-CBC with Zero Padding."""
    try:
        key_bytes = binascii.unhexlify(key_hex)
        iv_bytes = binascii.unhexlify(iv_hex)
        data_bytes = binascii.unhexlify(hex_data)
        
        cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
        # PKCS7 is often used, but ZeroPadding matches the JS/Garena API behavior
        padded_data = pad(data_bytes, AES.block_size, style='x923') 
        encrypted_bytes = cipher.encrypt(padded_data)
        
        return binascii.hexlify(encrypted_bytes).decode().upper()
    except Exception as e:
        print(f"Encryption error: {e}")
        raise ValueError(f"Encryption failed with key/iv issues: {e}")

# --- 3. API Call Function ---
def apis(encrypted_hex, region):
    """Makes the encrypted POST request to the Garena API."""
    global jwt_token
    
    endpoints = {
        "IND": "https://sg-lobby.ff.garena.com/api/v2/account/GetAccountPersonalShowInfo",
        "BR": "https://br-lobby.ff.garena.com/api/v2/account/GetAccountPersonalShowInfo",
    }
    
    url = endpoints.get(region, endpoints["IND"])
    token = get_jwt_token_sync(region)
    
    if not token:
        raise Exception("Failed to acquire JWT token before API call.")

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "text/plain",
        "X-App-Key": "ff-website"
    }

    try:
        response = requests.post(url, data=encrypted_hex, headers=headers, timeout=15)
        response.raise_for_status()
        return response.text
    except requests.exceptions.RequestException as e:
        # Garena API returns the raw hex string of the decrypted protobuf data
        print(f"API Request error: {e}")
        raise Exception(f"External API call failed or timed out: {e}")
    except Exception as e:
        raise Exception(f"API request failed: {e}")

# --- 4. Data Formatting ---
def format_datetime(timestamp):
    """Converts Garena timestamp (sometimes ms, sometimes s) to readable format."""
    try:
        # Check if it's milliseconds and convert to seconds if needed
        if timestamp > 100000000000:
            timestamp /= 1000
        
        dt_object = datetime.fromtimestamp(timestamp)
        return dt_object.strftime('%d %B %Y %H:%M:%S')
    except:
        return "N/A"

def format_data(data):
    """Formats the JSON data into a clean, human-readable text string."""
    try:
        basic_info = data.get('basicInfo', {})
        social_info = data.get('socialBasicInfo', {})
        clan_info = data.get('clanInfoBasic', {})
        pet_info = data.get('petInfo', {})
        
        name = basic_info.get('nickName', 'N/A')
        uid = basic_info.get('accountId', 'N/A')
        level = basic_info.get('level', 'N/A')
        rank_points = basic_info.get('rankingPoints', 0)
        likes = basic_info.get('likeNum', 0)
        exp = basic_info.get('exp', 0)
        region_name = basic_info.get('region', 'N/A')
        
        last_login_ts = basic_info.get('lastLoginTime', 0)
        create_ts = basic_info.get('createTime', 0)
        
        last_login_dt = format_datetime(int(last_login_ts))
        create_dt = format_datetime(int(create_ts))
        
        output = []
        
        output.append("**BASIC INFO ✨**")
        output.append(f"• Name: {name}")
        output.append(f"• UID: {uid}")
        output.append(f"• Level: {level}")
        output.append(f"• Likes: {likes:,}")
        output.append(f"• XP: {exp:,}")
        output.append(f"• Region: {region_name}")
        output.append(f"• RankBR Points: {rank_points:,}")
        output.append(f"• Last Login: {last_login_dt}")
        output.append(f"• Created On: {create_dt}")
        
        signature = social_info.get('signature', 'No Bio Set')
        output.append(f"• Bio: {signature}")
        
        # --- GUILD INFO ---
        guild_name = clan_info.get('clanName', 'None')
        if guild_name != 'None':
            output.append("\n**GUILD 🛡️**")
            output.append(f"• Name: {guild_name}")
            output.append(f"• UID: {clan_info.get('clanId', 'N/A')}")
            output.append(f"• Level: {clan_info.get('level', 'N/A')}")
            output.append(f"• Members: {clan_info.get('memberNum', 'N/A')}")

            leader_info = clan_info.get('leaderBasicInfo', {})
            if leader_info:
                output.append("\n**GUILD LEADER 👑**")
                output.append(f"• Name: {leader_info.get('nickName', 'N/A')}")
                output.append(f"• UID: {leader_info.get('accountId', 'N/A')}")
        
        return "\n".join(output)

    except Exception as e:
        print(f"Formatting Error: {e}")
        return f"Error formatting data: Could not parse all data fields ({str(e)})."

# --- 5. API Endpoints ---

@app.route('/accinfo', methods=['GET'])
def get_player_info_json():
    """Returns raw JSON of the decoded Protobuf data."""
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', 'IND').upper()
        custom_key = request.args.get('key', key)
        custom_iv = request.args.get('iv', iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400

        # 1. Protobuf Encode Request (UID)
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        # 2. Encrypt Data
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        # 3. Call External API
        api_response = apis(encrypted_hex, region) 
        
        if not api_response:
            return jsonify({"error": "Empty response from API"}), 400
            
        # 4. Protobuf Decode Response
        message = AccountPersonalShowInfo()
        message.ParseFromString(bytes.fromhex(api_response)) 
        
        # 5. Convert to JSON
        result = MessageToDict(message, preserving_proto_field_name=True, use_integers_for_enums=True)
        
        result['Owners'] = ['MOHANBOTS']
        
        return jsonify(result)
        
    except ValueError:
        return jsonify({"error": "Invalid UID or Encryption Key/IV format"}), 400
    except Exception as e:
        print(f"Error processing JSON request: {e}")
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500

@app.route('/info', methods=['GET'])
def get_player_info_text():
    """Returns human-readable text output of the player data."""
    try:
        # Call the core logic to get the JSON data internally
        response = get_player_info_json()
        
        if response.status_code != 200:
             # Extract error message from JSON response and return as plain text
            error_data = response.get_json()
            error_msg = error_data.get("error", "An unknown error occurred.")
            return Response(error_msg, status=response.status_code, mimetype='text/plain')

        data = response.get_json()
        formatted_text = format_data(data)
        
        # Return as plain text
        return Response(formatted_text, status=200, mimetype='text/plain; charset=utf-8')
        
    except Exception as e:
        return Response(f"Internal error while formatting data: {str(e)}", status=500, mimetype='text/plain')


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "OK",
        "message": "Welcome to the Free Fire Account Info API (Python/Render Version)!",
        "endpoints": {
            "/accinfo": "Returns raw JSON data. Use /accinfo?uid=<UID>&region=<REGION>",
            "/info": "Returns formatted text. Use /info?uid=<UID>&region=<REGION>"
        },
        "creator": "MOHANBOTS"
    })
