# bot.py
import uuid
import time
import json
import os
import subprocess
from datetime import datetime
from telebot import TeleBot, types

# Токен бота
TOKEN = "8287346818:AAFp_SU0EW-Z9yt-g6QefSggwbX5L2TcUCs"

# Константы из оригинального кода
PORT = "443"
SERVER_IP = "212.132.120.102"
CONFIG_PATH = os.path.join(os.getcwd(), 'config.json')
USERS_DB = os.path.join(os.getcwd(), 'users.json')
XRAY_LOG = 'xray.log'

bot = TeleBot(TOKEN)

def determine_server_ip():
    global SERVER_IP
    if SERVER_IP in (None, "None"):
        SERVER_IP = subprocess.getoutput("curl -s ifconfig.me") or "your-server-ip"
    return SERVER_IP

def load_users():
    try:
        with open(USERS_DB, 'r') as f:
            data = f.read().strip()
            return json.loads(data) if data else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []

def save_users(users):
    with open(USERS_DB, 'w') as f:
        json.dump(users, f, indent=2)

def generate_vless_key(user_id, chat_id, duration_seconds=3153600000, key_name="KingVless"):
    determine_server_ip()
    new_uuid = str(uuid.uuid4())
    vless_uri = f"vless://{new_uuid}@{SERVER_IP}:{PORT}?type=ws&security=none#{key_name}"
    
    users = load_users()
    user = next((u for u in users if u["user_id"] == user_id), None)
    if not user:
        user = {
            "user_id": user_id,
            "chat_id": chat_id,
            "created_at": datetime.utcnow().isoformat(),
            "key": None
        }
        users.append(user)
    
    user["key"] = {
        "id": new_uuid,
        "expiration": int(time.time()) + duration_seconds,
        "key_name": key_name
    }
    save_users(users)
    
    return vless_uri

def download_and_extract_xray():
    xray_url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    tmp_zip = "/tmp/xray.zip"
    try:
        import requests
        import zipfile
        response = requests.get(xray_url, timeout=30)
        response.raise_for_status()
        with open(tmp_zip, 'wb') as f:
            f.write(response.content)
        with zipfile.ZipFile(tmp_zip, 'r') as zip_ref:
            zip_ref.extractall('/tmp/')
        os.chmod('/tmp/xray', 0o755)
        user_bin = os.path.expanduser("~/bin")
        os.makedirs(user_bin, exist_ok=True)
        subprocess.run(f"cp /tmp/xray {user_bin}/xray", shell=True)
        os.environ['PATH'] = user_bin + ":" + os.environ.get('PATH', '')
        return True
    except Exception:
        return False

def update_xray_config_and_restart():
    current_time = int(time.time())
    users = load_users()
    active_clients = [
        {"id": u["key"]["id"]} for u in users 
        if u.get("key") and u["key"]["expiration"] > current_time
    ]
    
    server_config = {
        "log": {"loglevel": "info"},
        "inbounds": [{
            "port": PORT,
            "protocol": "vless",
            "settings": {
                "clients": active_clients,
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {"headers": {"Host": SERVER_IP}}
            }
        }],
        "outbounds": [{"protocol": "freedom"}]
    }
    
    with open(CONFIG_PATH, 'w') as f:
        json.dump(server_config, f, indent=2)
    
    subprocess.run("pkill xray", shell=True)
    time.sleep(1)
    subprocess.run(f"nohup ~/bin/xray run -c {CONFIG_PATH} > {XRAY_LOG} 2>&1 &", shell=True)
    time.sleep(2)

@bot.message_handler(commands=['start'])
def handle_start(message):
    user_id = message.from_user.id
    chat_id = message.chat.id
    
    # Подготовка хостинга (один раз при первом запуске)
    if not os.path.exists(os.path.expanduser("~/bin/xray")):
        if download_and_extract_xray():
            update_xray_config_and_restart()
    
    # Генерация ключа
    key = generate_vless_key(user_id, chat_id)
    
    # Обновление конфига Xray с новым ключом
    update_xray_config_and_restart()
    
    # Отправка только ключа моноширинным шрифтом
    bot.send_message(chat_id, f"<code>{key}</code>", parse_mode="HTML")

bot.infinity_polling()
