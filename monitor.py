# monitor.py (for paid hosts, with limit 2)
# Updated to sync users back to API after local changes

import uuid
import os
import json
import subprocess
import requests
import logging
import time
import zipfile
import threading
import sys
from datetime import datetime
from hashlib import md5  # Для хэша users.json

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

CONFIG_PATH = os.path.join(os.getcwd(), 'config.json')
USERS_DB = os.path.join(os.getcwd(), 'users.json')
REFERRAL_STATS = os.path.join(os.getcwd(), 'referral_stats.json')
XRAY_LOG = 'xray.log'

BASE_URL = "https://qpalz012.pythonanywhere.com/api"

HOST_ID = "1"  # "1" for first, "2" for second, etc.
AUTH_USER2 = (f"user2_{HOST_ID}", f"password2_{HOST_ID}")
PORT = 2083  # Set your port
# Не указываем IP жёстко — определим автоматически при старте
SERVER_IP = None  # будет заполнен determine_server_ip()
MAX_USERS = 1

is_active = False

# Добавлено: глобальный флаг остановки для безопасного завершения циклов
stop_event = threading.Event()

def register_self():
    # Глобальная переменная используется и должна быть объявлена до её первого обращения
    global SERVER_IP
    # Попытка определить реальный публичный IP перед формированием payload
    try:
        detected_ip = determine_server_ip()
        if detected_ip:
            SERVER_IP = detected_ip
    except Exception:
        pass

    payload = {
        'id': HOST_ID,
        'ip': SERVER_IP,
        'port': PORT,
        'auth_user': AUTH_USER2[0],
        'auth_pass': AUTH_USER2[1],
        'max_users': MAX_USERS
    }
    r = requests.post(BASE_URL + "/register_host", json=payload)
    r.raise_for_status()
    logger.info(f"Хостинг {HOST_ID} зарегистрирован")
    
    r_hosts = requests.get(BASE_URL + "/hosts", auth=AUTH_USER2)
    r_hosts.raise_for_status()
    hosts = r_hosts.json()
    this_host = next((h for h in hosts if h["id"] == HOST_ID), None)
    if this_host and this_host["active"]:
        global is_active
        is_active = True
        set_my_server_info()
        logger.info(f"Хостинг {HOST_ID} is active by default")

def set_my_server_info():
    # Используем текущий SERVER_IP (установлен в register_self или по умолчанию)
    payload = {"server_ip": SERVER_IP, "port": PORT}
    r = requests.post(BASE_URL + "/set_server_info", json=payload, auth=AUTH_USER2)
    r.raise_for_status()
    logger.info(f"Информация о сервере {HOST_ID} установлена")

def get_server_info():
    r_port = requests.get(BASE_URL + "/port", auth=AUTH_USER2)
    r_port.raise_for_status()
    r_ip = requests.get(BASE_URL + "/server_ip", auth=AUTH_USER2)
    r_ip.raise_for_status()
    logger.info(f"Получены с API: PORT={r_port.json()['port']}, SERVER_IP={r_ip.json()['server_ip']}")

def backup_monitor():
    global is_active
    while not stop_event.is_set():
        try:
            r_hosts = requests.get(BASE_URL + "/hosts", auth=AUTH_USER2)
            r_hosts.raise_for_status()
            hosts = r_hosts.json()
            this_host = next((h for h in hosts if h["id"] == HOST_ID), None)
            if this_host:
                if this_host["active"] != is_active:
                    is_active = this_host["active"]
                    if is_active:
                        set_my_server_info()
                    logger.info(f"Синхронизировано is_active для {HOST_ID}: {is_active}")
            
            r = requests.get(f"{BASE_URL}/get_backup_status", auth=AUTH_USER2, timeout=10)
            r.raise_for_status()
            if r.json()["backup_needed"]:
                set_my_server_info()
                r_reset = requests.post(f"{BASE_URL}/reset_backup_status", auth=AUTH_USER2, timeout=10)
                r_reset.raise_for_status()
                is_active = True
                logger.info(f"Хостинг {HOST_ID} активирован")
        except Exception as e:
            logger.error(f"Ошибка в backup_monitor: {e}")
        # безопасный сон с возможностью прервать
        if stop_event.wait(5):
            break

def determine_server_ip():
    ip = subprocess.getoutput("curl -s ifconfig.me")
    if ip and "." in ip:
        return ip
    return SERVER_IP

def load_users():
    try:
        if not os.path.exists(USERS_DB):
            save_users([])
            return []
        with open(USERS_DB, 'r') as f:
            data = f.read().strip()
            if not data:
                return []
            users = json.loads(data)
            for u in users:
                u.setdefault("referrals", [])
                u.setdefault("referral_message_id", None)
                u.setdefault("referral_code", None)
                u.setdefault("host_id", None)
                if u.get("key"):
                    u["key"].setdefault("key_name", "KingVless")
            return users
    except Exception as e:
        logger.error(f"load_users: {e}")
        return []

def save_users(users):
    try:
        with open(USERS_DB, 'w') as f:
            json.dump(users, f, indent=2)
        logger.info("users.json сохранён")
        sync_users_to_api(users)
    except Exception as e:
        logger.error(f"save_users: {e}")

def sync_users_to_api(users):
    try:
        r = requests.post(BASE_URL + "/users", json=users, auth=AUTH_USER2)
        r.raise_for_status()
        logger.info("Users synced to API")
    except Exception as e:
        logger.error(f"Failed to sync users to API: {e}")

def load_ref_stats():
    try:
        if not os.path.exists(REFERRAL_STATS):
            save_ref_stats({})
            return {}
        with open(REFERRAL_STATS, 'r') as f:
            data = f.read().strip()
            if not data:
                return {}
            return json.loads(data)
    except Exception as e:
        logger.error(f"load_ref_stats: {e}")
        return {}

def save_ref_stats(stats):
    try:
        with open(REFERRAL_STATS, 'w') as f:
            json.dump(stats, f, indent=2)
        logger.info("referral_stats.json сохранён")
    except Exception as e:
        logger.error(f"save_ref_stats: {e}")

def generate_vless_key(user_id, duration_seconds, chat_id, key_name="KingVless"):
    now = int(time.time())
    new_key = {
        "id": str(uuid.uuid4()),
        "user_id": user_id,
        "chat_id": chat_id,
        "expiration": now + duration_seconds if duration_seconds > 0 else now + 3153600000,
        "original_duration": duration_seconds,
        "remaining_duration": duration_seconds if duration_seconds > 0 else 3153600000,
        "frozen": False,
        "freeze_time": None,
        "message_id": None,
        "key_name": key_name
    }

    users = load_users()
    user = next((u for u in users if u["user_id"] == user_id), None)
    if not user:
        user = {
            "user_id": user_id,
            "chat_id": chat_id,
            "created_at": datetime.utcnow().isoformat(),
            "key": None,
            "referrer_id": None,
            "referral_code": None,
            "referrals": [],
            "referral_message_id": None,
            "host_id": None
        }
        users.append(user)
    user["key"] = new_key
    save_users(users)

    # Формируем URI с актуальным публичным IP (SERVER_IP уже обновлён в register_self)
    vless_host = SERVER_IP if SERVER_IP else determine_server_ip()
    vless_uri = f"vless://{new_key['id']}@{vless_host}:{PORT}?type=ws&security=none#{key_name}"
    logger.info(f"КЛЮЧ СГЕНЕРИРОВАН: {vless_uri}")
    return vless_uri

def freeze_key(user_id):
    users = load_users()
    user = next((u for u in users if u["user_id"] == user_id), None)
    if user and user.get("key") and not user["key"].get("frozen", False):
        current_time = int(time.time())
        remaining = user["key"]["expiration"] - current_time
        user["key"]["remaining_duration"] = max(0, remaining)
        user["key"]["frozen"] = True
        user["key"]["freeze_time"] = current_time
        save_users(users)
        logger.info(f"Ключ заморожен для user_id {user_id}")
        return True
    return False

def unfreeze_key(user_id):
    users = load_users()
    user = next((u for u in users if u["user_id"] == user_id), None)
    if user and user.get("key") and user["key"].get("frozen", False):
        freeze_time = user["key"].get("freeze_time", 0)
        frozen_duration = int(time.time()) - freeze_time
        user["key"]["expiration"] += frozen_duration
        user["key"]["frozen"] = False
        user["key"]["freeze_time"] = None
        save_users(users)
        logger.info(f"Ключ разморожен для user_id {user_id}")
        return True
    return False

def update_xray_config():
    now = int(time.time())
    users = load_users()
    active_clients = [
        u["key"] for u in users
        if u.get("key") and u["key"]["expiration"] > now and not u["key"].get("frozen", False)
    ]

    clients = [{"id": c["id"]} for c in active_clients]

    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "listen": "0.0.0.0",
            "port": PORT,
            "protocol": "vless",
            "settings": {
                "clients": clients,
                "decryption": "none"
            },
            "streamSettings": {
                "network": "ws",
                "wsSettings": {
                    "path": "/",
                    "headers": {"Host": SERVER_IP}
                }
            },
            "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
        }],
        "outbounds": [{"protocol": "freedom"}]
    }

    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
        logger.info("config.json обновлён")
    except Exception as e:
        logger.error(f"Ошибка записи config.json: {e}")

    start_xray()

def download_and_extract_xray():
    url = "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
    zip_path = "/tmp/xray.zip"
    bin_path = os.path.expanduser("~/bin/xray")
    if os.path.exists(bin_path):
        return True
    try:
        r = requests.get(url, timeout=30)
        r.raise_for_status()
        with open(zip_path, 'wb') as f:
            f.write(r.content)
        with zipfile.ZipFile(zip_path) as z:
            z.extractall('/tmp')
        os.chmod('/tmp/xray', 0o755)
        os.makedirs(os.path.expanduser("~/bin"), exist_ok=True)
        subprocess.run(f"cp /tmp/xray {bin_path}", shell=True, check=True)
        logger.info("Xray установлен в ~/bin/xray")
        return True
    except Exception as e:
        logger.error(f"Не удалось установить Xray: {e}")
        return False

def start_xray():
    subprocess.run("pkill -f xray", shell=True)
    time.sleep(1)
    cmd = f"nohup ~/bin/xray run -c {CONFIG_PATH} > {XRAY_LOG} 2>&1 &"
    result = subprocess.run(cmd, shell=True)
    if result.returncode == 0:
        time.sleep(2)
        logger.info("Xray запущен")
        return True
    logger.error("Xray НЕ запустился")
    return False

def monitor_pending_requests():
    global is_active
    while not stop_event.is_set():
        if not is_active:
            if stop_event.wait(5):
                break
            continue
        try:
            # Для платных хостов явно запрашиваем тип=paid, аналогично free версии
            r = requests.get(f"{BASE_URL}/pending_requests?type=paid", auth=AUTH_USER2, timeout=10)
            if r.status_code != 200:
                time.sleep(5)
                continue
            pending = r.json()
            for req in pending:
                rid = req["request_id"]
                p = req["params"]
                if p.get("test"):
                    payload = {"request_id": rid, "key": "pong"}
                    resp = requests.post(f"{BASE_URL}/set_key", json=payload, auth=AUTH_USER2, timeout=10)
                    if resp.status_code == 200:
                        logger.info("Ответ на тестовый запрос отправлен")
                    continue

                if "action" in p:
                    success = False
                    if p["action"] == "freeze":
                        success = freeze_key(p["user_id"])
                    elif p["action"] == "unfreeze":
                        success = unfreeze_key(p["user_id"])
                    if success:
                        update_xray_config()
                        payload = {"request_id": rid, "result": "success"}
                    else:
                        payload = {"request_id": rid, "result": "failed"}
                    resp = requests.post(f"{BASE_URL}/set_action_result", json=payload, auth=AUTH_USER2, timeout=10)
                    if resp.status_code == 200:
                        logger.info(f"Action {p['action']} processed for user_id {p['user_id']}")
                    continue

                logger.info(f"Запрос ключа: user_id={p['user_id']}, длительность={p['duration_seconds']}s")
                key_uri = generate_vless_key(
                    user_id=p["user_id"],
                    duration_seconds=p["duration_seconds"],
                    chat_id=p["chat_id"],
                    key_name=p.get("key_name", "KingVless")
                )
                update_xray_config()
                payload = {"request_id": rid, "key": key_uri}
                resp = requests.post(f"{BASE_URL}/set_key", json=payload, auth=AUTH_USER2, timeout=10)
                if resp.status_code == 200:
                    logger.info(f"Ключ отправлен: {key_uri}")
        except Exception as e:
            logger.error(f"monitor_pending_requests error: {e}")
        if stop_event.wait(5):
            break

def poll_users_and_update_xray():
    last_hash = None
    while not stop_event.is_set():
        try:
            r = requests.get(f"{BASE_URL}/users", auth=AUTH_USER2, timeout=10)
            r.raise_for_status()
            users_json = json.dumps(r.json())
            current_hash = md5(users_json.encode()).hexdigest()
            if current_hash != last_hash:
                last_hash = current_hash
                with open(USERS_DB, 'w') as f:
                    f.write(users_json)
                update_xray_config()
                logger.info("users.json обновлён — Xray перезапущен")
        except Exception as e:
            logger.debug(f"poll_users error: {e}")
        if stop_event.wait(30):
            break

if __name__ == "__main__":
    logger.info(f"Запуск monitor.py для хостинга {HOST_ID}...")

    # Попытка автоматически определить публичный IP перед регистрацией (если порт известен, но IP нет)
    try:
        detected = determine_server_ip()
        if detected:
            SERVER_IP = detected
            logger.info(f"Автоопределён public IP: {SERVER_IP}")
    except Exception as e:
        logger.warning(f"Не удалось определить public IP: {e}")

    register_self()
    
    for path, creator in [
        (USERS_DB, lambda: save_users([])),
        (REFERRAL_STATS, lambda: save_ref_stats({})),
        (CONFIG_PATH, update_xray_config),
        (XRAY_LOG, lambda: open(XRAY_LOG, 'a').close())
    ]:
        if not os.path.exists(path):
            creator()
            logger.info(f"Создан: {path}")

    if not os.path.exists(os.path.expanduser("~/bin/xray")):
        if not download_and_extract_xray():
            raise SystemExit("Xray не установлен")

    if not start_xray():
        raise SystemExit("Xray не запустился")

    threading.Thread(target=poll_users_and_update_xray, daemon=True).start()
    threading.Thread(target=backup_monitor, daemon=True).start()
    threading.Thread(target=monitor_pending_requests, daemon=True).start()

    # Ожидаем сигнала остановки; защищаемся от KeyboardInterrupt в основном потоке
    try:
        while not stop_event.is_set():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, setting stop_event")
        stop_event.set()
    finally:
        logger.info("Monitor shutting down")

        sys.exit(0)
