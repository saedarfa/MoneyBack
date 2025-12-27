
import os , sys
import json
import time
import base64
import hashlib
import requests
from typing import Dict, Any, List
import pyfiglet
from colorama import Fore
import webbrowser
G = Fore.GREEN
R = Fore.RED
Y = Fore.YELLOW
B = Fore.BLUE
import shutil
logo = r"""
     .... NO! ...                  ... MNO! ...
   ..... MNO!! ...................... MNNOO! ...
 ..... MMNO! ......................... MNNOO!! .
..... MNOONNOO!   MMMMMMMMMMPPPOII!   MNNO!!!! .
 ... !O! NNO! MMMMMMMMMMMMMPPPOOOII!! NO! ....
    ...... ! MMMMMMMMMMMMMPPPPOOOOIII! ! ...
   ........ MMMMMMMMMMMMPPPPPOOOOOOII!! .....
   ........ MMMMMOOOOOOPPPPPPPPOOOOMII! ...
    ....... MMMMM..    OPPMMP    .,OMI! ....
     ...... MMMM::   o.,OPMP,.o   ::I!! ...
         .... NNM:::.,,OOPM!P,.::::!! ....
          .. MMNNNNNOOOOPMO!!IIPPO!!O! .....
         ... MMMMMNNNNOO:!!:!!IPPPPOO! ....
           .. MMMMMNNOOMMNNIIIPPPOO!! ......
          ...... MMMONNMMNNNIIIOO!..........
       ....... MN MOMMMNNNIIIIIO! OO ..........
    ......... MNO! IiiiiiiiiiiiI OOOO ...........
  ...... NNN.MNO! . O!!!!!!!!!O . OONO NO! ........
   .... MNNNNNO! ...OOOOOOOOOOO .  MMNNON!........
   ...... MNNNNO! .. PPPPPPPPP .. MMNON!........
      ...... OO! ................. ON! .......
         ................................
          {by @MR_ALKAP00S}
          {MoneyBack}
"""

def center_ascii(text: str) -> str:
    term_width = shutil.get_terminal_size((80, 20)).columns
    lines = text.splitlines()

    max_len = max(len(line) for line in lines)
    left_padding = max((term_width - max_len) // 2, 0)

    return "\n".join((" " * left_padding) + line for line in lines)


#@MR_ALKAPOS

s=("□■"*30)
m=("□■"*30)
g=("□■"*30)
SK = pyfiglet.figlet_format('                TEAM')
saa = pyfiglet.figlet_format('       ALKAPOS')
sk2=pyfiglet.figlet_format('        Vodafone')
alkapos=pyfiglet.figlet_format('        MoneyBack')
def sped(s):
        for c in s + '\n':
        	sys.stdout.write(c)
        	sys.stdout.flush()
        	time.sleep(0.001)
        	def kapos():
        		print("")
os.system('clear')
sped(R+g)
sped(R+center_ascii(logo))
sped(R+s)
sped(G+SK)
sped(G+saa)
sped(R+m)
sped(R+sk2)
sped(R+g)
sped(Y+alkapos)
sped(R+g)

webbrowser.open("https://t.me/TEAM_ALKAPOS")






BASE_DIR = "@MR_ALKAP00S"
SESSIONS_FILE = os.path.join(BASE_DIR, "@MR_ALKAP00S.dat")
SESSION_TTL = 24 * 60 * 60
os.makedirs(BASE_DIR, exist_ok=True)


SECRET_KEY = "MR_ALKAP00S_SUPER_SECRET_KEY"


CLIENT_ID = "ana-vodafone-app"
CLIENT_SECRET = "95fd95fb-7489-4958-8ae6-d31a525cd20a"

BASE_HEADERS = {
    "User-Agent": "okhttp/4.11.0",
    "Accept": "application/json",
    "Accept-Encoding": "gzip",
    "Accept-Language": "ar",
    "x-agent-operatingsystem": "15",
    "x-agent-device": "HONOR ALI-NX1",
    "x-agent-version": "2024.11.2",
    "x-agent-build": "944",
}


def now_ts():
    return int(time.time())

def safe_int(x, default=None):
    try:
        return int(x)
    except:
        return default

def ask_yes_no(prompt: str, default="n"):
    d = default.lower()
    while True:
        ans = input(Y+f"{prompt} (y/n) [{'y' if d=='y' else 'n'}]: ").strip().lower()
        if ans == "":
            ans = d
        if ans in ("y", "yes", "اه", "أيوه", "ايوه", "ا"):
            return True
        if ans in ("n", "no", "لا", "ل"):
            return False
        print("❗ اكتب y أو n")


def _derive_key():
    return hashlib.sha256(SECRET_KEY.encode()).digest()

def encrypt_data(data: Dict[str, Any]) -> bytes:
    raw = json.dumps(data, ensure_ascii=False).encode()
    key = _derive_key()
    encrypted = bytes(raw[i] ^ key[i % len(key)] for i in range(len(raw)))
    return base64.b64encode(encrypted)

def decrypt_data(blob: bytes) -> Dict[str, Any]:
    encrypted = base64.b64decode(blob)
    key = _derive_key()
    raw = bytes(encrypted[i] ^ key[i % len(key)] for i in range(len(encrypted)))
    return json.loads(raw.decode())


def load_sessions() -> Dict[str, Any]:
    if not os.path.exists(SESSIONS_FILE):
        return {}
    try:
        with open(SESSIONS_FILE, "rb") as f:
            return decrypt_data(f.read())
    except:
        return {}

def save_sessions(sessions: Dict[str, Any]):
    with open(SESSIONS_FILE, "wb") as f:
        f.write(encrypt_data(sessions))

def cleanup_sessions():
    sessions = load_sessions()
    now = now_ts()
    cleaned = {
        k: v for k, v in sessions.items()
        if now - v.get("updated_at", 0) <= SESSION_TTL
    }
    save_sessions(cleaned)

def upsert_session(number, password, token, packages):
    sessions = load_sessions()
    sessions[number] = {
        "password": password,
        "token": token,
        "packages": packages,
        "created_at": sessions.get(number, {}).get("created_at", now_ts()),
        "updated_at": now_ts(),
    }
    save_sessions(sessions)


def get_token(number, password):
    url = "https://mobile.vodafone.com.eg/auth/realms/vf-realm/protocol/openid-connect/token"
    payload = {
        "grant_type": "password",
        "username": number,
        "password": password,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    headers = BASE_HEADERS | {
        "silentLogin": "false",
        "digitalId": "297WAW1VKE02A",
    }
    r = requests.post(url, headers=headers, data=payload)
    if not "access_token" in r.text:
    	print(R+"الرقم او الباسورد غلط اتأكد و حاول تاني")
    	return None
    r.raise_for_status()
    
    return r.json()["access_token"]


def get_packages(number, token):
    end_time = int(time.time() * 1000)
    start_time = end_time - (35 * 24 * 60 * 60 * 1000)

    url = (
        "https://mobile.vodafone.com.eg/services/dxl/usagemng/usage"
        f"?relatedParty.id={number}"
        f"&validFor.startDateTime={start_time}"
        f"&validFor.endDateTime={end_time}"
        f"&%40type=BalanceDetails"
    )

    headers = BASE_HEADERS | {
        "Authorization": f"Bearer {token}",
        "api-host": "UsageManagementHost",
        "api-version": "v2",
        "clientId": "AnaVodafoneAndroid",
        "msisdn": number,
        "Content-Type": "application/json",
    }

    r = requests.get(url, headers=headers)
    r.raise_for_status()

    packages = []
    for item in r.json():
        enc_id = next(
            (c.get("value") for c in item.get("usageCharacteristic", [])
             if c.get("name") == "EncProductID"),
            None
        )
        if not enc_id:
            continue

        price = None
        rated = item.get("ratedProductUsage")
        if rated:
            amt = rated[0].get("taxIncludedRatingAmount")
            if amt:
                price = abs(int(amt))

        packages.append({
            "name": item.get("description", "غير معروف"),
            "id": enc_id,
            "price": price
        })
    return packages


def perform_moneyback(number, token, enc_id):
    url = "https://mobile.vodafone.com.eg/services/dxl/pom/productOrder"
    payload = {
        "channel": {"name": "internet"},
        "orderItem": [{
            "action": "add",
            "product": {
                "characteristic": [
                    {"name": "WorkflowName", "value": "SelfRefund"},
                    {"name": "EncProductID", "value": enc_id},
                    {"name": "ActionID", "value": "6"},
                ],
                "relatedParty": [
                    {"id": number, "name": "MSISDN", "role": "Subscriber"}
                ]
            },
            "eCode": 0
        }],
        "@type": "MoneyBack"
    }
    headers = BASE_HEADERS | {
        "Authorization": f"Bearer {token}",
        "api-host": "ProductOrderingManagement",
        "api-version": "v2",
        "clientId": "AnaVodafoneAndroid",
        "msisdn": number,
        "Content-Type": "application/json",
        "useCase": "MONEYBACK",
    }
    r = requests.post(url, headers=headers, data=json.dumps(payload))
    
    
    return r.status_code, r.text


def interpret_response(text, status):
    t = text.lower()

    # نجاح
    if status == 200 and ("completed" in t or "success" in t):
        return f"{G}✅ تمت العملية بنجاح"

    # تخطي حد الاسترجاع
    if "maximum number of refunds" in t:
        return f"{R}⚠️ العميل تخطّى الحد الأقصى للاسترجاع هذا الشهر"

    # طلب سابق شغال
    if "not compatible products" in t:
        return f"{B}⏳ الطلب السابق ما زال تحت التنفيذ"

    # عدد المحاولات
    if "capping limit exceed" in t:
        return f"{R}⛔ وصلت للحد الأقصى من المحاولات هذا الشهر"

    # استهلاك من الباقة
    if "consumed more than" in t and "bundle" in t:
        return f"{R}⛔ عفواً لقد استهلكت أكثر من المسموح من الباقة ولا يمكنك استرجاعها"

    # غير معروف
    return f"{Y}❓ رد غير معروف من السيرفر"


def main():
    cleanup_sessions()

    number = input(G+"📱 ادخل رقم الخط: ").strip()
    password = input(G+"🔑 ادخل الباسورد: ").strip()

    sessions = load_sessions()
    session = sessions.get(number)

    if session:
        print(Y+"\n📌 تم العثور على جلسة محفوظة.")
        if ask_yes_no(G+"➡️ عاوز تفتح الجلسة المحفوظة؟", "y"):
            token = get_token(number, password)
            if not token:
            	return
            packages = session["packages"]
        else:
            print(R+"⚠️ الجلسة القديمة هتتحذف.")
            if not ask_yes_no(Y+"❗ متأكد؟", "n"):
                return
            del sessions[number]
            save_sessions(sessions)
            token = get_token(number, password)
            packages = get_packages(number, token)
            upsert_session(number, password, token, packages)
    else:
        token = get_token(number, password)
        if not token:
        	return
        packages = get_packages(number, token)
        upsert_session(number, password, token, packages)

    print(B+"\n📦 الباقات:")
    for i, p in enumerate(packages, 1):
        print(f"{i}) {p['name']}   {p['price']}")

    choice = safe_int(input(Y+"\n➡️ اختر رقم الباقة: "))
    selected = packages[choice - 1]

    status, text = perform_moneyback(number, token, selected["id"])
    print(B+"\n📌 النتيجة:")
    print(interpret_response(text, status))

if __name__ == "__main__":
    main()
