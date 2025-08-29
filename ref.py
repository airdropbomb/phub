import requests
from eth_account import Account
from eth_account.messages import encode_defunct
import random, string, time, urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://hub-prod.engineering-87e.workers.dev"

# === Load User-Agents from brs.txt ===
try:
    with open("brs.txt", "r") as f:
        USER_AGENTS = [line.strip() for line in f if line.strip()]
except FileNotFoundError:
    USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]  # fallback

def get_random_headers():
    ua = random.choice(USER_AGENTS)
    return {
        "Accept": "application/json",
        "Origin": "https://hub.playai.network",
        "Referer": "https://hub.playai.network/",
        "User-Agent": ua
    }

# === Retry wrapper ===
def safe_request(method, url, max_retries=3, backoff=3, **kwargs):
    if 'verify' not in kwargs:
        kwargs['verify'] = False
    for attempt in range(max_retries):
        try:
            print(f"[🔄 Attempt {attempt+1}/{max_retries}] Processing...", end="\r")
            response = requests.request(method, url, timeout=30, **kwargs)
            response.raise_for_status()
            print(f"[✅] Success on attempt {attempt+1}")
            return response
        except requests.exceptions.RequestException:
            time.sleep(backoff * (attempt+1))
    print(f"[❌] Failed after {max_retries} retries.")
    return None

# === Random username generator ===
def random_username(prefix=None, length=4):
    if prefix is None:
        prefixes = ["neo", "ari", "niko", "luna", "kai", "alex"]
        prefix = random.choice(prefixes)
    suffix = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return prefix + suffix

def create_unique_username(headers, max_attempts=10):
    for _ in range(max_attempts):
        username = random_username()
        res = safe_request("POST", f"{BASE_URL}/user/username", headers=headers, json={"username": username})
        if res and res.status_code == 200:
            return res.json().get("username", username)
        elif res and "username" in res.text.lower():
            continue
        else:
            break
    raise Exception("❌ Failed to generate unique username")

# === Daily check-in / streak ===
def daily_check_in(headers):
    res = safe_request("POST", f"{BASE_URL}/user/streak", headers=headers)
    if res and res.status_code == 200:
        data = res.json()
        claimed_today = data.get("claimedToday", False) or data.get("claimed", False)
        if claimed_today:
            print(f"[🟢] Claimed Today already")
        else:
            print(f"[✅] Success Claimed!")
        return True
    else:
        print(f"[🟢] Claimed Today already")
        return False

# === Create account with referral ===
def create_account(referral_code, success_count, fail_count):
    account = Account.create()
    address = account.address
    private_key = account.key.hex()
    print(f"[✅] Wallet: {address}")

    headers = get_random_headers()

    # Nonce + message
    res = safe_request("GET", f"{BASE_URL}/auth/wallet", headers=headers)
    if not res or res.status_code != 200:
        print("[❌] Error fetching nonce.")
        fail_count += 1
        print(f"[📊] Total Success: {success_count}, Total Fail: {fail_count}")
        return None, success_count, fail_count
    data = res.json()
    message_text = data.get("message")
    nonce = data.get("nonce")

    # Sign + login
    message = encode_defunct(text=message_text)
    signed = Account.sign_message(message, private_key=private_key)
    signature = "0x" + signed.signature.hex()
    payload = {"wallet": address, "nonce": nonce, "signature": signature}

    auth_res = safe_request("POST", f"{BASE_URL}/auth/wallet/evm",
                             headers={**headers, "Content-Type": "application/json"},
                             json=payload)
    if not auth_res or auth_res.status_code != 200:
        print("[❌] Wallet login failed.")
        fail_count += 1
        print(f"[📊] Total Success: {success_count}, Total Fail: {fail_count}")
        return None, success_count, fail_count

    jwt_token = auth_res.json().get("jwt")
    if not jwt_token:
        print("[❌] JWT not found.")
        fail_count += 1
        print(f"[📊] Total Success: {success_count}, Total Fail: {fail_count}")
        return None, success_count, fail_count

    headers_with_auth = {**headers, "Content-Type": "application/json", "Authorization": f"Bearer {jwt_token}"}

    # Username
    username = create_unique_username(headers_with_auth)
    print(f"[✅] Username created: {username}")

    # Referral
    res3 = safe_request("POST", f"{BASE_URL}/user/referral/add", headers=headers_with_auth, json={"code": referral_code})
    if res3 and res3.status_code == 200:
        print(f"[📩] Referral: Success")
    else:
        print(f"[📩] Referral: Fail")
        fail_count += 1

    # Daily check-in
    daily_check_in(headers_with_auth)

    # Save account
    with open("successful_accounts.txt", "a") as f:
        f.write(f"{address},{private_key},{username},{jwt_token},{referral_code}\n")

    success_count += 1
    print(f"[💾] Account Saved.")
    print(f"[📊] Total Success: {success_count}, Total Fail: {fail_count}\n")
    return address, success_count, fail_count

# === Main ===
if __name__ == "__main__":
    try:
        with open("ref.txt", "r") as f:
            referral_codes = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        referral_codes = ["cf0xo83963"]

    total = int(input("👉 How many accounts would you like to create?: "))
    success_count = 0
    fail_count = 0

    for i in range(total):
        referral_code = referral_codes[i % len(referral_codes)]
        print(f"\n=== 🚀 Account {i+1}/{total} using referral code: {referral_code} ===")
        try:
            _, success_count, fail_count = create_account(referral_code, success_count, fail_count)
        except Exception as e:
            print(f"[❌] Error: {e}")
            fail_count += 1
            print(f"[📊] Total Success: {success_count}, Total Fail: {fail_count}")
        time.sleep(5)
