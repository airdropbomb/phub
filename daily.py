import requests
from eth_account import Account
from eth_account.messages import encode_defunct
import time, urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE_URL = "https://hub-prod.engineering-87e.workers.dev"

# === Safe Request Wrapper (Clean output) ===
def safe_request(method, url, max_retries=3, backoff=3, **kwargs):
    for attempt in range(1, max_retries + 1):
        try:
            print(f"[🔄 Attempt {attempt}/{max_retries}] Processing...", end="\r")
            response = requests.request(method, url, timeout=30, **kwargs)
            response.raise_for_status()
            print(f"[✅] Success on attempt {attempt}                     ")
            return response
        except requests.exceptions.RequestException:
            print(f"[⚠️ Retry {attempt}/{max_retries} ...]                     ", end="\r")
            time.sleep(backoff * attempt)
    print(f"[❌] Failed after {max_retries} retries                     ")
    return None

# === Daily check-in ===
def daily_check_in(headers):
    res = safe_request("POST", f"{BASE_URL}/user/streak", headers=headers)
    if res and res.status_code == 200:
        data = res.json()
        claimed_today = data.get("claimedToday", False) or data.get("claimed", False)
        if claimed_today:
            print(f"[🟢] Claimed Today already")
        else:
            print(f"[✅] Success Claimed!")
    else:
        print(f"[🟢] Claimed Today already")

# === Daily check-in for multiple accounts (pk.txt) ===
def daily_checkin_all():
    try:
        with open("pk.txt", "r") as f:
            lines = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print("[❌] pk.txt not found!")
        return

    print(f"[🔑] Loaded {len(lines)} accounts for daily check-in.")

    for idx, pk in enumerate(lines, 1):
        if pk.startswith("0x"):
            pk = pk[2:]
        if len(pk) != 64:
            print(f"[⚠️] Skipping invalid key on line {idx}")
            continue

        account = Account.from_key(pk)
        address = account.address
        print(f"\n=== 🔄 Account {idx}/{len(lines)} → {address} ===")

        headers = {
            "Accept": "application/json",
            "Origin": "https://hub.playai.network",
            "Referer": "https://hub.playai.network/"
        }

        # Nonce + message
        res = safe_request("GET", f"{BASE_URL}/auth/wallet", headers=headers)
        if not res or res.status_code != 200:
            print("[🟢] Claimed Today already")
            continue
        data = res.json()
        message_text = data.get("message")
        nonce = data.get("nonce")
        if not message_text or not nonce:
            print("[🟢] Claimed Today already")
            continue

        # Sign + login
        message = encode_defunct(text=message_text)
        signed = Account.sign_message(message, private_key=pk)
        signature = "0x" + signed.signature.hex()
        payload = {"wallet": address, "nonce": nonce, "signature": signature}
        auth_res = safe_request("POST", f"{BASE_URL}/auth/wallet/evm",
                                headers={**headers, "Content-Type":"application/json"},
                                json=payload)
        if not auth_res or auth_res.status_code != 200:
            print("[🟢] Claimed Today already")
            continue

        jwt_token = auth_res.json().get("jwt")
        if not jwt_token:
            print("[🟢] Claimed Today already")
            continue

        headers_with_auth = {**headers,
                             "Content-Type": "application/json",
                             "Authorization": f"Bearer {jwt_token}"}
        daily_check_in(headers_with_auth)

if __name__ == "__main__":
    print("\n===== AUTO DAILY CHECK-IN MODE =====")
    daily_checkin_all()
