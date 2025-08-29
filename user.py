import random
from pathlib import Path

# Supported browsers
BROWSERS = {
    "1": "opera",
    "2": "chrome",
    "3": "firefox",
    "4": "edge",
    "5": "safari",
    "6": "random",  # special: combine all
}

# Expanded UA lists (~100 per browser)
FALLBACK_UAS = {
    "opera": [f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) OPR/{100+i}.0.0.0" for i in range(100)],
    "chrome": [f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/{100+i}.0.0.0" for i in range(100)],
    "firefox": [f"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:{100+i}.0) Firefox/{100+i}.0" for i in range(100)],
    "edge": [f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Edg/{100+i}.0.0.0" for i in range(100)],
    "safari": [f"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Version/{14+i}.0 Safari/605.1.15" for i in range(100)],
}

# Add combined pool for random (all browsers together)
FALLBACK_UAS["random"] = (
    FALLBACK_UAS["opera"]
    + FALLBACK_UAS["chrome"]
    + FALLBACK_UAS["firefox"]
    + FALLBACK_UAS["edge"]
    + FALLBACK_UAS["safari"]
)


def generate_user_agents(browser_choice, n=10, filename="brs.txt"):
    agents = set()

    # Load existing UAs if file exists
    file_path = Path(filename)
    if file_path.exists():
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    agents.add(line.strip())

    start_count = len(agents)
    generated = 0

    while generated < n:
        browser_key = BROWSERS.get(browser_choice)
        if browser_key not in FALLBACK_UAS:
            browser_key = "chrome"  # default fallback

        ua_list = FALLBACK_UAS[browser_key]
        ua_pool = ua_list * ((n // len(ua_list)) + 2)
        random.shuffle(ua_pool)

        for ua in ua_pool:
            if ua not in agents:
                agents.add(ua)
                generated += 1
                # Progress fraction update
                print(f"\r{generated} / {n}", end="", flush=True)
                if generated >= n:
                    break

    # Save final UA list
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(agents)))

    print()  # move to new line
    print(f"Added {len(agents) - start_count} new agents → Total {len(agents)} saved in {filename}")


if __name__ == "__main__":
    print("Available Browsers:")
    for k, v in BROWSERS.items():
        print(f"{k}: {v.capitalize()}")

    browser_choice = input("\nChoose a browser (number): ").strip()
    try:
        n = int(input("How many user-agents do you want to generate? : ").strip())
    except ValueError:
        n = 10

    generate_user_agents(browser_choice, n, "brs.txt")
