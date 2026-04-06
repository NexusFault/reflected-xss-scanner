import argparse
import time
import re
from urllib.parse import urljoin, parse_qs, urlencode, urlparse
from playwright.sync_api import sync_playwright


def load_payloads(filepath: str) -> list:
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print(f"[!] Wordlist not found: {filepath}")
        return []


def parse_arguments():
    parser = argparse.ArgumentParser(description="Reflected XSS Scanner")
    parser.add_argument("--url", type=str, help="Target URL", required=True)
    parser.add_argument("--cookies", type=str, help="Cookies (key1=value1; key2=value2)")
    parser.add_argument("--user-agent", type=str)
    parser.add_argument("--delay", type=float, default=1, help="Delay between tests")
    parser.add_argument("--headless", action="store_true", default=True)
    parser.add_argument("--wordlist", type=str, help="Path to payloads wordlist", required=True)

    args = parser.parse_args()

    cookies = {}
    if args.cookies:
        for c in args.cookies.split(";"):
            if "=" in c:
                key, value = c.strip().split("=", 1)
                cookies[key] = value

    return args.url, cookies, args.user_agent, args.delay, args.headless, args.wordlist


def extract_reflection_points(html: str, test_str: str):
    reflections = []
    pattern = re.escape(test_str)
    for match in re.finditer(pattern, html):
        start = max(0, match.start() - 50)
        end = min(len(html), match.end() + 50)
        reflections.append({
            "position": match.start(),
            "context": html[start:end],
            "before": html[max(0, match.start() - 10):match.start()],
            "after": html[match.end():match.end() + 10]
        })
    return reflections


def get_context_type(refl: dict) -> str:
    before, after = refl["before"], refl["after"]
    if "<" in before or "<" in after:
        return "html"
    elif '"' in before or '"' in after:
        return "attribute"
    elif "'" in before or "'" in after:
        return "js_string"
    return "text"


def check_xss_vulnerability(html: str, payload: str) -> tuple[bool, str]:
    if payload in html:
        return True, "Direct reflection"
    encoded = payload.replace("<", "%3C").replace(">", "%3E")
    if encoded in html:
        return True, "URL encoded"
    return False, ""


def scan_url(url: str, cookies: dict, user_agent: str, delay: float, headless: bool, payloads: list):
    results = []
    parsed = urlparse(url)
    base_url = f"{parsed.scheme}://{parsed.netloc}"
    query_params = parse_qs(parsed.query)
    test_str = "xss_test_12345"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(
            user_agent=user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            ignore_https_errors=True
        )

        for name, value in cookies.items():
            context.add_cookies([{"name": name, "value": value, "domain": parsed.netloc, "path": "/"}])

        page = context.new_page()

        print(f"\n[*] Scanning: {url}")
        print(f"[*] Query params: {list(query_params.keys()) or 'None'}")

        try:
            page.goto(url, wait_until="networkidle", timeout=30000)
            time.sleep(delay)
        except Exception as e:
            print(f"[!] Page load error: {e}")
            browser.close()
            return results

        form_count = page.locator("form").count()
        print(f"[*] Forms found: {form_count}")

        for i in range(form_count):
            form = page.locator("form").nth(i)
            action = form.get_attribute("action") or url
            method = (form.get_attribute("method") or "get").lower()

            inputs = form.locator("input, textarea, select").all()
            input_data = {inp.get_attribute("name"): test_str for inp in inputs if inp.get_attribute("name")}

            form_url = urljoin(url, action)
            print(f"\n[+] Form #{i+1} -> {form_url} ({method.upper()})")

            if method == "get":
                params = {k: v[0] for k, v in query_params.items()}
                params.update(input_data)
                test_url = f"{form_url}?{urlencode(params)}"

                page.goto(test_url, wait_until="networkidle", timeout=30000)
                time.sleep(delay)

                response_html = page.content()
                reflections = extract_reflection_points(response_html, test_str)

                if reflections:
                    print(f"  [!] {len(reflections)} reflection point(s) found")
                    for refl in reflections:
                        ctx = get_context_type(refl)
                        print(f"      Context: {ctx} | ...{refl['context']}...")

                    for payload in payloads:
                        page.goto(test_url.replace(test_str, payload), wait_until="networkidle", timeout=30000)
                        time.sleep(delay)

                        result_html = page.content()
                        is_vuln, reason = check_xss_vulnerability(result_html, payload)

                        if is_vuln:
                            print(f"\n  [!!!] VULNERABLE!")
                            print(f"       Payload: {payload}")
                            print(f"       Reason: {reason}")

                            results.append({"url": test_url, "form": i + 1, "payload": payload, "context": ctx, "reason": reason})
                            break

        if query_params:
            print(f"\n[*] Testing URL parameters...")
            for param, values in query_params.items():
                for payload in payloads:
                    test_params = {k: v[0] for k, v in query_params.items()}
                    test_params[param] = payload
                    test_url = f"{base_url}{parsed.path}?{urlencode(test_params)}"

                    page.goto(test_url, wait_until="networkidle", timeout=30000)
                    time.sleep(delay)

                    if check_xss_vulnerability(page.content(), payload)[0]:
                        print(f"\n  [!!!] VULNERABLE!")
                        print(f"       Parameter: {param}")
                        print(f"       Payload: {payload}")

                        results.append({"url": test_url, "parameter": param, "payload": payload})
                        break

        browser.close()
    return results


def main():
    url, cookies, user_agent, delay, headless, wordlist_path = parse_arguments()
    payloads = load_payloads(wordlist_path)

    if not payloads:
        print("[!] No payloads loaded. Exiting.")
        return

    print(f"[*] Loaded {len(payloads)} payloads from {wordlist_path}")

    results = scan_url(url, cookies, user_agent, delay, headless, payloads)

    print("\n" + "="*50)
    print(f"[*] Scan complete. Vulnerabilities: {len(results)}")
    for r in results:
        print(f"  - {r['url']} | {r.get('payload', 'N/A')}")


if __name__ == "__main__":
    main()
