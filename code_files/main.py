import warnings
warnings.filterwarnings("ignore", category=UserWarning)

import asyncio
from datetime import datetime
import pickle
import time

from termcolor import colored

import attack
import crawler
import report_generator


def print_aligned(label, value, label_width=25):
    """Print a label and value with aligned formatting."""
    print(colored(f"{label:<{label_width}}", "cyan") + colored(f"{value}", "white"))


async def main():
    print(colored("\n=== WebSocket Vulnerability Scanner ===", "blue", attrs=['bold']))
    print(colored("Starting scan on " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "blue"))
    print(colored("=" * 40 + "\n", "blue"))

    start_scan_time = time.time()

    combined_results = {
        'scan_start_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'total_scan_duration': 0,
        'url_scanned': '',
        'total_vulnerabilities': {'High': 0, 'Medium': 0, 'Low': 0, 'No': 0},
        'detailed_results': {},
        'dict_total_errors': {
            "Handshake & Upgrade Validation": 0,
            "Authentication & Session Control": 0,
            "Subprotocols & Extension Handling": 0,
            "Transport Security & Encryption": 0,
            "Payload Framing & Messaging Semantics": 0,
            "Origin Policy & Cross-Origin Enforcement": 0,
            "Application-Layer Logic & Misconfigurations": 0,
            "DoS, Compression & Resource Limits": 0,
            "Protocol Fuzzing": 0,
        }
    }

    di = {}

    print(colored("Choose input mode:", "cyan", attrs=['bold']))
    print(colored("  a. Enter URL to test", "white"))
    print(colored("  b. Enter WebSocket endpoint(s) to test", "white"))

    selected_mode = ""
    while selected_mode not in {"a", "b"}:
        selected_mode = input(colored("Select option (a/b): ", "cyan")).strip().lower()

    if selected_mode == "a":
        target_url = input(colored("Enter the URL you want to test (e.g., https://example.com): ", "cyan")).strip()
        if not target_url:
            print(colored("No URL provided. Exiting.", "red"))
            return

        if not target_url.startswith(("http://", "https://")):
            print(colored(f"[-] Invalid URL: {target_url}. Exiting.", "red"))
            return

        print(colored(f"\n[Scanning] {target_url}", "blue", attrs=['bold']))
        print(colored("-" * 60, "blue"))
        combined_results['url_scanned'] = target_url
        start_time = time.time()

        try:
            crawl_data = await crawler.crawl_website(target_url)
            if not isinstance(crawl_data, dict):
                print(colored("Crawling failed to return expected data structure. Exiting.", "red"))
                return

            websocket_urls = list(crawl_data.get('websocket_urls', []))
            print(colored(f"[+] Crawling complete: {crawl_data.get('num_crawls', 0)} URLs, {len(websocket_urls)} WebSocket endpoints", "green"))

            print(colored("\nWebSocket Endpoints:", "blue", attrs=["bold"]))
            if websocket_urls:
                for i, ws_url in enumerate(websocket_urls, 1):
                    print(colored(f"  {i}. {ws_url}", "white"))
            else:
                print(colored("  None discovered during crawl.", "white"))

            crawl_notes = crawl_data.get('crawl_notes', '')

        except Exception as e:
            print(colored(f"[-] Error crawling {target_url}: {e}", "red"))
            crawl_notes = f"Crawling failed with error: {e}."
        finally:
            if not websocket_urls:
                print(colored(f"\n[!] No WebSocket endpoints found for {target_url}", "red"))
                ws_input = input(colored("    Enter WebSocket URLs (comma-separated, e.g., wss://example.com/ws): ", "cyan")).strip()
                if ws_input:
                    websocket_urls = [ws.strip() for ws in ws_input.split(",") if ws.strip()]
                    if websocket_urls:
                        crawl_notes += f"{crawl_notes} WebSocket URLs added manually post-scan.".strip()
                        print(colored(f"    [+] {len(websocket_urls)} WebSocket URL(s) added to {target_url}", "green"))
                else:
                    print(colored("    [-] No WebSocket endpoints added.", "red"))

            di[target_url] = websocket_urls
            scan_duration = time.time() - start_time
            combined_results['detailed_results'][target_url] = {
                'num_crawled_urls': crawl_data.get('num_crawls', 0),
                'crawled_urls': crawl_data.get('crawled_urls', []),
                'num_websockets': len(websocket_urls),
                'websocket_urls': websocket_urls,
                'crawl_notes': crawl_notes,
                'scan_duration': scan_duration,
            }
    else:
        target_url = input(colored("Enter the base URL for the WebSocket endpoints (e.g., https://example.com): ", "cyan")).strip()
        ws_input = input(colored("Enter WebSocket endpoints (comma-separated, e.g., wss://example.com/ws): ", "cyan")).strip()
        websocket_urls = [ws.strip() for ws in ws_input.split(",")]

        if not websocket_urls:
            print(colored("No WebSocket endpoints provided. Exiting.", "red"))
            return

        di[target_url] = websocket_urls
        combined_results['detailed_results'][target_url] = {
            'num_crawled_urls': 0,
            'crawled_urls': [],
            'num_websockets': len(websocket_urls),
            'websocket_urls': websocket_urls,
            'crawl_notes': 'Crawling Skipped. WebSocket endpoints were provided manually.',
            'scan_duration': 0,
        }

    print(colored("[*] Starting WebSocket attack...", "yellow"))

    try:
        for key, val in di.items():
            attack_time = time.time()
            ws_report, ds = attack.attack_website(val)
            scan_duration = time.time() - attack_time
            details = combined_results["detailed_results"][key]

            details['vulnerabilities'] = ws_report
            details['scan_duration'] += scan_duration
            details['dict_errors'] = ds

    except Exception as e:
        print(colored(f"[-] Error during attack: {e}", "red"))

    print(colored("[+] Attack complete for all websites.", "green"))

    combined_results['total_scan_duration'] = time.time() - start_scan_time

    for _, detail in combined_results["detailed_results"].items():
        vulnerabilities = detail.get("vulnerabilities")
        if vulnerabilities is None:
            continue

        for vuln_group in vulnerabilities.values():
            if vuln_group is None:
                continue
            for item in vuln_group:
                if isinstance(item, dict):
                    risk = item.get("risk", "Low")
                    if risk in combined_results['total_vulnerabilities']:
                        combined_results['total_vulnerabilities'][risk] += 1
                elif isinstance(item, list):
                    for nested_item in item:
                        if isinstance(nested_item, dict):
                            risk = nested_item.get("risk", "Low")
                            if risk in combined_results['total_vulnerabilities']:
                                combined_results['total_vulnerabilities'][risk] += 1

        for category, count in detail.get("dict_errors", {}).items():
            if category in combined_results["dict_total_errors"]:
                combined_results["dict_total_errors"][category] += count

    with open("report1.dat", "wb") as f:
        pickle.dump(combined_results, f)

    print(colored("\n=== Scan Summary ===", "green", attrs=['bold']))
    print_aligned("Scan Start Time:", combined_results['scan_start_time'])
    print_aligned("Total Scan Duration:", f"{combined_results['total_scan_duration']:.2f} seconds")
    print_aligned("URL Scanned:", combined_results['url_scanned'])
    print_aligned("High Severity:", combined_results['total_vulnerabilities']['High'])
    print_aligned("Medium Severity:", combined_results['total_vulnerabilities']['Medium'])
    print_aligned("Low Severity:", combined_results['total_vulnerabilities']['Low'])

    print(colored("\n[*] Generating PDF report...", "yellow"))
    try:
        report_file = report_generator.generate_pdf_report(combined_results)
        print(colored(f"[+] Report saved: {report_file}", "green"))
    except Exception as e:
        print(colored(f"[-] Error generating report: {e}", "red"))


if __name__ == "__main__":
    asyncio.run(main())
