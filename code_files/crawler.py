import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
from playwright.async_api import async_playwright
from termcolor import colored
import asyncio
import re
from urllib.parse import urljoin, urlparse
import logging
import random
import json
import os
import attack
logging.basicConfig(level=logging.CRITICAL)

# Expanded list of realistic user agents
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.3 Mobile/15E148 Safari/604.1",
]

# Proxy configuration via environment variables
PROXY = None
if os.getenv("PROXY_SERVER"):
    PROXY = {
        "server": os.getenv("PROXY_SERVER"),
        "username": os.getenv("PROXY_USERNAME", ""),
        "password": os.getenv("PROXY_PASSWORD", "")
    }

# Optional cookies for authenticated crawling
COOKIES = []  # Example: [{"name": "session_cookie", "value": "your_cookie_value", "domain": "chatgpt.com", "path": "/"}]

async def crawl_website(target_url: str, timeout_seconds: int = 600, max_retries: int = 2):
    print(colored(f"Starting crawl for {target_url} with Playwright...", "blue"))
    crawled_urls = set()
    all_discovered_urls = set()  # Store all URLs encountered
    websocket_urls = set()
    to_crawl = {target_url}
    max_requests = 1000  # Increased to capture more URLs
    max_depth = 4  # Increased for deeper crawling
    current_depth = 0
    per_page_timeout = 60

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True, proxy=PROXY)
            context = await browser.new_context(
                user_agent=random.choice(USER_AGENTS),
                viewport={"width": random.randint(1200, 1920), "height": random.randint(600, 1080)},
                ignore_https_errors=True,
                java_script_enabled=True,
                permissions=["geolocation", "notifications"],
                locale="en-US",
                timezone_id="America/New_York",
            )

            await context.add_init_script("""
                    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                    Object.defineProperty(navigator, 'platform', { get: () => 'Win32' });
                    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => Math.floor(Math.random() * 8 + 2) });
                    Object.defineProperty(navigator, 'deviceMemory', { get: () => Math.floor(Math.random() * 8 + 4) });
                    window.chrome = { runtime: {}, loadTimes: () => {} };
                    Object.defineProperty(navigator, 'plugins', { get: () => [{name: 'PDF Viewer'}, {name: 'Chrome PDF Viewer'}] });
                    Object.defineProperty(navigator, 'languages', { get: () => ['en-US', 'en'] });
                    Object.defineProperty(window, 'screen', {
                        get: () => ({
                            width: Math.floor(Math.random() * 600 + 1200),
                            height: Math.floor(Math.random() * 400 + 600),
                            availWidth: Math.floor(Math.random() * 600 + 1200),
                            availHeight: Math.floor(Math.random() * 400 + 600),
                        })
                    });
                """)

            # Add cookies
            if COOKIES:
                await context.add_cookies(COOKIES)

            async def crawl_page(url, depth, retry_count=0):
                nonlocal crawled_urls, all_discovered_urls, websocket_urls, to_crawl
                if len(crawled_urls) >= max_requests or depth > max_depth or url in crawled_urls:
                    return

                parsed_target = urlparse(target_url)
                parsed_url = urlparse(url)
                if not (parsed_url.netloc == parsed_target.netloc or parsed_url.netloc.endswith('.' + parsed_target.netloc)):
                    return

                # Normalize URL to avoid duplicates
                normalized_url = url.rstrip('/')
                if normalized_url in crawled_urls:
                    return

                # Skip non-navigable URLs but add to all_discovered_urls
                if any(url.lower().endswith(ext) for ext in ['.js', '.json', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2']):
                    logging.debug(f"Skipping non-navigable URL: {url}")
                    all_discovered_urls.add(url)
                    crawled_urls.add(normalized_url)
                    return
                if any(path in url.lower() for path in ['/cdn-cgi/']):
                    logging.debug(f"Skipping CDN endpoint: {url}")
                    all_discovered_urls.add(url)
                    crawled_urls.add(normalized_url)
                    return

                # Handle API endpoints separately
                if any(path in url.lower() for path in ['/api/', '/backend-api/']):
                    logging.debug(f"Processing API endpoint: {url}")
                    all_discovered_urls.add(url)
                    crawled_urls.add(normalized_url)
                    try:
                        async with context.request.get(url, timeout=30000) as response:
                            if response.status == 200:
                                content_type = response.headers.get('content-type', '').lower()
                                if 'json' in content_type:
                                    json_data = await response.json()
                                    urls = re.findall(r'(https?://[^\s"\']+)', json.dumps(json_data), re.IGNORECASE)
                                    ws_urls = re.findall(r'(wss?://[^\s"\']+)', json.dumps(json_data), re.IGNORECASE)
                                    all_discovered_urls.update(urls)
                                    websocket_urls.update(ws_urls)
                                    to_crawl.update([u for u in urls if u not in crawled_urls])
                    except Exception as e:
                        logging.debug(f"Failed to fetch API: {url} - {e}")
                    return
                crawled_urls.add(normalized_url)
                all_discovered_urls.add(url)
                #print(colored(f"Crawling (Depth {depth}): {url}", "blue"))

                page = await context.new_page()
                network_urls = set()

                try:
                    # Intercept network requests
                    async def handle_request(request):
                        try:
                            if request.url.startswith(('http://', 'https://')):
                                parsed_req = urlparse(request.url)
                                if (parsed_req.netloc == parsed_target.netloc or
                                    parsed_req.netloc.endswith('.' + parsed_target.netloc)):
                                    network_urls.add(request.url)
                                    all_discovered_urls.add(request.url)
                        except Exception:
                            pass
                    page.on("request", handle_request)

                    # Capture WebSocket events
                    page.on("websocket", lambda ws: websocket_urls.add(ws.url) if ws.url.startswith(('ws://', 'wss://')) else None)
                    page.on("console", lambda msg: logging.debug(f"Console: {msg.text}"))
                    page.on("requestfailed", lambda req: logging.warning(f"Request failed: {req.url} - {req.failure}"))

                    # Capture network responses
                    async def handle_response(response):
                        try:
                            if response.url.startswith(('http://', 'https://')):
                                headers = await response.all_headers()
                                content_type = headers.get('content-type', '').lower()
                                if 'json' in content_type:
                                    try:
                                        json_data = await response.json()
                                        urls = re.findall(r'(https?://[^\s"\']+)', json.dumps(json_data), re.IGNORECASE)
                                        ws_urls = re.findall(r'(wss?://[^\s"\']+)', json.dumps(json_data), re.IGNORECASE)
                                        all_discovered_urls.update(urls)
                                        websocket_urls.update(ws_urls)
                                    except Exception:
                                        pass
                        except Exception:
                            pass
                    page.on("response", handle_response)

                    # Navigate to page
                    try:
                        response = await page.goto(url, timeout=60000, wait_until="domcontentloaded")
                        if not response:
                            raise Exception("No response received")
                        if response.status in (403, 429, 503):
                            logging.warning(f"Access issue at {url}, status: {response.status}")
                            if retry_count < max_retries:
                                print(colored(f"Retrying {url} ({retry_count + 1}/{max_retries})...", "yellow"))
                                await page.close()
                                await asyncio.sleep(random.uniform(2, 5))
                                return await crawl_page(url, depth, retry_count + 1)
                            return
                    except Exception as e:
                        logging.error(f"Navigation error at {url}: {e}")
                        if retry_count < max_retries:
                            print(colored(f"Retrying {url} ({retry_count + 1}/{max_retries})...", "yellow"))
                            await page.close()
                            await asyncio.sleep(random.uniform(2, 5))
                            return await crawl_page(url, depth, retry_count + 1)
                        return

                    content = await page.content()
                    if any(keyword in content.lower() for keyword in ["enable javascript", "challenge", "captcha", "verify you are human"]):
                        logging.warning(f"Bot challenge detected at {url}, attempting fallback extraction.")
                        headers = response.headers.get('link', '') if response else ''
                        header_urls = re.findall(r'<(https?://[^\s>]+)>', headers, re.IGNORECASE)
                        content_urls = re.findall(r'(https?://[^\s"\']+)', content, re.IGNORECASE)
                        network_urls.update(header_urls + content_urls)
                        all_discovered_urls.update(header_urls + content_urls)
                        to_crawl.update([u for u in network_urls if u not in crawled_urls])
                        return

                    # Simulate human-like behavior
                    await page.evaluate("""
                        () => {
                            const moveMouse = () => {
                                const x = Math.random() * window.innerWidth;
                                const y = Math.random() * window.innerHeight;
                                const event = new MouseEvent('mousemove', { clientX: x, clientY: y });
                                document.dispatchEvent(event);
                            };
                            setInterval(moveMouse, 1000);
                        }
                    """)
                    await page.mouse.move(random.randint(0, 1200), random.randint(0, 600))
                    await page.mouse.click(random.randint(0, 1200), random.randint(0, 600))

                    # Wait longer for network activity
                    try:
                        await page.wait_for_load_state("networkidle", timeout=20000)
                    except Exception:
                        pass

                    # Scroll and interact
                    await page.evaluate("""
                        () => {
                            window.scrollTo(0, document.body.scrollHeight);
                            return new Promise(resolve => setTimeout(resolve, 3000));
                        }
                    """)
                    interactive_elements = await page.query_selector_all('button, a[href], input[type="submit"], div[role="button"]')
                    for element in interactive_elements[:50]:  # Increased interaction limit
                        try:
                            if await element.is_visible():
                                await element.click()
                                await asyncio.sleep(random.uniform(1, 3))
                                await page.mouse.move(random.randint(0, 1200), random.randint(0, 600))
                        except Exception as e:
                            logging.debug(f"Interaction issue in {url}: {e}")

                    # Extract URLs from HTML
                    new_urls = set()
                    links = await page.query_selector_all('a[href]')
                    for link in links:
                        try:
                            href = await link.get_attribute('href')
                            if href:
                                absolute_url = urljoin(url, href)
                                all_discovered_urls.add(absolute_url)
                                parsed_abs = urlparse(absolute_url)
                                if (absolute_url.startswith(('http://', 'https://')) and
                                    (parsed_abs.netloc == parsed_target.netloc or parsed_abs.netloc.endswith('.' + parsed_target.netloc)) and
                                    absolute_url.rstrip('/') not in crawled_urls and
                                    absolute_url not in to_crawl):
                                    new_urls.add(absolute_url)
                        except Exception:
                            continue
                    to_crawl.update(new_urls)

                    # Extract URLs from network activity
                    to_crawl.update([u for u in network_urls if u.rstrip('/') not in crawled_urls])

                    # Extract WebSocket URLs from HTML
                    ws_in_html = re.findall(r'(wss?://[^\s"\']+)', content, re.IGNORECASE)
                    websocket_urls.update(ws_in_html)
                    all_discovered_urls.update(ws_in_html)

                    # Extract WebSocket URLs from scripts
                    scripts = await page.query_selector_all('script')
                    for script in scripts:
                        try:
                            script_content = await script.inner_text()
                            script_urls = re.findall(r'(wss?://[^\s"\']+)', script_content, re.IGNORECASE)
                            ws_dynamic = re.findall(r'new\s+WebSocket\s*\(\s*[\'"](wss?://[^\s"\']+)[\'"]\s*\)', script_content, re.IGNORECASE)
                            websocket_urls.update(script_urls)
                            websocket_urls.update(ws_dynamic)
                            all_discovered_urls.update(script_urls + ws_dynamic)
                        except Exception:
                            pass

                    # Extract URLs from JSON responses
                    responses = await page.query_selector_all('script[type="application/json"]')
                    for response in responses:
                        try:
                            json_content = await response.inner_text()
                            json_data = json.loads(json_content)
                            json_urls = re.findall(r'(https?://[^\s"\']+)', json.dumps(json_data), re.IGNORECASE)
                            ws_json_urls = re.findall(r'(wss?://[^\s"\']+)', json.dumps(json_data), re.IGNORECASE)
                            all_discovered_urls.update(json_urls + ws_json_urls)
                            to_crawl.update([u for u in json_urls if u.rstrip('/') not in crawled_urls])
                            websocket_urls.update(ws_json_urls)
                        except Exception:
                            pass

                except Exception as e:
                    logging.error(f"Error processing {url}: {e}")
                finally:
                    await page.close()

            try:
                while to_crawl and len(crawled_urls) < max_requests and current_depth <= max_depth:
                    current_batch = list(to_crawl - crawled_urls)
                    to_crawl.difference_update(current_batch)
                    tasks = [
                        asyncio.wait_for(crawl_page(url, current_depth), timeout=per_page_timeout)
                        for url in current_batch
                    ]
                    await asyncio.gather(*tasks, return_exceptions=True)
                    current_depth += 1
                    print(colored(f"Depth {current_depth}: Crawled {len(crawled_urls)} URLs, {len(to_crawl)} remaining", "cyan"))

            except asyncio.TimeoutError:
                print(colored(f"Crawl timed out after {timeout_seconds} seconds.", "red"))

            await browser.close()

    except Exception as e:
        logging.error(f"Crawl error: {e}")
        print(colored(f"Crawl error: {e}", "red"))

    websocket_urls = attack.test_working_websocket(websocket_urls)
    
    if not websocket_urls:
        print(colored("No WebSocket endpoints found.", "yellow"))
    else:
        print(colored(f"Found {len(websocket_urls)} WebSocket endpoints:", "green"))

    if not all_discovered_urls:
        print(colored("No URLs discovered.", "yellow"))
    else:
        print(colored(f"Discovered {len(all_discovered_urls)} URLs (including non-crawled):", "green"))

    return {
        "num_crawls": len(crawled_urls),
        "crawled_urls": list(crawled_urls),
        "num_websockets": len(websocket_urls),
        "websocket_urls": list(websocket_urls),
        "crawl_notes": "No WebSocket endpoints found from crawling." if not websocket_urls else ""
    }

#https://www.cryptocompare.com, https://www.tradingview.com, https://www.twitch.tv,https://www.discord.com,https://www.binance.com,https://websocket.org,https://kaazing.com,https://ifelse.io,https://postman.com,https://nownodes.io,https://publicnode.com,https://ankr.com,https://coinsdo.com,http://ws.vi-server.org,http://websocket-echo-intustack.koyeb.app,https://echo-websocket.fly.dev,https://socketsbay.com,https://www.okx.com/docs-v5/en/#overview,https://docs.kraken.com/api/,https://www.blockchain.com/en/,https://docs.bitfinex.com/docs/introduction,https://www.bitstamp.net/,https://docs.gemini.com/get-started/intro,https://pro.coincap.io/api-docs, https://developers.binance.com/en