"""
HTTP Client for the SRC Vulnerability Mining Agent.

Features:
- Async HTTP requests with configurable rate limiting
- Automatic retry with exponential backoff
- Response analysis (headers, redirects, content-type detection)
- Respects robots.txt when configured
- Request/response tracing for evidence capture
- WAF/firewall detection heuristics
"""

import time
import json
import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from pathlib import Path

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .logger import get_logger

logger = get_logger("agent.http_client")


@dataclass
class HTTPResponse:
    """Structured HTTP response for analysis."""

    url: str
    method: str
    status_code: int
    headers: Dict[str, str]
    body: str
    body_size_bytes: int
    elapsed_seconds: float
    redirect_chain: List[str] = field(default_factory=list)
    request_headers: Dict[str, str] = field(default_factory=dict)
    request_body: Optional[str] = None

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    @property
    def content_type(self) -> str:
        return self.headers.get("Content-Type", "").lower()

    @property
    def is_html(self) -> bool:
        return "text/html" in self.content_type

    @property
    def is_json(self) -> bool:
        return "application/json" in self.content_type


@dataclass
class EndpointInfo:
    """Information about a discovered endpoint."""

    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    forms: List[Dict] = field(default_factory=list)
    response_status: int = 0
    response_size: int = 0
    content_type: str = ""
    linked_from: str = ""


class HTTPClient:
    """
    HTTP client with security research features.

    Usage:
        client = HTTPClient(config)
        resp = client.get("http://target.com/page?id=1")
        if resp.is_html:
            forms = client.extract_forms(resp.body)
    """

    # Common directory scanning wordlist (abbreviated)
    COMMON_PATHS = [
        "admin", "login", "api", "backup", "config", "debug",
        "robots.txt", "sitemap.xml", ".git/HEAD", ".env",
        "wp-admin", "phpinfo.php", "test", "console", "swagger",
        "api/v1", "api/v2", "graphql", "actuator", "health",
        ".well-known/security.txt", "crossdomain.xml",
    ]

    # Technology fingerprint patterns
    TECH_PATTERNS = {
        "PHP": [r'\.php', r'PHPSESSID', r'X-Powered-By:.*PHP'],
        "Java/Spring": [r'JSESSIONID', r'X-Application-Context'],
        "ASP.NET": [r'__VIEWSTATE', r'\.aspx', r'X-AspNet-Version'],
        "Python/Django": [r'csrftoken', r'django'],
        "Python/Flask": [r'werkzeug'],
        "Node.js/Express": [r'X-Powered-By:.*Express', r'connect.sid'],
        "Nginx": [r'Server:.*nginx'],
        "Apache": [r'Server:.*Apache'],
        "Cloudflare": [r'cf-ray', r'__cfduid'],
        "AWS": [r'x-amz-request-id'],
    }

    def __init__(self, config: Dict[str, Any]):
        """
        Initialize HTTP client.

        Args:
            config: Target/HTTP configuration from config.yaml
        """
        self.timeout = config.get("default_timeout", 30)
        self.max_concurrency = config.get("max_concurrency", 10)
        self.rate_limit = config.get("rate_limit", 2.0)
        self.respect_robots = config.get("respect_robots_txt", True)
        self.user_agent = config.get(
            "user_agent", "SRC-VulnMiner/1.0 (Security Research Agent)"
        )
        self.max_page_size = config.get("max_page_size_mb", 10) * 1024 * 1024

        self._session = self._create_session()
        self._no_retry_session = self._create_no_retry_session()
        self._last_request_time = 0.0
        self._robots_cache: Dict[str, List[str]] = {}
        self._trace_log: List[HTTPResponse] = []

        # Metrics
        self.total_requests = 0
        self.total_bytes = 0

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic and security headers."""
        session = requests.Session()

        # Retry strategy — 2 retries for robustness during crawling
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "HEAD", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_maxsize=self.max_concurrency)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/json,*/*",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
        })

        return session

    def _create_no_retry_session(self) -> requests.Session:
        """
        Create a session with NO retries — for verification requests.
        Verification must fail fast; retrying a hung target wastes minutes.
        """
        session = requests.Session()
        adapter = HTTPAdapter(max_retries=Retry(total=0), pool_maxsize=self.max_concurrency)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        session.headers.update({
            "User-Agent": self.user_agent,
            "Accept": "*/*",
        })
        return session

    # --- Rate limiting ---

    def _rate_limit(self):
        """Enforce request rate limiting."""
        if self.rate_limit <= 0:
            return
        elapsed = time.time() - self._last_request_time
        min_interval = 1.0 / self.rate_limit
        if elapsed < min_interval:
            # Add jitter to avoid looking like a bot
            jitter = random.uniform(0, min_interval * 0.5)
            time.sleep(min_interval - elapsed + jitter)
        self._last_request_time = time.time()

    # --- HTTP methods ---

    def get(self, url: str, params: Optional[Dict] = None, **kwargs) -> HTTPResponse:
        """Send a GET request."""
        return self._request("GET", url, params=params, **kwargs)

    def post(self, url: str, data: Optional[Dict] = None, json_data: Optional[Dict] = None, **kwargs) -> HTTPResponse:
        """Send a POST request."""
        return self._request("POST", url, data=data, json=json_data, **kwargs)

    def head(self, url: str, **kwargs) -> HTTPResponse:
        """Send a HEAD request (lightweight, no body)."""
        return self._request("HEAD", url, **kwargs)

    def options(self, url: str, **kwargs) -> HTTPResponse:
        """Send an OPTIONS request to check allowed methods."""
        return self._request("OPTIONS", url, **kwargs)

    def _request(
        self,
        method: str,
        url: str,
        params: Optional[Dict] = None,
        data: Optional[Dict] = None,
        json: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        allow_redirects: bool = True,
        timeout: Optional[int] = None,
        no_retry: bool = False,
        **kwargs,
    ) -> HTTPResponse:
        """
        Core request method with rate limiting, tracing, and error handling.

        Args:
            method: HTTP method
            url: Target URL
            params: Query parameters
            data: Form data
            json: JSON body
            headers: Additional headers
            allow_redirects: Follow redirects
            timeout: Request timeout (seconds)
            no_retry: If True, use no-retry session (for verification requests)

        Returns:
            HTTPResponse with full details
        """
        self._rate_limit()

        timeout = timeout or self.timeout
        session = self._no_retry_session if no_retry else self._session
        req_headers = dict(session.headers)
        if headers:
            req_headers.update(headers)

        start = time.time()
        redirect_chain = []

        try:
            resp = session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json,
                headers=req_headers,
                allow_redirects=allow_redirects,
                timeout=timeout,
                stream=False,
                **kwargs,
            )

            elapsed = time.time() - start

            # Collect redirect history
            for r in resp.history:
                redirect_chain.append(r.url)

            # Read body with size limit
            body = ""
            if method != "HEAD":
                if int(resp.headers.get("Content-Length", 0)) > self.max_page_size:
                    logger.warning(f"Response body exceeds size limit: {url}")
                    body = resp.text[:self.max_page_size]
                else:
                    body = resp.text

            result = HTTPResponse(
                url=resp.url,
                method=method,
                status_code=resp.status_code,
                headers=dict(resp.headers),
                body=body,
                body_size_bytes=len(body.encode("utf-8")),
                elapsed_seconds=round(elapsed, 3),
                redirect_chain=redirect_chain,
                request_headers=req_headers,
                request_body=str(data) if data else (str(json) if json else None),
            )

            self.total_requests += 1
            self.total_bytes += result.body_size_bytes
            self._trace_log.append(result)

            logger.debug(f"{method} {resp.url} → {resp.status_code} ({elapsed:.2f}s, {result.body_size_bytes}B)")
            return result

        except requests.exceptions.Timeout:
            logger.warning(f"Request timeout ({timeout}s): {method} {url}")
            return HTTPResponse(
                url=url, method=method, status_code=0,
                headers={}, body="", body_size_bytes=0,
                elapsed_seconds=timeout,
            )
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"Connection error: {method} {url} — {e}")
            return HTTPResponse(
                url=url, method=method, status_code=0,
                headers={}, body="", body_size_bytes=0,
                elapsed_seconds=time.time() - start,
            )
        except Exception as e:
            logger.error(f"Unexpected error during {method} {url}: {e}")
            return HTTPResponse(
                url=url, method=method, status_code=0,
                headers={}, body="", body_size_bytes=0,
                elapsed_seconds=time.time() - start,
            )

    # --- Response analysis ---

    def extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """
        Extract HTML forms from a page.

        Returns list of dicts with:
            - action: form action URL
            - method: GET or POST
            - inputs: list of {name, type, value}

        Args:
            html: HTML content
            base_url: Base URL for resolving relative form actions

        Returns:
            List of parsed forms
        """
        from bs4 import BeautifulSoup

        forms = []
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return forms

        for form in soup.find_all("form"):
            action = form.get("action", "")
            if action:
                action = urljoin(base_url, action)
            else:
                action = base_url

            method = form.get("method", "GET").upper()
            inputs = []

            for inp in form.find_all(["input", "textarea", "select"]):
                inputs.append({
                    "name": inp.get("name", ""),
                    "type": inp.get("type", "text"),
                    "value": inp.get("value", ""),
                    "tag": inp.name,
                })

            forms.append({
                "action": action,
                "method": method,
                "inputs": inputs,
                "id": form.get("id", ""),
                "class": form.get("class", []),
            })

        return forms

    def extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML."""
        from bs4 import BeautifulSoup

        links = set()
        try:
            soup = BeautifulSoup(html, "lxml")
        except Exception:
            try:
                soup = BeautifulSoup(html, "html.parser")
            except Exception:
                return list(links)

        for a in soup.find_all("a", href=True):
            href = a["href"]
            if href.startswith(("javascript:", "mailto:", "#", "tel:")):
                continue
            full_url = urljoin(base_url, href)
            links.add(full_url)

        # Also extract script src and link href
        for tag in soup.find_all(["script", "link"], src=True):
            full_url = urljoin(base_url, tag.get("src", tag.get("href", "")))
            links.add(full_url)

        return list(links)

    def extract_params(self, url: str) -> List[str]:
        """Extract query parameter names from a URL."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        return list(params.keys())

    def detect_tech_stack(self, response: HTTPResponse) -> List[str]:
        """
        Detect technology stack from response headers and body.

        Args:
            response: HTTPResponse to analyze

        Returns:
            List of detected technology names
        """
        import re

        detected = set()
        # Combine headers and first part of body for analysis
        analysis_text = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        analysis_text += "\n" + response.body[:2000]

        for tech, patterns in self.TECH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, analysis_text, re.IGNORECASE):
                    detected.add(tech)

        return sorted(detected)

    def check_waf(self, response: HTTPResponse) -> Optional[str]:
        """
        Detect if a WAF (Web Application Firewall) is present.

        Args:
            response: HTTPResponse from the target

        Returns:
            WAF name if detected, None otherwise
        """
        waf_signatures = {
            "Cloudflare": ["cf-ray", "__cfduid", "cf-chl-bypass"],
            "AWS WAF": ["x-amzn-RequestId", "x-amz-cf-id"],
            "Akamai": ["X-Akamai-Transformed"],
            "ModSecurity": ["Mod_Security", "This error was generated by Mod_Security"],
            "F5 BIG-IP": ["BIGipServer", "X-WA-Info"],
            "Imperva": ["X-Iinfo", "_incapsula_"],
            "Sucuri": ["Sucuri/Cloudproxy", "X-Sucuri-ID"],
        }

        header_str = json.dumps(dict(response.headers)).lower()
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig.lower() in header_str or sig.lower() in response.body[:2000].lower():
                    logger.info(f"Detected WAF: {waf_name} (signature: {sig})")
                    return waf_name
        return None

    # --- Discovery ---

    def discover_endpoints(
        self, base_url: str, response: HTTPResponse
    ) -> List[EndpointInfo]:
        """
        Discover endpoints from a base URL and its response.

        Args:
            base_url: The target base URL
            response: HTTPResponse from the base URL

        Returns:
            List of discovered EndpointInfo objects
        """
        endpoints = []

        if not response.is_html:
            return endpoints

        # Extract parameters from the URL itself
        params = self.extract_params(base_url)
        if params:
            endpoints.append(EndpointInfo(
                url=base_url, method="GET", params=params,
                response_status=response.status_code,
                content_type=response.content_type,
            ))

        # Extract forms
        for form in self.extract_forms(response.body, base_url):
            input_names = [inp["name"] for inp in form["inputs"] if inp["name"]]
            endpoints.append(EndpointInfo(
                url=form["action"],
                method=form["method"],
                params=input_names,
                response_status=0,
                content_type="",
                linked_from=base_url,
            ))

        # Extract links (same-domain only)
        base_domain = urlparse(base_url).netloc
        for link in self.extract_links(response.body, base_url):
            parsed = urlparse(link)
            if parsed.netloc == base_domain or not parsed.netloc:
                link_params = self.extract_params(link)
                if link_params:
                    endpoints.append(EndpointInfo(
                        url=link, method="GET", params=link_params,
                        linked_from=base_url,
                    ))

        return endpoints

    def directory_scan(self, base_url: str) -> List[str]:
        """
        Scan common directories and paths on the target.

        Args:
            base_url: Base URL of the target

        Returns:
            List of discovered URLs (those returning non-404)
        """
        discovered = []
        base = base_url.rstrip("/")

        logger.info(f"Directory scanning: {base} ({len(self.COMMON_PATHS)} paths)")

        for path in self.COMMON_PATHS:
            url = f"{base}/{path.lstrip('/')}"
            resp = self.head(url)
            if resp.status_code != 404 and resp.status_code != 0:
                # Confirm with GET
                resp = self.get(url)
                if resp.status_code not in (404, 0):
                    discovered.append(url)
                    logger.info(f"  Found: {url} ({resp.status_code})")

        return discovered

    # --- Trace access ---

    def get_trace(self) -> List[HTTPResponse]:
        """Get the full request/response trace for evidence."""
        return list(self._trace_log)

    def save_trace(self, filepath: str) -> None:
        """Save the HTTP trace to a file for evidence."""
        trace_data = []
        for resp in self._trace_log:
            trace_data.append({
                "url": resp.url,
                "method": resp.method,
                "status": resp.status_code,
                "request_headers": resp.request_headers,
                "response_headers": resp.headers,
                "body_preview": resp.body[:500],
                "elapsed": resp.elapsed_seconds,
            })

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(trace_data, f, ensure_ascii=False, indent=2)
        logger.info(f"HTTP trace saved: {path} ({len(trace_data)} requests)")

    def get_stats(self) -> Dict[str, Any]:
        """Get HTTP client statistics."""
        return {
            "total_requests": self.total_requests,
            "total_bytes_transferred": self.total_bytes,
            "rate_limit": self.rate_limit,
        }
