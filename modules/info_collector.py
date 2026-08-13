"""
Module 2: Information Collector (信息采集模块)

Collects all relevant information about the target before analysis:
- HTTP endpoint discovery (crawling, directory scanning)
- Form and input parameter extraction
- Technology stack fingerprinting
- API documentation discovery
- WAF/CDN detection
- Source code retrieval (git clone or local path)

Design principle: Collect comprehensively but within scope.
All collection respects rate limits and robots.txt.
"""

import re
import json
from typing import Dict, List, Optional, Any, Set
from urllib.parse import urljoin, urlparse
from pathlib import Path

from utils.logger import get_logger

logger = get_logger("agent.info_collector")


class InfoCollector:
    """
    Collects target information through various channels.

    Usage:
        collector = InfoCollector(http_client, llm_client, config)
        inventory = collector.collect(parsed_task)
        # inventory = {
        #     "endpoints": [...],
        #     "files": [...],
        #     "tech_stack": [...],
        #     "forms": [...],
        #     "raw_responses": {...},
        # }
    """

    # Common file extensions to look for
    INTERESTING_EXTENSIONS = {
        ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
        ".py", ".rb", ".go", ".js", ".ts",
        ".json", ".xml", ".yaml", ".yml",
        ".conf", ".config", ".ini", ".env",
        ".sql", ".db", ".sqlite",
        ".bak", ".backup", ".old", ".swp",
        ".gitignore", ".dockerignore",
    }

    def __init__(self, http_client, llm_client, config: Dict[str, Any]):
        """
        Initialize the information collector.

        Args:
            http_client: HTTPClient instance
            llm_client: LLMClient instance (for smart endpoint analysis)
            config: Full agent configuration
        """
        self.http = http_client
        self.llm = llm_client
        self.config = config
        self.target_config = config.get("target", {})
        self.max_depth = self.target_config.get("max_depth", 3)
        self.max_endpoints = self.target_config.get("max_endpoints", 500)

        # Visited URL tracking to avoid duplicates
        self._visited: Set[str] = set()

    def collect(self, parsed_task: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute all collection methods for a parsed task.

        Args:
            parsed_task: Output from TaskParser.parse()

        Returns:
            Asset inventory dictionary
        """
        target_url = parsed_task.get("target_url", "")
        scope = parsed_task.get("scope", [target_url])

        if not target_url:
            logger.warning("No target URL in parsed task, skipping collection")
            return self._empty_inventory()

        logger.info(f"Starting collection for: {target_url}")

        endpoints = []
        forms = []
        tech_stack = []
        raw_responses = {}
        files = []

        # Step 1: Fetch main page
        logger.info("  Fetching main page...")
        main_response = self.http.get(target_url)
        if main_response.status_code == 0:
            logger.error(f"Cannot reach target: {target_url}")
            return self._empty_inventory(error=f"Target unreachable: {target_url}")

        raw_responses[target_url] = {
            "status": main_response.status_code,
            "content_type": main_response.content_type,
            "size": main_response.body_size_bytes,
            "headers": main_response.headers,
            "body": main_response.body,  # Store body for vulnerability analysis
        }

        # Step 2: Technology fingerprinting
        tech_stack = self.http.detect_tech_stack(main_response)
        waf = self.http.check_waf(main_response)
        if waf:
            tech_stack.append(f"WAF:{waf}")
        logger.info(f"  Tech stack: {tech_stack}")

        # Step 3: WAF detection
        waf_detected = self.http.check_waf(main_response)
        if waf_detected:
            logger.info(f"  WAF detected: {waf_detected}")
            tech_stack.append(f"WAF:{waf_detected}")

        # Step 4: Extract links, forms, endpoints from main page
        if main_response.is_html:
            # Forms
            extracted_forms = self.http.extract_forms(main_response.body, target_url)
            forms.extend(extracted_forms)
            logger.info(f"  Found {len(extracted_forms)} forms on main page")

            # Links
            links = self.http.extract_links(main_response.body, target_url)
            logger.info(f"  Found {len(links)} links on main page")

            # Endpoint discovery from links
            for link in links:
                ep_info = self._link_to_endpoint(link, target_url)
                if ep_info:
                    endpoints.append(ep_info)
        else:
            logger.info(f"  Main page is not HTML ({main_response.content_type}), "
                       f"skipping link extraction")

        # Step 5: Robots.txt and Sitemap
        robots_url = urljoin(target_url, "/robots.txt")
        robots_resp = self.http.get(robots_url)
        if robots_resp.status_code == 200:
            logger.info("  Found robots.txt")
            raw_responses[robots_url] = {"status": 200}
            # Parse for sitemap/disallow paths
            sitemap_urls = self._parse_robots(robots_resp.body, target_url)
            for sm_url in sitemap_urls:
                ep = self._link_to_endpoint(sm_url, target_url)
                if ep:
                    endpoints.append(ep)

        sitemap_url = urljoin(target_url, "/sitemap.xml")
        sitemap_resp = self.http.get(sitemap_url)
        if sitemap_resp.status_code == 200:
            logger.info("  Found sitemap.xml")
            raw_responses[sitemap_url] = {"status": 200}
            sitemap_endpoints = self._parse_sitemap(sitemap_resp.body, target_url)
            for url in sitemap_endpoints:
                ep = self._link_to_endpoint(url, target_url)
                if ep:
                    endpoints.append(ep)

        # Step 6: Directory scan (limited)
        if self.max_endpoints > len(endpoints):
            discovered = self.http.directory_scan(target_url)
            for url in discovered:
                ep = self._link_to_endpoint(url, target_url)
                if ep:
                    endpoints.append(ep)

        # Step 7: Check for API documentation
        api_docs = self._discover_api_docs(target_url)
        for doc_url in api_docs:
            ep = self._link_to_endpoint(doc_url, target_url)
            if ep:
                endpoints.append(ep)

        # Step 8: Explore discovered endpoints (breadth-first, limited depth)
        explored_endpoints = self._explore_endpoints(
            endpoints, target_url, raw_responses, depth=self.max_depth
        )
        for ep in explored_endpoints:
            if ep not in endpoints:
                endpoints.append(ep)

        # Step 9: Collect all unique parameters
        all_params: Set[str] = set()
        for ep in endpoints:
            if isinstance(ep, dict) and "params" in ep:
                for p in ep["params"]:
                    all_params.add(p)

        # Step 10: Source code collection (if applicable)
        source_path = parsed_task.get("source_path", "")
        if source_path and Path(source_path).exists():
            logger.info(f"  Collecting source files from: {source_path}")
            files = self._collect_source_files(source_path)

        # Step 11: Skip black-box probing when source code is available
        # (source code analysis is more reliable and doesn't risk hanging the target)

        # Build inventory
        inventory = {
            "endpoints": endpoints,
            "files": files,
            "forms": forms,
            "tech_stack": tech_stack,
            "params": sorted(all_params),
            "raw_responses": raw_responses,
            "env": {
                "tech_stack": tech_stack,
                "waf": waf_detected,
                "server": main_response.headers.get("Server", "unknown"),
                "powered_by": main_response.headers.get("X-Powered-By", ""),
                "content_type": main_response.content_type,
                "status": main_response.status_code,
            },
            "stats": {
                "total_endpoints": len(endpoints),
                "total_forms": len(forms),
                "total_params": len(all_params),
                "total_files": len(files),
                "http_requests_made": self.http.total_requests,
            },
        }

        logger.info(f"Collection complete: {inventory['stats']}")
        return inventory

    # --- Exploration ---

    def _explore_endpoints(
        self,
        seed_endpoints: List[Dict],
        base_url: str,
        raw_responses: Dict[str, Any],
        depth: int = 2,
    ) -> List[Dict]:
        """
        Explore discovered endpoints with limited depth BFS.

        For each endpoint URL that returns HTML, extract more links and forms,
        and store the response body for vulnerability analysis.
        """
        if depth <= 0:
            return []

        base_domain = urlparse(base_url).netloc
        explored: List[Dict] = []
        urls_to_visit: Set[str] = set()

        for ep in seed_endpoints[:50]:  # Limit seed exploration
            if ep is None:
                continue
            url = ep.get("url", "")
            # Visit seed endpoints even if they were linked from main page
            if url:
                urls_to_visit.add(url)

        for url in list(urls_to_visit)[:30]:  # Limit total exploration
            # NOTE: Don't skip visited URLs here — seed endpoints were
            # added to _visited during link extraction, but we still
            # need to visit them to extract forms and probe for vulns
            self._visited.add(url)

            resp = self.http.get(url)
            if resp.status_code == 0 or not resp.is_html:
                continue

            # Store page response for vulnerability analysis
            raw_responses[url] = {
                "status": resp.status_code,
                "content_type": resp.content_type,
                "headers": resp.headers,
                "body": resp.body,
                "elapsed_seconds": resp.elapsed_seconds,
            }

            # Extract links
            links = self.http.extract_links(resp.body, url)
            for link in links:
                parsed = urlparse(link)
                if parsed.netloc == base_domain or not parsed.netloc:
                    ep = self._link_to_endpoint(link, base_url)
                    if ep and link not in self._visited:
                        explored.append(ep)
                        self._visited.add(link)

            # Extract forms (but don't probe — that happens during verification)
            forms = self.http.extract_forms(resp.body, url)
            for form in forms:
                ep = {
                    "url": form["action"],
                    "method": form["method"],
                    "params": [inp["name"] for inp in form.get("inputs", []) if inp["name"]],
                    "type": "form",
                    "linked_from": url,
                }
                explored.append(ep)

            # Extract params from URL
            params = self.http.extract_params(url)
            if params:
                if not any(e.get("url") == url for e in explored):
                    explored.append({
                        "url": url,
                        "method": "GET",
                        "params": params,
                        "type": "endpoint",
                    })

        return explored

    # --- API documentation discovery ---

    def _discover_api_docs(self, base_url: str) -> List[str]:
        """Discover API documentation endpoints."""
        api_paths = [
            "/swagger.json", "/openapi.json", "/api-docs",
            "/swagger/v1/swagger.json", "/v1/openapi.json",
            "/api/swagger.json", "/api/v1/openapi.json",
            "/docs/api", "/api/docs", "/graphql",
            "/.well-known/openapi.json", "/api-spec.json",
        ]

        found = []
        for path in api_paths:
            url = urljoin(base_url, path)
            resp = self.http.head(url)
            if resp.status_code not in (404, 0):
                found.append(url)
                logger.info(f"  API doc found: {url} ({resp.status_code})")

        return found

    # --- Source code collection ---

    def _collect_source_files(self, path: str) -> List[Dict[str, Any]]:
        """
        Collect source code files from a local directory.

        Args:
            path: Directory path containing source code

        Returns:
            List of file info dicts with path, language, line_count, content preview
        """
        files = []
        source_dir = Path(path)

        if not source_dir.is_dir():
            logger.warning(f"Source path is not a directory: {path}")
            return files

        # Directories to skip
        skip_dirs = {
            "node_modules", "vendor", "__pycache__", ".git",
            "dist", "build", ".next", "target", "bin", "obj",
            ".idea", ".vscode", ".vs",
            "migrations", "venv", ".venv", "env", ".env",
            "test", "tests", "__tests__", "spec",
        }

        # Extensions to collect
        code_extensions = {
            ".py", ".php", ".java", ".js", ".ts", ".tsx", ".jsx",
            ".go", ".rb", ".cs", ".swift", ".kt", ".c", ".cpp",
            ".html", ".htm", ".jsp", ".asp", ".aspx",
            ".yaml", ".yml", ".json", ".xml",
        }

        for file_path in source_dir.rglob("*"):
            # Skip directories
            if any(part in skip_dirs for part in file_path.parts):
                continue

            # Only collect code files
            if file_path.suffix.lower() not in code_extensions:
                continue

            # Skip large files
            try:
                size = file_path.stat().st_size
                if size > 1024 * 1024:  # Skip files > 1MB
                    continue
            except OSError:
                continue

            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
            except Exception:
                continue

            rel_path = str(file_path.relative_to(source_dir))
            full_content = "".join(lines)
            files.append({
                "path": rel_path,
                "absolute_path": str(file_path),
                "language": self._detect_language(file_path.suffix),
                "line_count": len(lines),
                "content": full_content,             # Full content for analysis
                "preview": full_content[:3000],       # First 3000 chars for LLM
            })

        logger.info(f"Collected {len(files)} source files from {path}")
        return files

    # --- Payload probing ---

    def _probe_endpoints(
        self,
        endpoints: List[Dict],
        base_url: str,
        raw_responses: Dict[str, Any],
    ) -> None:
        """
        Send security test payloads to discovered endpoints.

        This is the black-box testing step: for each endpoint with parameters,
        send common vulnerability probes and record responses for the analyzer.
        """
        # Test payloads for each vulnerability type
        test_payloads = {
            "sql_injection": [
                ("'", "sqli_single_quote"),
                ('"', "sqli_double_quote"),
                ("' OR '1'='1", "sqli_tautology"),
                ("' AND 1=1-- ", "sqli_always_true"),
            ],
            "xss": [
                ("<script>alert(1)</script>", "xss_script_tag"),
                ("<img src=x onerror=alert(1)>", "xss_img_onerror"),
                ('"><script>alert(1)</script>', "xss_attr_break"),
            ],
            "path_traversal": [
                ("../../../etc/hostname", "traversal_linux"),
                ("..%2F..%2F..%2Fetc%2Fhostname", "traversal_encoded"),
            ],
            "command_injection": [
                ("; sleep 3 #", "cmd_sleep"),
                ("| ping -c 3 127.0.0.1", "cmd_ping"),
            ],
            "ssrf": [
                ("http://127.0.0.1:80/", "ssrf_localhost"),
                ("http://169.254.169.254/latest/meta-data/", "ssrf_aws_metadata"),
            ],
        }

        probed = 0
        for ep in endpoints[:30]:  # Limit probing to avoid excessive requests
            if ep is None:
                continue
            url = ep.get("url", "")
            params = ep.get("params", [])
            method = ep.get("method", "GET")

            if not url or not params:
                continue

            for param in params[:3]:  # Test first 3 params per endpoint
                # Try SQL injection payloads
                for payload, ptype in test_payloads.get("sql_injection", [])[:2]:
                    probe_url = f"{url}?{param}={payload}" if "?" not in url else f"{url}&{param}={payload}"
                    try:
                        resp = self.http.get(probe_url)
                        if resp.status_code > 0:
                            raw_responses[probe_url] = {
                                "status": resp.status_code,
                                "content_type": resp.content_type,
                                "headers": resp.headers,
                                "body": resp.body,
                                "elapsed_seconds": resp.elapsed_seconds,
                            }
                            probed += 1
                    except Exception:
                        pass

                # Try XSS payloads
                for payload, ptype in test_payloads.get("xss", [])[:1]:
                    probe_url = f"{url}?{param}={payload}" if "?" not in url else f"{url}&{param}={payload}"
                    try:
                        resp = self.http.get(probe_url)
                        if resp.status_code > 0:
                            raw_responses[probe_url] = {
                                "status": resp.status_code,
                                "content_type": resp.content_type,
                                "headers": resp.headers,
                                "body": resp.body,
                                "elapsed_seconds": resp.elapsed_seconds,
                            }
                            probed += 1
                    except Exception:
                        pass

        logger.info(f"    Probed {probed} endpoint+payload combinations")

    # --- Helper methods ---

    def _link_to_endpoint(self, url: str, base_url: str) -> Optional[Dict]:
        """Convert a URL to an endpoint info dict."""
        if not url or url in self._visited:
            return None

        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            return None

        self._visited.add(url)
        params = self.http.extract_params(url)

        return {
            "url": url,
            "method": "GET",
            "params": params,
            "type": "link",
            "linked_from": base_url,
        }

    def _parse_robots(self, body: str, base_url: str) -> List[str]:
        """Parse robots.txt for sitemap URLs and interesting disallowed paths."""
        urls = []
        for line in body.split("\n"):
            line = line.strip().lower()
            if line.startswith("sitemap:"):
                sm_url = line.split(":", 1)[1].strip()
                urls.append(sm_url)
            elif line.startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and not path.startswith("#"):
                    # Disallowed paths are often interesting
                    full_url = urljoin(base_url, path)
                    urls.append(full_url)
        return urls

    def _parse_sitemap(self, body: str, base_url: str) -> List[str]:
        """Parse sitemap.xml for URLs."""
        urls = []
        # Simple regex extraction of <loc> tags
        import re
        for match in re.finditer(r'<loc>(.*?)</loc>', body, re.IGNORECASE):
            url = match.group(1).strip()
            if url:
                urls.append(url)
        return urls

    def _detect_language(self, ext: str) -> str:
        """Detect programming language from file extension."""
        lang_map = {
            ".py": "python", ".php": "php", ".java": "java",
            ".js": "javascript", ".ts": "typescript", ".tsx": "typescript",
            ".jsx": "javascript", ".go": "go", ".rb": "ruby",
            ".cs": "csharp", ".swift": "swift", ".kt": "kotlin",
            ".c": "c", ".cpp": "cpp", ".html": "html", ".htm": "html",
            ".jsp": "java", ".asp": "asp", ".aspx": "aspnet",
        }
        return lang_map.get(ext.lower(), "unknown")

    def _empty_inventory(self, error: str = "") -> Dict[str, Any]:
        """Return an empty inventory structure."""
        return {
            "endpoints": [],
            "files": [],
            "forms": [],
            "tech_stack": [],
            "params": [],
            "raw_responses": {},
            "env": {},
            "stats": {"error": error} if error else {},
        }
