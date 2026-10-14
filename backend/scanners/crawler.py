import re
import asyncio
from typing import List, Set, Dict, Any, Optional
from urllib.parse import urljoin, urlparse, parse_qs
import httpx


class DiscoveredEndpoint:
    def __init__(self, url: str, method: str = "GET", params: Optional[List[str]] = None, is_form: bool = False):
        self.url = url
        self.method = method.upper()
        self.params = params or []
        self.is_form = is_form

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "method": self.method,
            "params": self.params,
            "is_form": self.is_form,
        }


class WebCrawler:
    """
    Asynchronous, non-intrusive web spider that maps the application's attack surface:
    - Discovers internal endpoints, sub-pages, and routes.
    - Extracts parameterized URLs (e.g., ?id=, ?q=, ?search=) for injection testing.
    - Identifies HTML form actions, input field names, and methods.
    - Identifies client-side JavaScript assets for static secret analysis.
    """

    def __init__(self, max_depth: int = 2, max_pages: int = 15, timeout: float = 6.0):
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 SecOpsAudit/2.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    async def crawl(self, base_url: str) -> Dict[str, Any]:
        parsed_base = urlparse(base_url)
        base_domain = parsed_base.netloc

        visited: Set[str] = set()
        queue: List[tuple[str, int]] = [(base_url, 0)]

        endpoints: Dict[str, DiscoveredEndpoint] = {}
        js_assets: Set[str] = set()
        forms: List[Dict[str, Any]] = []

        async with httpx.AsyncClient(timeout=self.timeout, verify=False, follow_redirects=True) as client:
            while queue and len(visited) < self.max_pages:
                current_url, depth = queue.pop(0)

                # Normalize URL (strip fragment)
                clean_url = current_url.split("#")[0].rstrip("/")
                if not clean_url:
                    clean_url = current_url
                if clean_url in visited:
                    continue

                visited.add(clean_url)

                try:
                    resp = await client.get(current_url, headers=self.headers)
                    content_type = resp.headers.get("content-type", "").lower()
                    if "text/html" not in content_type and "application/xhtml" not in content_type:
                        continue

                    html = resp.text

                    # 1. Parse parameters from current URL
                    query_params = list(parse_qs(urlparse(current_url).query).keys())
                    endpoints[clean_url] = DiscoveredEndpoint(clean_url, "GET", query_params)

                    # 2. Extract <script src="...">
                    for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.IGNORECASE):
                        src = match.group(1).strip()
                        abs_src = urljoin(current_url, src)
                        if urlparse(abs_src).netloc == base_domain:
                            js_assets.add(abs_src)

                    # 3. Extract <form action="..." method="...">
                    form_pattern = re.compile(r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL)
                    for form_match in form_pattern.finditer(html):
                        attrs = form_match.group(1)
                        body = form_match.group(2)

                        action_m = re.search(r'action=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                        method_m = re.search(r'method=["\']([^"\']*)["\']', attrs, re.IGNORECASE)

                        action = action_m.group(1).strip() if action_m else ""
                        method = method_m.group(1).strip().upper() if method_m else "GET"
                        abs_action = urljoin(current_url, action) if action else current_url

                        # Extract input field names
                        input_names = re.findall(r'<input[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
                        textarea_names = re.findall(r'<textarea[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
                        select_names = re.findall(r'<select[^>]+name=["\']([^"\']+)["\']', body, re.IGNORECASE)
                        all_inputs = list(set(input_names + textarea_names + select_names))

                        forms.append({
                            "action": abs_action,
                            "method": method,
                            "inputs": all_inputs,
                            "source_page": current_url,
                        })

                        endpoints[abs_action] = DiscoveredEndpoint(abs_action, method, all_inputs, is_form=True)

                    # 4. Extract hyperlinks for deeper crawling
                    if depth < self.max_depth:
                        for match in re.finditer(r'<a[^>]+href=["\']([^"\'#]+)["\']', html, re.IGNORECASE):
                            href = match.group(1).strip()
                            if href.startswith("mailto:") or href.startswith("javascript:") or href.startswith("tel:"):
                                continue

                            abs_href = urljoin(current_url, href)
                            parsed_href = urlparse(abs_href)

                            # Only crawl same host
                            if parsed_href.netloc == base_domain:
                                if abs_href not in visited and abs_href not in [q[0] for q in queue]:
                                    queue.append((abs_href, depth + 1))

                except Exception:
                    continue

        return {
            "endpoints": [ep.to_dict() for ep in endpoints.values()],
            "js_assets": list(js_assets),
            "forms": forms,
            "total_pages_visited": len(visited),
        }
