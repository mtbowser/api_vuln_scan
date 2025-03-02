"""
API Security Scanner - A tool to scan and analyze REST API endpoints for common security issues
"""

import argparse
import requests
import json
import concurrent.futures
from urllib.parse import urlparse, urljoin
import logging
from rich.console import Console
from rich.table import Table
from rich.progress import Progress

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='api_scanner.log'
)

console = Console()

class APISecurityScanner:
    """Scanner for detecting common API security issues"""
    
    def __init__(self, base_url, endpoints=None, headers=None, auth=None, threads=5):
        """Initialize the scanner with target API information"""
        self.base_url = base_url
        self.endpoints = endpoints or []
        self.headers = headers or {}
        self.auth = auth
        self.threads = threads
        self.results = {
            "missing_auth": [],
            "sensitive_data": [],
            "rate_limiting": [],
            "error_disclosure": [],
            "http_methods": []
        }
        
    def discover_endpoints(self, wordlist_file):
        """Discover API endpoints using a wordlist"""
        console.print("[bold blue]Discovering API endpoints...[/bold blue]")
        
        with open(wordlist_file, 'r') as f:
            wordlist = [line.strip() for line in f if line.strip()]
        
        discovered = []
        
        with Progress() as progress:
            task = progress.add_task("[green]Discovering endpoints...", total=len(wordlist))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for word in wordlist:
                    url = urljoin(self.base_url, word)
                    futures.append(executor.submit(self._check_endpoint, url))
                    
                for future in concurrent.futures.as_completed(futures):
                    progress.update(task, advance=1)
                    result = future.result()
                    if result:
                        discovered.append(result)
        
        self.endpoints.extend(discovered)
        console.print(f"[bold green]Discovered {len(discovered)} endpoints[/bold green]")
        return discovered
    
    def _check_endpoint(self, url):
        """Check if an endpoint exists"""
        try:
            response = requests.get(
                url, 
                headers=self.headers, 
                auth=self.auth, 
                timeout=5,
                allow_redirects=False
            )
            
            if 200 <= response.status_code < 404:
                return url
        except requests.RequestException:
            pass
        return None
    
    def scan_all(self):
        """Run all security checks on the API endpoints"""
        if not self.endpoints:
            console.print("[bold red]No endpoints to scan. Run discover_endpoints first or provide endpoints.[/bold red]")
            return {}
        
        console.print(f"[bold blue]Scanning {len(self.endpoints)} endpoints for security issues...[/bold blue]")
        
        with Progress() as progress:
            task = progress.add_task("[green]Scanning endpoints...", total=len(self.endpoints))
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                for endpoint in self.endpoints:
                    executor.submit(self._scan_endpoint, endpoint, progress, task)
        
        self._print_results()
        return self.results
    
    def _scan_endpoint(self, endpoint, progress, task):
        """Run all security checks on a single endpoint"""
        self._check_auth(endpoint)
        self._check_sensitive_data(endpoint)
        self._check_rate_limiting(endpoint)
        self._check_error_disclosure(endpoint)
        self._check_http_methods(endpoint)
        progress.update(task, advance=1)
    
    def _check_auth(self, endpoint):
        """Check if endpoint requires authentication"""
        try:
            # Try without auth headers
            no_auth_headers = {k: v for k, v in self.headers.items() 
                              if k.lower() not in ['authorization', 'auth', 'token', 'api-key']}
            
            response = requests.get(endpoint, headers=no_auth_headers, timeout=5)
            
            if response.status_code == 200:
                self.results["missing_auth"].append({
                    "endpoint": endpoint,
                    "status_code": response.status_code
                })
        except requests.RequestException:
            pass
    
    def _check_sensitive_data(self, endpoint):
        """Check for sensitive data in responses"""
        try:
            response = requests.get(
                endpoint, 
                headers=self.headers, 
                auth=self.auth, 
                timeout=5
            )
            
            if response.status_code == 200:
                # Define patterns for sensitive data
                sensitive_patterns = [
                    "password", "token", "secret", "key", "credential", 
                    "ssn", "social security", "credit card", "api_key"
                ]
                
                text = response.text.lower()
                found_patterns = [pattern for pattern in sensitive_patterns if pattern in text]
                
                if found_patterns:
                    self.results["sensitive_data"].append({
                        "endpoint": endpoint,
                        "patterns": found_patterns
                    })
        except requests.RequestException:
            pass
    
    def _check_rate_limiting(self, endpoint):
        """Check if rate limiting is implemented"""
        try:
            responses = []
            for _ in range(10):
                response = requests.get(
                    endpoint, 
                    headers=self.headers, 
                    auth=self.auth, 
                    timeout=5
                )
                responses.append(response)
                
            # Check for rate limiting headers
            rate_limit_headers = [
                'x-rate-limit',
                'x-ratelimit-limit',
                'x-ratelimit-remaining',
                'x-ratelimit-reset',
                'retry-after'
            ]
            
            has_rate_limit_headers = any(
                any(h.lower() in response.headers for h in rate_limit_headers)
                for response in responses
            )
            
            # Check if any response was rate limited
            any_rate_limited = any(
                response.status_code in [429, 403] for response in responses
            )
            
            if not (has_rate_limit_headers or any_rate_limited):
                self.results["rate_limiting"].append({
                    "endpoint": endpoint,
                    "issue": "No rate limiting detected"
                })
        except requests.RequestException:
            pass
    
    def _check_error_disclosure(self, endpoint):
        """Check for verbose error messages"""
        try:
            # Try to cause errors with invalid parameters
            params = {'invalid_param': "' OR 1=1; --"}
            response = requests.get(
                endpoint, 
                params=params,
                headers=self.headers, 
                auth=self.auth, 
                timeout=5
            )
            
            error_indicators = [
                "exception", "stack trace", "syntax error", 
                "at line", "traceback", "error:", 
                "sql syntax", "odbc driver", "postgresql"
            ]
            
            text = response.text.lower()
            found_indicators = [indicator for indicator in error_indicators if indicator in text]
            
            if found_indicators:
                self.results["error_disclosure"].append({
                    "endpoint": endpoint,
                    "indicators": found_indicators,
                    "status_code": response.status_code
                })
        except requests.RequestException:
            pass
    
    def _check_http_methods(self, endpoint):
        """Check which HTTP methods are supported"""
        try:
            methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
            allowed_methods = []
            
            for method in methods:
                try:
                    response = requests.request(
                        method, 
                        endpoint,
                        headers=self.headers,
                        auth=self.auth,
                        timeout=5
                    )
                    
                    # Consider 2xx, 3xx, and 4xx (except 404, 405) as supported
                    if response.status_code != 404 and response.status_code != 405:
                        allowed_methods.append(method)
                except:
                    continue
            
            # Check OPTIONS response
            try:
                options_response = requests.options(
                    endpoint,
                    headers=self.headers,
                    auth=self.auth,
                    timeout=5
                )
                
                if 'Allow' in options_response.headers:
                    options_allowed = options_response.headers['Allow'].split(', ')
                    allowed_methods = list(set(allowed_methods + options_allowed))
            except:
                pass
            
            self.results["http_methods"].append({
                "endpoint": endpoint,
                "allowed_methods": allowed_methods
            })
        except requests.RequestException:
            pass
    
    def _print_results(self):
        """Print scan results in a formatted table"""
        console.print("\n[bold green]Scan Results[/bold green]")
        
        # Print missing authentication issues
        if self.results["missing_auth"]:
            table = Table(title="Missing Authentication")
            table.add_column("Endpoint", style="cyan")
            table.add_column("Status Code", style="green")
            
            for issue in self.results["missing_auth"]:
                table.add_row(
                    issue["endpoint"],
                    str(issue["status_code"])
                )
            
            console.print(table)
        
        # Print sensitive data issues
        if self.results["sensitive_data"]:
            table = Table(title="Sensitive Data Exposure")
            table.add_column("Endpoint", style="cyan")
            table.add_column("Sensitive Patterns", style="red")
            
            for issue in self.results["sensitive_data"]:
                table.add_row(
                    issue["endpoint"],
                    ", ".join(issue["patterns"])
                )
            
            console.print(table)
        
        # Print rate limiting issues
        if self.results["rate_limiting"]:
            table = Table(title="Rate Limiting Issues")
            table.add_column("Endpoint", style="cyan")
            table.add_column("Issue", style="yellow")
            
            for issue in self.results["rate_limiting"]:
                table.add_row(
                    issue["endpoint"],
                    issue["issue"]
                )
            
            console.print(table)
        
        # Print error disclosure issues
        if self.results["error_disclosure"]:
            table = Table(title="Error Disclosure Issues")
            table.add_column("Endpoint", style="cyan")
            table.add_column("Error Indicators", style="red")
            table.add_column("Status Code", style="green")
            
            for issue in self.results["error_disclosure"]:
                table.add_row(
                    issue["endpoint"],
                    ", ".join(issue["indicators"]),
                    str(issue["status_code"])
                )
            
            console.print(table)
        
        # Print HTTP methods
        table = Table(title="HTTP Methods")
        table.add_column("Endpoint", style="cyan")
        table.add_column("Allowed Methods", style="green")
        
        for item in self.results["http_methods"]:
            table.add_row(
                item["endpoint"],
                ", ".join(item["allowed_methods"])
            )
        
        console.print(table)

def main():
    
    """Main function to run the API scanner"""
    parser = argparse.ArgumentParser(description="API Security Scanner")
    parser.add_argument("--url", required=True, help="Base URL of the API")
    parser.add_argument("--wordlist", help="Path to endpoint wordlist for discovery")
    parser.add_argument("--endpoints", help="Comma-separated list of endpoints to scan")
    parser.add_argument("--auth", help="Authorization header value")
    parser.add_argument("--threads", type=int, default=5, help="Number of threads to use")
    parser.add_argument("--output", help="Output results to JSON file")
    
    args = parser.parse_args()
    
    headers = {}
    if args.auth:
        headers["Authorization"] = args.auth
    
    endpoints = []
    if args.endpoints:
        endpoints = [urljoin(args.url, e.strip()) for e in args.endpoints.split(",")]
    
    scanner = APISecurityScanner(
        base_url=args.url,
        endpoints=endpoints,
        headers=headers,
        threads=args.threads
    )
    
    if args.wordlist:
        scanner.discover_endpoints(args.wordlist)
    
    results = scanner.scan_all()
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"[bold green]Results saved to {args.output}[/bold green]")

if __name__ == "__main__":
    console.print("[bold]=== API Security Scanner ===[/bold]")
    main()