import time
import subprocess
import json
import os
import re
import uuid

# Ensure tools are in path or define absolute paths if needed
NMAP_PATH = "nmap"
NUCLEI_PATH = "nuclei"
HTTPX_PATH = "httpx"


def run_command(command, scan_id=None, scans=None, stream_handler=None):
    """Runs a shell command and streams output line-by-line."""
    full_stdout = []
    try:
        if scan_id and scans:
             scans[scan_id]["logs"].append(f"$ {command}")
             print(f"[{scan_id}] EXEC: {command}")
             
             # check stop signal
             if scans[scan_id].get("status") == "STOPPED":
                 return ""

        # Merging stderr into stdout to prevent deadlock and simplify streaming
        process = subprocess.Popen(
            command, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Track process if scan_id provided
        if scan_id and scans:
            scans[scan_id]["_process"] = process

        
        # Read stdout line by line
        while True:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            
            if line:
                stripped_line = line.strip()
                full_stdout.append(stripped_line)
                
                # Stream to logs
                if scan_id and scans:
                    if stream_handler:
                        stream_handler(stripped_line)
                    else:
                        # Default logging (truncate if too long, but show activity)
                        log_line = stripped_line
                        if len(log_line) > 200: 
                            log_line = log_line[:200] + "..."
                        scans[scan_id]["logs"].append(f"[OUT] {log_line}")

        return "\n".join(full_stdout)
    except Exception as e:
        err_msg = f"Error running command: {e}"
        print(err_msg)
        if scan_id and scans:
            scans[scan_id]["logs"].append(f"[ERROR] {err_msg}")
        return ""

def run_scan(scan_id: str, target: str, scans: dict, scan_mode: str = "light"):
    """Orchestrates the scanning process."""
    
    # Initialize Logs
    scans[scan_id]["logs"] = []
    
    def log(msg):
        timestamp = time.strftime("%H:%M:%S")
        entry = f"[{timestamp}] {msg}"
        print(entry)
        scans[scan_id]["logs"].append(entry)
        # Keep log size manageable
        if len(scans[scan_id]["logs"]) > 1000:
            scans[scan_id]["logs"] = scans[scan_id]["logs"][-1000:]

    try:
        scans[scan_id]["status"] = "RUNNING"
        scans[scan_id]["progress"] = 5
        scans[scan_id]["findings"] = []
        scans[scan_id]["technologies"] = [] # Track detected technologies
        scans[scan_id]["target_url"] = target # Store target for follow-up scans
        
        log(f"Starting {scan_mode.upper()} scan for: {target}")

        # Sanitize target for Nmap/Subfinder (expects hostname/IP, not URL)
        nmap_target = target
        if "://" in nmap_target:
            nmap_target = nmap_target.split("://")[1]
        if nmap_target.endswith("/"):
            nmap_target = nmap_target[:-1]

        # --- BRANCH: ENUMERATION MODE ---
        if scan_mode == "enumeration":
             # --- ENUMERATION MODE (RECON ONLY) ---
             scans[scan_id]["progress"] = 10
             scans[scan_id]["current_stage"] = "Phase 1/2: Subdomain Discovery (Subfinder)"
             log("Starting Enumeration Scan (Recon Mode)...")
             
             # 1. Subfinder
             log(f"Running Subfinder on {nmap_target}...")
             subs_file = f"/tmp/subs_{scan_id}.txt"
             SUBFINDER_PATH = os.path.expanduser("~/go/bin/subfinder")
             sub_cmd = f"{SUBFINDER_PATH} -d {nmap_target} -o {subs_file} -silent"
             run_command(sub_cmd, scan_id, scans)
             
             subs = []
             if os.path.exists(subs_file):
                 with open(subs_file, 'r') as f:
                     subs = [line.strip() for line in f.readlines() if line.strip()]
             
             log(f"Subfinder found {len(subs)} subdomains.")
             for sub in subs[:20]: # Log first 20
                 scans[scan_id]["findings"].append({
                    "tool": "subfinder",
                    "name": "Subdomain Discovered",
                    "severity": "info",
                    "description": f"Found subdomain: {sub}",
                    "id": f"sub-{sub}"
                 })
                 
             # 2. GAU (Get All Urls)
             scans[scan_id]["progress"] = 50
             scans[scan_id]["current_stage"] = "Phase 2/2: URL Discovery (Gau) & UUID Hunt"
             log("Running Gau (URL Extraction)...")
             gau_file = f"/tmp/gau_{scan_id}.txt"
             GAU_PATH = os.path.expanduser("~/go/bin/gau")
             
             # Gau on target + subs
             # To save time, maybe just target? User asked for gau.
             # Let's run gau on domain.
             gau_cmd = f"echo {nmap_target} | {GAU_PATH} --subs --o {gau_file}"
             run_command(gau_cmd, scan_id, scans)
             
             # 3. UUID Detection (Grep)
             log("Analyzing URLs for UUIDs...")
             uuid_pattern = r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
             
             uuid_count = 0
             if os.path.exists(gau_file):
                 with open(gau_file, 'r') as f:
                     for line in f:
                         line = line.strip()
                         if not line: continue
                         
                         # Check for UUIDs
                         found_uuids = re.findall(uuid_pattern, line)
                         for found in found_uuids:
                             uuid_count += 1
                             scans[scan_id]["findings"].append({
                                 "tool": "grep-uuid",
                                 "name": "UUID Discovered in URL",
                                 "severity": "info",
                                 "description": f"Found UUID {found} in URL",
                                 "evidence": line,
                                 "id": f"uuid-{found}-{uuid_count}"
                             })
                             if uuid_count <= 10:
                                 log(f"UUID Found: {found}")
                                 
             log(f"Enumeration finished. Discovered {uuid_count} UUIDs in public URLs.")
             
             # Cleanup
             if os.path.exists(subs_file): os.remove(subs_file)
             if os.path.exists(gau_file): os.remove(gau_file)
        
        # --- BRANCH: STANDARD MODE (LIGHT/DEEP) ---
        else:
            log(f"Starting Standard {scan_mode.upper()} Scan...")
            # --- PHASE 1: NMAP ---
            scans[scan_id]["progress"] = 10
            scans[scan_id]["current_stage"] = "Phase 1/4: Port Scanning (Nmap)"
            
            log(f"Starting Nmap scan on {nmap_target}")
            
            # -F: Fast mode (top 100 ports)
            # -T4: Faster timing
            # --open: Only show open ports
            nmap_cmd = f"{NMAP_PATH} -F -T4 --open {nmap_target}"
            nmap_output = run_command(nmap_cmd, scan_id, scans)
            
            # Parse Nmap output for Ports
            # 80/tcp open http
            ports = []
            for line in nmap_output.splitlines():
                if "/tcp" in line and "open" in line:
                    parts = line.split("/")
                    port = parts[0].strip()
                    ports.append(port)
            
            log(f"Nmap discovered {len(ports)} open ports: {', '.join(ports)}")
            
            if not ports:
                log("Nmap found no open ports. Checking if target is a live URL...")
                # Fallback: If no ports found but user gave a URL, proceed to Httpx phase
                if not (target.startswith("http://") or target.startswith("https://")):
                     log("No open ports and not a URL. Aborting.")
                     scans[scan_id]["status"] = "COMPLETED"
                     scans[scan_id]["progress"] = 100
                     return

            formatted_ports = []
            for port in ports:
                # Use original nmap_target for formatting standard ports
                formatted_ports.append(f"{nmap_target}:{port}")


            # --- PHASE 2: HTTPX ---
            scans[scan_id]["progress"] = 30
            scans[scan_id]["current_stage"] = "Phase 2/4: Service Discovery (Httpx)"
            log(f"Starting Httpx service discovery on {len(formatted_ports)} targets")
            
            targets_file = f"/tmp/targets_{scan_id}.txt"
            with open(targets_file, "w") as f:
                f.write("\n".join(formatted_ports))
                if not formatted_ports:
                    f.write(f"\n{target}")

            httpx_cmd = f"{HTTPX_PATH} -l {targets_file} -silent -json"
            
            def httpx_handler(line):
                try:
                    if not line.strip(): return
                    data = json.loads(line)
                    url = data.get("url")
                    if url:
                       log(f"Httpx found live service: {url}")
                except:
                    pass

            httpx_output = run_command(httpx_cmd, scan_id, scans, stream_handler=httpx_handler)
            
            live_urls = []
            try:
                for line in httpx_output.splitlines():
                    if not line.strip(): continue
                    try:
                        data = json.loads(line)
                        url = data.get("url")
                        if url:
                            live_urls.append(url)
                            scans[scan_id]["findings"].append({
                                "tool": "httpx",
                                "name": "Web Service Detected",
                                "severity": "info",
                                "description": f"Live web service found at {url} ({data.get('title', 'No Title')})",
                                "id": f"httpx-{url}"
                            })
                    except:
                        pass
            except Exception as e:
                log(f"Error parsing httpx output: {e}")

            # clean up temp file
            if os.path.exists(targets_file):
                os.remove(targets_file)

            if not live_urls:
                log("No live web services found by Httpx. Falling back to default HTTP/HTTPS probes.")
                live_urls = [target if target.startswith("http") else f"http://{target}", target if target.startswith("http") else f"https://{target}"]
            else:
                log(f"Httpx found {len(live_urls)} live web services")

            # Create temp urls file for all nuclei phases
            urls_file = f"/tmp/urls_{scan_id}.txt"
            with open(urls_file, "w") as f:
                f.write("\n".join(live_urls))

            # --- PHASE 3: CRAWLING (KATANA) ---
            scans[scan_id]["progress"] = 50
            scans[scan_id]["current_stage"] = "Phase 3/4: Deep Crawling (Katana) & Sensitive Data Check"
            log(f"Starting Katana crawler on {len(live_urls)} URLs")

            KATANA_PATH = os.path.expanduser("~/go/bin/katana")
            katana_cmd = f"{KATANA_PATH} -list {urls_file} -d 2 -jc -silent -j" 
            
            katana_count = 0
            def katana_handler(line):
                nonlocal katana_count
                katana_count += 1
                if katana_count % 5 == 0:
                     log(f"Katana crawled {katana_count} URLs...")

            katana_stdout = run_command(katana_cmd, scan_id, scans, stream_handler=katana_handler)
            
            crawled_urls = set(live_urls) # Start with roots
            
            # Simple Sensitive Keywords (Case Insensitive)
            SENSITIVE_KEYWORDS = ["API_KEY", "apikey", "secret", "password", "auth_token", "access_token", "aws_access_key_id"]
            
            try:
                for line in katana_stdout.splitlines():
                    try:
                        data = json.loads(line)
                        
                        # 1. Harvest URL
                        k_url = data.get("request", {}).get("endpoint")
                        if k_url:
                            crawled_urls.add(k_url)
                        
                        # 2. Sensitive Data Check (Grep on Response Body)
                        body = data.get("response", {}).get("body", "")
                        if body:
                            for keyword in SENSITIVE_KEYWORDS:
                                if keyword.lower() in body.lower():
                                    idx = body.lower().find(keyword.lower())
                                    start = max(0, idx - 50)
                                    end = min(len(body), idx + 50)
                                    snippet = body[start:end].replace("\n", " ")
                                    
                                    unique_id = f"sensitive-{k_url}-{keyword}"
                                    if not any(f["id"] == unique_id for f in scans[scan_id]["findings"]):
                                        issue = {
                                            "id": unique_id,
                                            "tool": "katana",
                                            "name": "Potential Sensitive Data Found",
                                            "severity": "high",
                                            "description": f"Found keyword '{keyword}' in {k_url}",
                                            "evidence": f"...{snippet}...",
                                            "details": "Katana Crawl Response Analysis"
                                        }
                                        scans[scan_id]["findings"].append(issue)
                                        log(f"SENSITIVE DATA FOUND: {keyword} at {k_url}")
                    except:
                        pass
            except Exception as e:
                log(f"Error parsing katana output: {e}")
            
            scans[scan_id]["findings"].append({
                "tool": "katana",
                "name": "Crawled Endpoints",
                "severity": "info",
                "description": f"Discovered {len(crawled_urls)} unique endpoints (JS, API, etc.)",
                "details": f"Total URLs to scan: {len(crawled_urls)}" 
            })
            
            log(f"Katana finished. Total unique URLs discovered: {len(crawled_urls)}")

            # Update URLs file with ALL findings for Nuclei
            with open(urls_file, "w") as f:
                f.write("\n".join(crawled_urls))

            # --- PHASE 4: ADVANCED NUCLEI (Vulnerability Scan) ---
            scans[scan_id]["progress"] = 70
            scans[scan_id]["current_stage"] = "Phase 4/4: Vuln Scanning (Nuclei - Expanded)"
            
            log(f"Starting Nuclei vulnerability scan on {len(crawled_urls)} URLs. This may take a while.")
            
            # Extended Tags based on user request + Defaults
            nuclei_cmd = f"{NUCLEI_PATH} -l {urls_file} -tags tech,ssl,misconfig,sqli,xss,rce,lfi,exposure,token,auth -severity info,low,medium,high,critical -j -include-rr -silent"
            
            nuclei_findings_count = 0
            def nuclei_handler(line):
                nonlocal nuclei_findings_count
                try:
                    finding = json.loads(line)
                    name = finding.get("info", {}).get("name", "Unknown Issue")
                    sev = finding.get("info", {}).get("severity", "info")
                    if sev not in ["info", "unknown"]:
                        log(f"!!! NUCLEI FINDING: [{sev.upper()}] {name}")
                    else:
                        if nuclei_findings_count % 10 == 0:
                             log(f"Nuclei finding: {name}")
                    nuclei_findings_count += 1
                except:
                    if line.strip():
                        log(f"Nuclei: {line.strip()[:100]}")

            nuclei_output = run_command(nuclei_cmd, scan_id, scans, stream_handler=nuclei_handler)
            
            # "Smart Filter" patterns for Info severity to reduce noise
            # We only filter these if the severity is 'info' or 'unknown'
            NOISY_INFO_KEYWORDS = [
                "ssl certificate", "ssl issuer", "tls", "cipher", "mismatched header", 
                "dns", "cname", "txt record", "missing header", "cookie", "csp", "x-powered-by"
            ]

            nuclei_count = 0
            for line in nuclei_output.splitlines():
                try:
                    finding = json.loads(line)
                    
                    # Tech Detection Logic
                    name = finding.get("info", {}).get("name", "Unknown")
                    tags = finding.get("info", {}).get("tags", [])
                    
                    # Check for WordPress
                    if "wordpress" in name.lower() or "wordpress" in str(tags).lower():
                        if "wordpress" not in scans[scan_id]["technologies"]:
                            scans[scan_id]["technologies"].append("wordpress")
                            log("Technology Detected: WordPress")
                    
                    # --- SMART FILTER IMPLEMENTATION ---
                    # Drop "noisy" info items before adding them to our list
                    severity = finding.get("info", {}).get("severity", "info")
                    if severity.lower() in ["info", "unknown"]:
                        # Check if the name contains any noisy keyword
                        if any(keyword in name.lower() for keyword in NOISY_INFO_KEYWORDS):
                            # But KEEP vital info like "Technology", "WAF", "Panel", "Login"
                            # (The negative check ensures we don't accidentally drop good stuff if it overlaps)
                            # Actually 'tech' and 'detect' are usually good.
                            is_vital = any(good in name.lower() for good in ["detect", "technology", "login", "panel", "waf", "version"])
                            if not is_vital:
                                continue # Skip this finding
                    # -----------------------------------

                    nuclei_count += 1
                    
                    description = finding.get("info", {}).get("description", "") or f"Matched template {finding.get('template-id')}"
                    
                    # Additional Metadata
                    references = finding.get("info", {}).get("reference", [])
                    if isinstance(references, str):
                        references = [references]
                    
                    tags = finding.get("info", {}).get("tags", [])
                    curl_cmd = finding.get("curl-command", "")
                    ip = finding.get("ip", "")
                    port = finding.get("port", "")
                    matched_at = finding.get("matched-at", "")
                    
                    # Fallback for matched_at
                    if not matched_at and ip:
                        matched_at = ip
                        if port:
                           matched_at += f":{port}"
                    
                    # Matcher Name Details
                    matcher_name = finding.get("matcher-name", "")

                    # Formatting "Evidence"
                    evidence_str = ""
                    
                    # 1. Extracted Results (Important for content checks)
                    extracted = finding.get("extracted-results", [])
                    if extracted:
                         evidence_str += f"--- EXTRACTED RESULTS ---\n" + "\n".join(extracted) + "\n\n"

                    # 2. Curl
                    if curl_cmd:
                         evidence_str += f"--- CURL ---\n{curl_cmd}\n\n"
                    
                    # 3. HTTP Request/Response
                    if finding.get("request"):
                        evidence_str += f"--- REQUEST ---\n{finding.get('request')}\n\n"
                    if finding.get("response"):
                        evidence_str += f"--- RESPONSE ---\n{finding.get('response')}\n"
                    
                    # 4. Interaction (OAST)
                    if finding.get("interaction-evidence"):
                         evidence_str += f"--- INTERACTION ---\n{finding.get('interaction-evidence')}\n\n"

                    scans[scan_id]["findings"].append({
                        "id": finding.get("template-id") + str(time.time()), 
                        "template_id": finding.get("template-id"),
                        "name": name,
                        "severity": severity,
                        "description": description,
                        "references": references,
                        "tags": tags,
                        "tool": "nuclei",
                        "details": matcher_name,
                        "evidence": evidence_str,
                        "host": finding.get("host", ""),
                        "ip": ip,
                        "port": port,
                        "matched_at": matched_at
                    })
                except:
                    continue
                    
            log(f"Nuclei finished. Found {nuclei_count} relevant issues (filtered noise).")
            
            # --- PHASE 4.5: RETIRE.JS (OUTDATED JS) ---
            log(f"Starting Phase 4.5: Outdated JS Scanning (Retire.js)")
            run_retire_js_scan(scan_id, scans, urls_file)

            # --- PHASE 5: WAPITI (DEEP SCAN ONLY) ---
            if scan_mode == "deep":
                scans[scan_id]["progress"] = 85
                scans[scan_id]["current_stage"] = "Phase 5/5: Deep Application Fuzzing (Wapiti)"
                log("Starting Wapiti Deep Scan... (This might take a few minutes)")
                
                target_url = live_urls[0] if live_urls else (target if target.startswith("http") else f"https://{target}")
                
                wapiti_output_file = f"/tmp/wapiti_{scan_id}.json"
                
                # Using --max-scan-time to prevent hanging
                wapiti_cmd = f"wapiti -u {target_url} -f json -o {wapiti_output_file} --flush-session --max-scan-time 300" 
                
                run_command(wapiti_cmd, scan_id, scans)
                
                # Parse Wapiti JSON
                if os.path.exists(wapiti_output_file):
                    try:
                        with open(wapiti_output_file, 'r') as f:
                            wapiti_data = json.load(f)
                            
                        vulns = wapiti_data.get("vulnerabilities", {})
                        w_count = 0
                        
                        for category, findings_list in vulns.items():
                            for f in findings_list:
                                w_count += 1
                                # Map Level (assuming typical Wapiti output, could be string or int)
                                # Actually Wapiti JSON usually has level as Int 0-3
                                lvl = f.get("level", 0)
                                severity = "info"
                                if lvl == 1: severity = "low"
                                elif lvl == 2: severity = "medium"
                                elif lvl >= 3: severity = "high"
                                
                                desc = f.get("info", "") or f.get("description", "")
                                path = f.get("path", "")
                                http_request = f.get("http_request", "")
                                curl_cmd = f.get("curl_command", "")
                                
                                evidence = ""
                                if curl_cmd: evidence += f"--- CURL ---\n{curl_cmd}\n\n"
                                if http_request: evidence += f"--- REQUEST ---\n{http_request}\n\n"
                                
                                scans[scan_id]["findings"].append({
                                    "id": f"wapiti-{uuid.uuid4()}",
                                    "tool": "wapiti",
                                    "name": category, 
                                    "severity": severity,
                                    "description": desc,
                                    "matched_at": path,
                                    "evidence": evidence,
                                    "references": ["https://wapiti.sourceforge.io/"]
                                })
                        log(f"Wapiti finished. Found {w_count} issues.")
                    except Exception as e:
                        log(f"Error parsing Wapiti output: {e}")
                else:
                    log("Wapiti produced no output file.")
            
            # cleanup (Standard Scan)
            for tmp in [f"/tmp/targets_{scan_id}.txt", f"/tmp/urls_{scan_id}.txt", f"/tmp/wapiti_{scan_id}.json"]:
                if os.path.exists(tmp):
                    os.remove(tmp)

        # --- FINALIZE ---
        scans[scan_id]["progress"] = 100
        scans[scan_id]["status"] = "COMPLETED"
        scans[scan_id]["current_stage"] = "Scan Completed"
        log("Scan finished successfully.")

        # cleanup
        for tmp in [f"/tmp/targets_{scan_id}.txt", f"/tmp/urls_{scan_id}.txt", f"/tmp/wapiti_{scan_id}.json"]:
            if os.path.exists(tmp):
                os.remove(tmp)

    except Exception as e:
        err_msg = f"Critical Scan Error: {e}"
        print(err_msg)
        scans[scan_id]["status"] = "FAILED"
        scans[scan_id]["error"] = str(e)
        if scan_id and scans:
           scans[scan_id]["logs"].append(f"[ERROR] {err_msg}")

def run_retire_js_scan(scan_id: str, scans: dict, urls_file: str):
    """
    Runs Retire.js on the list of discovered URLs to identify outdated JS libraries and CVEs.
    """
    RETIRE_PATH = "retire" # Assumed in path after npm install -g
    
    if scan_id not in scans:
         return

    scans[scan_id]["current_stage"] = "Phase 4.5/5: Outdated JS Analysis (Retire.js)"
    log_func = lambda msg: scans[scan_id]["logs"].append(f"[{time.strftime('%H:%M:%S')}] {msg}")
    
    log_func("Starting Retire.js scan for outdated JavaScript libraries...")
    
    if not os.path.exists(urls_file):
        log_func("[WARN] No URLs file found for Retire.js scan.")
        return

    # Retire.js typically scans files or a live URL. 
    # To scan a list of URLs, we might need to iterate or check if it supports a list.
    # Retire.js CLI normally scans local files or a single URL.
    # We will iterate over the top URLs (or all) to avoid taking too long, or use a proxy mode?
    # Actually, scanning *every* URL might be slow. Let's pick unique domain roots + some subpaths.
    # For now, let's try to run it on the main detected URLs.
    
    # ISSUE: 'retire' CLI usually scans LOCAL files (source code).
    # To scan remote URLs, we can use '--js --jspath <url>' maybe?
    # Wait, 'retire.js' CLI usually works on a directory of code.
    # For REMOTE scanning, it suggests using the browser extension or proxy.
    # HOWEVER, we can use `nuclei` with specific templates for outdated JS, OR we can download JS files and scan them.
    # OR better: run `retire -c` (checking) but it needs local files usually.
    
    # ALTERNATIVE: Use `retire` against the downloaded JS contents?
    # Katana already crawled. Maybe we can fetch the JS files?
    
    # Let's verify if `retire` has a CLI URL mode. 
    # 'retire --url https://example.com' exists in some versions?
    # Checking docs... "retire.js" CLI is mostly for local files.
    # BUT, there is a `retire` chrome extension logic.
    
    # RE-EVALUATION: Since the user specifically asked for "outdated js" and "retire.js", 
    # and we are a scanner, simply downloading the JS files mentioned in `crawled_urls` 
    # and running retire on that folder is the best approach.
    
    log_func("Downloading unique JS files for analysis...")
    
    js_download_dir = f"/tmp/js_downloads_{scan_id}"
    if not os.path.exists(js_download_dir):
        os.makedirs(js_download_dir)

    # 1. Identify JS URLs from the crawled list
    js_urls = []
    try:
        with open(urls_file, 'r') as f:
            for line in f:
                url = line.strip()
                if ".js" in url or ".map" in url:
                   js_urls.append(url)
    except:
        pass
        
    log_func(f"Found {len(js_urls)} JavaScript references. Downloading...")
    
    # Download logic (simple wget/curl loop or python request)
    # Using wget for speed/simplicity
    count = 0
    for url in js_urls[:50]: # Limit to 50 JS files to prevent freezing
        try:
             safe_name = re.sub(r'[^a-zA-Z0-9]', '_', url) + ".js"
             subprocess.run(f"curl -s -o {js_download_dir}/{safe_name} {url}", shell=True, timeout=5)
             count += 1
        except:
             pass
             
    if count == 0:
        log_func("No JS files could be downloaded. Skipping Retire.js.")
        return

    # 2. Run Retire.js on the directory
    retire_output_file = f"/tmp/retire_{scan_id}.json"
    retire_cmd = f"{RETIRE_PATH} --path {js_download_dir} --outputformat json --outputpath {retire_output_file} --exitwith 0"
    
    run_command(retire_cmd, scan_id, scans)
    
    # 3. Parse Results
    if os.path.exists(retire_output_file):
        try:
            with open(retire_output_file, 'r') as f:
                data = json.load(f)
                
            # data is list of file objects
            parsed_count = 0
            for item in data:
                file_path = item.get("file", "unknown")
                results = item.get("results", [])
                
                for res in results:
                    component = res.get("component", "Unknown Lib")
                    version = res.get("version", "Unknown Ver")
                    vulns = res.get("vulnerabilities", [])
                    
                    cves = []
                    severity = "info" # default
                    
                    evidence_lines = []
                    
                    for vuln in vulns:
                        # Identifiers
                        identifiers = vuln.get("identifiers", {})
                        if "CVE" in identifiers:
                            cves.extend(identifiers["CVE"])
                        if "summary" in identifiers:
                            evidence_lines.append(f"Summary: {identifiers['summary']}")
                        
                        # Severity estimation (Retire doesn't always give severity string)
                        info = vuln.get("info", [])
                        evidence_lines.extend(info)
                        if info:
                            severity = "medium" 
                        if cves: 
                            severity = "high"
                            
                    unique_cves = list(set(cves))
                    cve_str = ", ".join(unique_cves) if unique_cves else "No CVE detected"
                    
                    desc = f"Outdated/Vulnerable Library: {component} {version}"
                    if unique_cves:
                        desc += f" (Affects: {cve_str})"
                        
                    evidence = "\n".join(evidence_lines)
                    if not evidence: evidence = "Retire.js detected known vulnerabilities."
                    
                    finding = {
                        "id": f"retire-{uuid.uuid4()}",
                        "tool": "retirejs",
                        "name": f"Outdated JS: {component}",
                        "severity": severity,
                        "description": desc,
                        "evidence": evidence,
                        "references": unique_cves,
                        "matched_at": file_path
                    }
                    scans[scan_id]["findings"].append(finding)
                    parsed_count += 1
                    
            log_func(f"Retire.js analysis complete. Identified {parsed_count} vulnerable libraries.")
            
        except Exception as e:
            log_func(f"Error parsing Retire.js output: {e}")
            
    # Cleanup
    try:
        import shutil
        shutil.rmtree(js_download_dir)
        if os.path.exists(retire_output_file):
            os.remove(retire_output_file)
    except:
        pass

def terminate_scan(scan_id: str, scans: dict):
    """Stop a running scan."""
    if scan_id in scans:
        scan = scans[scan_id]
        scan["status"] = "STOPPED"
        scan["logs"].append("[WARN] Scan Process Terminated by User.")
        
        # Kill the subprocess if alive
        proc = scan.get("_process")
        if proc:
            try:
                proc.terminate()
                proc.wait(timeout=1)
            except:
                try:
                    proc.kill()
                except:
                    pass
        return True
        return True
    return False

def run_wpprobe_scan(scan_id: str, scans: dict):
    """Execution of specialized WordPress scan using wpprobe."""
    WPPROBE_PATH = os.path.expanduser("~/go/bin/wpprobe")
    if scan_id not in scans:
         return
    
    # Needs a target URL. We can infer it from findings or original request.
    # But main.py doesn't store original target in scan object easily accessible here unless we explicitly stored it.
    # Fortunately, we can check if we have it in scans (assuming main.py passed it in run_scan). 
    # But this is a separate process. We need to pass target here or store it.
    # Let's assume we store target in scan object when starting scan.
    
    target = scans[scan_id].get("target_url") 
    # NOTE: We need to ensure target is stored in scan object in run_scan
    
    if not target:
        scans[scan_id]["logs"].append("[ERROR] Target URL not found for WP scan.")
        return

    scans[scan_id]["logs"].append(f"Starting Deep WordPress Scan with wpprobe on {target}...")
    scans[scan_id]["action_status"] = "running" # UI will poll this
    scans[scan_id]["action_message"] = "Enumerating plugins with wpprobe..."
    
    # wpprobe output to json?
    # CLI help says: -o output_file (json format supported?)
    # Let's try -o stdout and parse line by line if possible, or file.
    # Based on search: usually tools support json output.
    # We will use a temp file.
    
    output_file = f"/tmp/wpprobe_{scan_id}.json"
    # Corrected command based on 'wpprobe scan --help':
    # - subcommand: scan
    # - url: -u
    # - output: -o
    # - mode: -m (stealthy, bruteforce, hybrid). 'aggressive' was invalid. Using 'hybrid' for deep scan.
    # - threads: -t (instead of --workers)
    cmd = f"{WPPROBE_PATH} scan -u {target} -o {output_file} -m hybrid -t 25"
    
    run_command(cmd, scan_id, scans)
    
    # Parse Output
    if os.path.exists(output_file):
        try:
            with open(output_file, 'r') as f:
                # wpprobe might output a single JSON object or list
                # Assuming list or single obj
                data = json.load(f)
                
                # Normalize to list
                if isinstance(data, dict):
                    data = [data]
                
                findings_count = 0
                for item in data:
                    # Map wpprobe logic to our findings
                    # Structure depends on tool, but generic fallback:
                    name = item.get("name") or item.get("plugin") or "WordPress Issue"
                    version = item.get("version", "")
                    vulns = item.get("vulnerabilities", [])
                    
                    if vulns:
                         for v in vulns:
                             findings_count += 1
                             scans[scan_id]["findings"].append({
                                "id": f"wp-{uuid.uuid4()}",
                                "tool": "wpprobe",
                                "name": f"WP Plugin Vuln: {name}",
                                "severity": "high", # usually vulns are high
                                "description": v.get("title", "Detected Vulnerability"),
                                "evidence": f"Plugin: {name} v{version}\nRef: {v.get('references', '')}",
                                "references": v.get("references", []),
                                "matched_at": target
                             })
                    else:
                        # Just detected plugin
                        findings_count += 1
                        scans[scan_id]["findings"].append({
                            "id": f"wp-{uuid.uuid4()}",
                            "tool": "wpprobe",
                            "name": f"WP Plugin Detected: {name}",
                            "severity": "info",
                            "description": f"Found plugin {name} version {version}",
                            "matched_at": target
                         })

            scans[scan_id]["logs"].append(f"WPScan Finished. Found {findings_count} WordPress specific items.")
            scans[scan_id]["action_status"] = "completed" # Success state
            scans[scan_id]["action_result_count"] = findings_count

            
        except Exception as e:
             scans[scan_id]["logs"].append(f"[ERROR] Failed to parse wpprobe output: {e}")
             scans[scan_id]["action_status"] = "failed"
    else:
         scans[scan_id]["logs"].append("[WARN] wpprobe produced no output.")
         scans[scan_id]["action_status"] = "failed"
         
    # scans[scan_id]["action_status"] = "idle" # OLD: Reset status


