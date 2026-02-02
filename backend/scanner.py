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
        
        log(f"Starting {scan_mode.upper()} scan for: {target}")

        # --- PHASE 1: NMAP ---
        scans[scan_id]["progress"] = 10
        scans[scan_id]["current_stage"] = "Phase 1/4: Port Scanning (Nmap)"
        
        # Sanitize target for Nmap (expects hostname/IP, not URL)
        nmap_target = target
        if "://" in nmap_target:
            nmap_target = nmap_target.split("://")[1]
        if nmap_target.endswith("/"):
            nmap_target = nmap_target[:-1]
            
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
        
        nuclei_count = 0
        for line in nuclei_output.splitlines():
            try:
                finding = json.loads(line)
                nuclei_count += 1
                
                # Map valid severities
                severity = finding.get("info", {}).get("severity", "info")
                name = finding.get("info", {}).get("name")
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
                
        log(f"Nuclei finished. Found {nuclei_count} issues.")

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
        else:
            log("Skipping Wapiti (Light Mode)")

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
        if scan_id and scans:
           scans[scan_id]["logs"].append(f"[ERROR] {err_msg}")
