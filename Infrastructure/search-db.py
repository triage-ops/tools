#!/usr/bin/env python3

import sqlite3
import os
import sys
import re
import requests

# === COLORS ===
C = {
    'G': '\033[92m',
    'Y': '\033[93m',
    'R': '\033[91m',
    'B': '\033[94m',
    'C': '\033[96m',
    'W': '\033[1m',
    'N': '\033[0m',
}

def log(msg, color='B'):
    print(f"{C.get(color, '')}{msg}{C['N']}")

# === DEPENDENCY CHECK ===
def check_dependencies():
    """Check for required Python modules"""
    log("[*] Checking dependencies...", "B")
    
    missing = []
    
    try:
        import sqlite3
    except:
        missing.append("sqlite3 (python3-sqlite)")
    
    try:
        import requests
    except:
        missing.append("requests (python3-requests)")
    
    if missing:
        log("[✗] MISSING DEPENDENCIES:", "R")
        for dep in missing:
            print(f"    {dep}")
        print(f"\n{C['Y']}Install with:{C['N']}")
        print(f"    {C['W']}pip3 install requests{C['N']}\n")
        return False
    
    log("[✓] All dependencies satisfied!\n", "G")
    return True

if not check_dependencies():
    sys.exit(1)

# === DATABASE PATH ===
DB_PATH = os.path.join(os.path.dirname(__file__), 'exploits.db')

# === CVE LOOKUP ===
def lookup_cve(cve_id):
    """Look up CVE to find EDB IDs"""
    log(f"[*] Looking up {cve_id}...", "C")
    
    try:
        url = f"https://cve.circl.lu/api/cve/{cve_id}"
        resp = requests.get(url, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            
            # Extract Exploit-DB references
            edb_ids = []
            if 'references' in data:
                for ref in data['references']:
                    if 'exploit-db.com' in ref:
                        if match := re.search(r'/exploits/(\d+)', ref):
                            edb_ids.append(int(match.group(1)))
            
            if edb_ids:
                log(f"[+] Found EDB IDs: {edb_ids}", "G")
                return edb_ids
            else:
                log(f"[!] No Exploit-DB entries found for {cve_id}", "Y")
        else:
            log(f"[!] CVE lookup failed (HTTP {resp.status_code})", "R")
    except Exception as e:
        log(f"[!] CVE lookup error: {e}", "R")
    
    return []

# === LETHALITY SCORING ===
def calculate_lethality(exploit):
    """Calculate exploit lethality score"""
    score = 0
    title = exploit['title'].lower()
    exp_type = exploit.get('type', '').lower()
    file_path = exploit.get('file', '')
    
    # Type weighting
    type_scores = {
        'remote': 50,
        'webapps': 40,
        'local': 30,
        'dos': 10,
    }
    score += type_scores.get(exp_type, 0)
    
    # Keyword weighting
    keywords = {
        'rce': 100,
        'remote code execution': 100,
        'buffer overflow': 80,
        'arbitrary code': 90,
        'command injection': 85,
        'sql injection': 70,
        'authentication bypass': 60,
        'privilege escalation': 75,
        'arbitrary file': 65,
        'denial of service': 15,
    }
    
    for keyword, points in keywords.items():
        if keyword in title:
            score += points
    
    # File extension bonus (indicates working PoC)
    ext_scores = {
        '.rb': 25,    # Metasploit
        '.py': 15,    # Python exploit
        '.c': 10,     # C exploit
        '.sh': 5,     # Shell script
    }
    
    for ext, points in ext_scores.items():
        if file_path.endswith(ext):
            score += points
    
    # CVSS score bonus
    if cvss := exploit.get('cvss_score'):
        try:
            score += float(cvss) * 10
        except:
            pass
    
    # Verified exploit bonus
    if exploit.get('verified'):
        score += 20
    
    return score

# === VERSION FILTERING ===
def version_matches(target_version, exploit_version):
    """Check if version matches exploit range"""
    if not target_version or not exploit_version:
        return True  # No filter
    
    # Simple version comparison
    try:
        # Handle ranges like "< 2.4.50"
        if '<' in exploit_version:
            max_ver = exploit_version.split('<')[1].strip()
            return target_version < max_ver
        elif '<=' in exploit_version:
            max_ver = exploit_version.split('<=')[1].strip()
            return target_version <= max_ver
        elif target_version in exploit_version:
            return True
    except:
        pass
    
    return False

# === SEARCH ===
def search_exploits(keyword=None, cve_id=None, version=None, verified_only=False):
    """Search exploit database"""
    if not os.path.exists(DB_PATH):
        log(f"[!] Database not found: {DB_PATH}", "R")
        log(f"    Run update_db.py first!", "Y")
        return []
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    results = []
    
    if cve_id:
        # CVE lookup
        edb_ids = lookup_cve(cve_id)
        if edb_ids:
            placeholders = ','.join('?' * len(edb_ids))
            cursor.execute(f"SELECT * FROM exploits WHERE edb_id IN ({placeholders})", edb_ids)
            results = cursor.fetchall()
    
    elif keyword:
        # Keyword search
        cursor.execute("SELECT * FROM exploits WHERE title LIKE ? OR description LIKE ?",
                      (f'%{keyword}%', f'%{keyword}%'))
        results = cursor.fetchall()
    
    conn.close()
    
    # Convert to dicts
    exploits = []
    for row in results:
        exploit = dict(row)
        
        # Version filtering
        if version and not version_matches(version, exploit.get('version', '')):
            continue
        
        # Verified-only filter
        if verified_only:
            file_path = exploit.get('file', '')
            if not file_path or not os.path.exists(file_path):
                continue
            exploit['verified'] = True
        
        # Calculate score
        exploit['lethality'] = calculate_lethality(exploit)
        exploits.append(exploit)
    
    # Sort by lethality
    exploits.sort(key=lambda x: x['lethality'], reverse=True)
    
    return exploits

# === DISPLAY ===
def display_exploits(exploits, limit=20):
    """Display exploit results"""
    if not exploits:
        log("[!] No exploits found", "Y")
        return
    
    log(f"\n[+] Found {len(exploits)} exploits (showing top {limit}):\n", "G")
    
    for i, exp in enumerate(exploits[:limit], 1):
        score = exp['lethality']
        edb_id = exp.get('edb_id', 'N/A')
        title = exp.get('title', 'Unknown')
        exp_type = exp.get('type', 'unknown')
        cvss = exp.get('cvss_score', 'N/A')
        
        # Color based on score
        if score >= 200:
            color = 'R'  # Critical
        elif score >= 100:
            color = 'Y'  # High
        else:
            color = 'C'  # Medium
        
        print(f"{C[color]}{i:2d}. [EDB-{edb_id}] {title[:80]}{C['N']}")
        print(f"    Type: {exp_type} | Lethality: {score} | CVSS: {cvss}")
        
        if file_path := exp.get('file'):
            print(f"    File: {file_path}")
        
        print()

# === MAIN ===
def main():
    log("\n--- Enhanced Exploit Database Search v2.0 ---\n", "W")
    
    if len(sys.argv) < 2:
        log("Usage: ./search_db.py <keyword|CVE-ID> [--version=X.X] [--verified]", "R")
        print("\nExamples:")
        print("  ./search_db.py apache")
        print("  ./search_db.py CVE-2021-44228")
        print("  ./search_db.py wordpress --version=5.8 --verified\n")
        sys.exit(1)
    
    query = sys.argv[1]
    version = None
    verified_only = False
    
    # Parse options
    for arg in sys.argv[2:]:
        if arg.startswith('--version='):
            version = arg.split('=')[1]
        elif arg == '--verified':
            verified_only = True
    
    # Determine query type
    if query.upper().startswith('CVE-'):
        exploits = search_exploits(cve_id=query.upper(), version=version, verified_only=verified_only)
    else:
        exploits = search_exploits(keyword=query, version=version, verified_only=verified_only)
    
    display_exploits(exploits)
    
    log("Search complete\n", "G")

if __name__ == "__main__":
    main()
