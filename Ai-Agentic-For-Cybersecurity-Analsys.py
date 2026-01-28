import os
import sys
import re
import socket
import nmap
import markdown
import requests
from xhtml2pdf import pisa
from datetime import datetime
from dotenv import load_dotenv

# ==========================================
#  ⚙️ CONFIGURATION & SECURITY
# ==========================================

# 1. โหลด API Key จากไฟล์ .env (ปลอดภัย 100%)
load_dotenv()
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GROQ_MODEL = "llama-3.3-70b-versatile"

REPORT_FILENAME = "Pentest_Report_{name}.pdf"

# เช็คว่ามี Key หรือไม่
if not GROQ_API_KEY:
    print("❌ Error: ไม่พบ GROQ_API_KEY ในไฟล์ .env")
    print("   -> กรุณาสร้างไฟล์ .env และใส่ GROQ_API_KEY=... ลงไป")
    sys.exit(1)

# ==========================================

try:
    from langchain_groq import ChatGroq
    from langchain_core.prompts import ChatPromptTemplate
    AI_AVAILABLE = True
except ImportError:
    print("⚠️ Libraries missing! Please run: pip install langchain-groq")
    sys.exit()

class SmartPentestAI:
    def __init__(self):
        self._print_banner()
        try:
            # เพิ่ม path ของ nmap หาก windows หาไม่เจอ (Optional)
            # nmap.PortScanner(nmap_search_path=('C:\\Program Files (x86)\\Nmap\\nmap.exe',))
            self.nm = nmap.PortScanner()
        except nmap.PortScannerError:
            print("❌ Nmap not found! Please install Nmap: https://nmap.org/download.html")
            sys.exit()
        except:
            print("❌ Unexpected error initializing Nmap.")
            sys.exit()
            
        self.findings = []
        self.llm = None
        self._init_ai()

    def _print_banner(self):
        print("\n" + "="*70)
        print("   🌐  FULL AGENTIC PENTEST TOOL (SECURE & HYBRID)  🌐")
        print("      [Nmap + Web Headers + AI Analysis -> PDF Report]")
        print("="*70)

    def _init_ai(self):
        try:
            print(f"[*] Connecting to AI Brain ({GROQ_MODEL})...")
            self.llm = ChatGroq(temperature=0.3, model_name=GROQ_MODEL, api_key=GROQ_API_KEY)
            print("✅ AI Ready.")
        except Exception as e:
            print(f"❌ AI Connection Error: {e}")

    def _resolve_target(self, target_input):
        """Resolve Domain to IP"""
        try:
            socket.inet_aton(target_input)
            return target_input, target_input
        except socket.error:
            try:
                print(f"[*] Resolving Domain: {target_input} ...")
                ip = socket.gethostbyname(target_input)
                print(f"    -> Resolved to: {ip}")
                return target_input, ip
            except:
                print("❌ Cannot resolve domain.")
                return None, None

    def _analyze_web_headers(self, target_ip, port):
        """ตรวจสอบ HTTP Security Headers"""
        print(f"      🌐 Analyzing Web Headers on port {port}...")
        try:
            protocol = "https" if port in [443, 8443] else "http"
            url = f"{protocol}://{target_ip}:{port}"
            
            # verify=False เพื่อข้าม SSL Error ในแล็บ
            response = requests.get(url, timeout=5, verify=False)
            headers = response.headers
            
            required_headers = [
                "X-Frame-Options",
                "X-XSS-Protection",
                "Content-Security-Policy",
                "Strict-Transport-Security", # HSTS
                "X-Content-Type-Options"
            ]
            
            missing = [h for h in required_headers if h not in headers]
            
            if missing:
                return f"Missing Security Headers: {', '.join(missing)}"
            return "✅ All key security headers are present."

        except Exception as e:
            return f"Web Analysis Error: {str(e)}"

    def _analyze_and_generate_poc(self, service, port, info_context):
        if not self.llm: return "AI Offline"

        prompt_template = """
        Role: Senior Penetration Tester & Security Consultant.
        Target: Service '{service}' on Port {port}.
        Context Info: {info}.

        Task: Write a professional vulnerability assessment block for a PDF report.

        Output Format (Strict Markdown):
        ### 🚩 Finding: [Name of the issue based on Context Info]
        
        **Severity:** [Critical/High/Medium/Low]
        
        **Description:**
        [Explain what the vulnerability is, focusing on the specific CVEs or Missing Headers found.]
        
        **🛠️ Manual Verification (PoC):**
        > Run this command to verify:
        ```bash
        [Insert Command Here e.g. curl, ncat]
        ```
        *Expected Output:* [What to look for]

        **🛡️ Remediation (How to Fix):**
        1. [Step 1]
        2. [Step 2]
        
        Note: If no specific vulnerability is critical, provide general hardening advice for this service.
        """
        
        try:
            # print(f"      🧠 AI is analyzing {service}...", end="\r")
            prompt = ChatPromptTemplate.from_template(prompt_template)
            chain = prompt | self.llm
            # Convert list to string if needed
            info_str = str(info_context)
            res = chain.invoke({"service": service, "port": port, "info": info_str})
            return res.content
        except Exception as e:
            return f"Analysis Failed: {e}"

    def run_scan(self, target_display, target_ip):
        print(f"\n[1/2] 📡 Scanning Target: {target_display} ({target_ip})")
        
        try:
            # Scan Argument:
            # -sV: Version Detection
            # --script vulners: Find CVEs
            # -T4: Faster timing
            args = '-sV --script vulners --script-args mincvss=5.0 -T4 --open -Pn'
            self.nm.scan(hosts=target_ip, arguments=args)
        except Exception as e:
            print(f"❌ Scan Error: {e}")
            return

        print("      ✅ Scan Finished. Analyzing results...")
        
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                ports = sorted(self.nm[host][proto].keys())
                for port in ports:
                    svc = self.nm[host][proto][port]
                    service_name = f"{svc.get('product', '')} {svc.get('version', '')}".strip() or svc.get('name', 'unknown')
                    
                    # 1. ดึง CVE
                    cves = []
                    if 'script' in svc and 'vulners' in svc['script']:
                        cves = re.findall(r'(CVE-\d{4}-\d{4,})', svc['script']['vulners'])
                        cves = list(set(cves))

                    # 2. เช็ค Web Headers (ถ้าเป็นพอร์ตเว็บ)
                    web_findings = ""
                    if port in [80, 443, 8080, 8443]:
                        web_findings = self._analyze_web_headers(target_ip, port)

                    # 3. ตัดสินใจส่ง AI วิเคราะห์
                    if cves or web_findings or port in [21, 22, 23, 3389, 3306]:
                        print(f"    🔎 Analyzed Port {port}: {service_name}")
                        
                        # รวมข้อมูลส่งให้ AI
                        context_data = f"CVEs Found: {cves}. "
                        if web_findings:
                            context_data += f"Web Analysis: {web_findings}"
                        
                        analysis = self._analyze_and_generate_poc(service_name, port, context_data)
                        
                        self.findings.append({
                            "port": port,
                            "service": service_name,
                            "analysis": analysis
                        })

    def generate_pdf_report(self, target_display, target_ip):
        if not self.findings:
            print("No significant findings to report.")
            return

        safe_name = target_display.replace('.', '_').replace(':', '')
        filename = REPORT_FILENAME.format(name=safe_name)
        print(f"\n[2/2] 📝 Generating PDF Report: {filename}")

        # --- Markdown Content ---
        md_content = f"# Penetration Test Report\n"
        md_content += f"**Target:** {target_display} ({target_ip})\n"
        md_content += f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
        md_content += "---\n\n"

        for item in self.findings:
            md_content += f"## 🎯 Port {item['port']} - {item['service']}\n"
            md_content += item['analysis']
            md_content += "\n\n---\n"

        # --- Convert to HTML ---
        html_body = markdown.markdown(md_content, extensions=['fenced_code', 'codehilite'])

        # --- CSS Styling (GitHub Style) ---
        css = """
        <style>
            @page { size: A4; margin: 2cm; }
            body { font-family: Helvetica, sans-serif; font-size: 11pt; color: #24292e; }
            h1 { color: #0366d6; border-bottom: 2px solid #eaecef; padding-bottom: 10px; }
            h2 { margin-top: 25px; border-bottom: 1px solid #eaecef; padding-bottom: 5px; }
            h3 { color: #d73a49; margin-top: 20px; } 
            pre { background-color: #f6f8fa; padding: 10px; border-radius: 5px; border: 1px solid #ddd; font-family: Courier; white-space: pre-wrap; }
            code { background-color: #f6f8fa; font-family: Courier; padding: 2px 4px; }
            blockquote { border-left: 4px solid #dfe2e5; color: #6a737d; padding-left: 10px; margin-left: 0; }
        </style>
        """
        
        full_html = f"<html><head>{css}</head><body>{html_body}</body></html>"

        # --- Save PDF ---
        try:
            with open(filename, "wb") as f:
                pisa_status = pisa.CreatePDF(full_html, dest=f)
            
            if not pisa_status.err:
                print(f"✅ PDF Created Successfully: {os.path.abspath(filename)}")
            else:
                print("❌ PDF Generation Failed.")
        except Exception as e:
            print(f"❌ Error saving PDF: {e}")

    def start(self):
        raw_input = input("🎯 Enter Target (Domain or IP): ").strip()
        if not raw_input: return
        
        display, ip = self._resolve_target(raw_input)
        if ip:
            self.run_scan(display, ip)
            self.generate_pdf_report(display, ip)

if __name__ == "__main__":
    app = SmartPentestAI()
    app.start()