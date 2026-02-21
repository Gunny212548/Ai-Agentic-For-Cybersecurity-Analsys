import streamlit as st
import asyncio
import os
import socket
import nmap
import builtwith
import json
import re
import warnings
from urllib.parse import urlparse
from dotenv import load_dotenv
from langchain_groq import ChatGroq

# ==========================================
# 🔧 1. INITIALIZATION & CONFIG
# ==========================================
warnings.filterwarnings("ignore")
load_dotenv()

st.set_page_config(page_title="Ultimate AI Pentest Agent", page_icon="🛡️", layout="wide")

CONFIG = {
    "MODEL_SMART": "llama-3.3-70b-versatile", # รุ่นฉลาดสุดสำหรับวิเคราะห์
    "MODEL_FAST": "llama-3.1-8b-instant",     # รุ่นเร็วสำหรับงานย่อย
    "MAX_CONCURRENT": 2,                      # จำกัดเพื่อป้องกัน 30 RPM Limit
    "NMAP_ARGS": "-sV --version-intensity 5 -T4 -Pn --open --script=ssl-cert,http-title,vulners"
}

# ==========================================
# 🧠 2. ADVANCED AI ENGINE (REASONING AGENTS)
# ==========================================
class AdvancedAIEngine:
    def __init__(self, api_key):
        self.llm_brain = ChatGroq(temperature=0.1, model_name=CONFIG["MODEL_SMART"], api_key=api_key)
        self.llm_fast = ChatGroq(temperature=0.1, model_name=CONFIG["MODEL_FAST"], api_key=api_key)
        self.sem = asyncio.Semaphore(CONFIG["MAX_CONCURRENT"])

    async def _safe_call(self, llm, prompt: str):
        async with self.sem:
            try:
                await asyncio.sleep(1.5) # หน่วงเวลาตามโควต้า API
                resp = await llm.ainvoke(prompt)
                return resp.content
            except Exception as e:
                return f"AI Error: {str(e)}"

    async def run_analyst(self, domain, p_data, tech):
        prompt = f"""
        Role: Senior Security Analyst
        Target: {domain} | Service: {p_data['product']} {p_data['version']}
        Vulnerability Data: {p_data['script_output']}
        Tech Stack: {tech}
        
        Task: Analyze if these are real threats or false positives. 
        Focus on: CVE impact, potential Ransomware entry points, and SSL/DNS risks.
        Summarize in professional bullet points starting with 'ANALYSIS:'.
        """
        return await self._safe_call(self.llm_brain, prompt)

    async def run_engineer(self, p_data, analysis):
        prompt = f"""
        Role: Red Team Engineer
        Context: {p_data['product']} {p_data['version']} | Analysis: {analysis}
        Task: Provide a SAFE verification command (JSON format).
        JSON: {{"risk_score": 0-10, "risk_level": "High/Medium/Low", "poc_cmd": "..."}}
        """
        res = await self._safe_call(self.llm_brain, prompt)
        try:
            match = re.search(r'\{.*\}', res, re.DOTALL)
            return json.loads(match.group())
        except: return {"risk_score": 0, "risk_level": "Low", "poc_cmd": f"nmap -p {p_data['port']} {p_data['product']}"}

    async def run_fixer(self, p_data, risk_level):
        prompt = f"Role: Blue Team. Provide 1 specific remediation step for {p_data['product']} {p_data['version']} (Risk: {risk_level})."
        return await self._safe_call(self.llm_fast, prompt)

# ==========================================
# 🖥️ 3. STREAMLIT GUI (EXECUTIVE DASHBOARD)
# ==========================================
st.title("🛡️ Ultimate AI Pentest Agent")
st.markdown("ระบบวิเคราะห์ความปลอดภัยอัจฉริยะ (Network, SSL, DNS & Vulnerability Intelligence)")

with st.sidebar:
    st.header("⚙️ Configuration")
    api_key = st.text_input("Groq API Key", type="password", value=os.getenv("GROQ_API_KEY", ""))
    target_input = st.text_input("Target Domain/IP", placeholder="scanme.nmap.org")
    scan_mode = st.selectbox("Scan Depth", ["Common Ports (1-1024)", "Full Scan (1-65535)"])
    start_btn = st.button("🚀 Start Deep Analysis", type="primary")

if start_btn and target_input and api_key:
    ai = AdvancedAIEngine(api_key)
    nm = nmap.PortScanner()
    
    try:
        with st.status("🔍 Phase 1: Deep Scanning & Fingerprinting...", expanded=True) as status:
            host = urlparse(target_input).hostname if "://" in target_input else target_input
            ip = socket.gethostbyname(host)
            st.write(f"🌐 Resolved IP: `{ip}`")
            
            p_range = "1-1024" if "Common" in scan_mode else "1-65535"
            st.write(f"📡 Nmap is scanning `{p_range}` with NSE Scripts...")
            nm.scan(ip, ports=p_range, arguments=CONFIG["NMAP_ARGS"])
            
            # เก็บข้อมูลเบื้องต้น
            scan_results = []
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto]:
                    s = nm[ip][proto][port]
                    scan_results.append({
                        'port': port,
                        'product': s.get('product') or "Unknown",
                        'version': s.get('version') or "N/A",
                        'script_output': str(s.get('script', 'None'))
                    })
            
            st.write("🌍 Identifying Tech Stack...")
            tech = "Standard Server Environment"
            try: tech = builtwith.parse(f"http://{host}")
            except: pass

            st.write("🧠 Phase 2: AI Multi-Agent Collaboration...")
            final_findings = []
            
            async def run_workflow():
                for res in scan_results:
                    ana = await ai.run_analyst(host, res, tech)
                    eng = await ai.run_engineer(res, ana)
                    fix = await ai.run_fixer(res, eng['risk_level'])
                    final_findings.append({**res, "ana": ana, "eng": eng, "fix": fix})

            # จัดการ Event Loop สำหรับ Streamlit
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    import nest_asyncio
                    nest_asyncio.apply()
                    loop.run_until_complete(run_workflow())
                else:
                    loop.run_until_complete(run_workflow())
            except:
                asyncio.run(run_workflow())

            status.update(label="✅ All Intelligence Gathered!", state="complete")

        # --- EXECUTIVE SUMMARY ---
        st.divider()
        c1, c2, c3, c4 = st.columns(4)
        with c1: st.metric("Open Ports", len(final_findings))
        with c2: 
            high_count = len([f for f in final_findings if f['eng']['risk_level'] in ['High', 'Critical']])
            st.metric("Critical/High Risks", high_count, delta="Action Required" if high_count > 0 else "Low Risk")
        with c3:
            grade = "A" if high_count == 0 else "B" if high_count == 1 else "C" if high_count <= 3 else "D"
            st.subheader(f"Security Grade: `{grade}`")
        with c4:
            st.write("**Overall Status:**")
            if grade in ["A", "B"]: st.success("SECURE")
            else: st.warning("VULNERABLE")

        # --- DETAILED TECHNICAL FINDINGS ---
        st.header("📝 Detailed Security Findings")
        for f in final_findings:
            with st.expander(f"🔹 Port {f['port']} - {f['product']} (Risk: {f['eng']['risk_level']})"):
                col_left, col_right = st.columns([2, 1])
                with col_left:
                    st.markdown("#### 🕵️ Analyst Insight")
                    st.info(f['ana'])
                    st.markdown("#### 🛡️ Remediation Plan")
                    st.success(f['fix'])
                with col_right:
                    st.markdown("#### ⚔️ Verification (PoC)")
                    st.code(f['eng']['poc_cmd'], language="bash")
                    st.progress(int(f['eng'].get('risk_score', 0)) * 10, 
                                text=f"Risk Score: {f['eng'].get('risk_score')}/10")

    except Exception as e:
        st.error(f"❌ Critical Error: {e}")
else:
    st.info("กรุณาระบุข้อมูลและ Groq API Key ใน Sidebar เพื่อเริ่มกระบวนการสแกนวิเคราะห์")