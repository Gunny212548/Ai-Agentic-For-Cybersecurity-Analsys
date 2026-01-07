import requests
import json

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "deepseek-r1"


def llm_analyst_agent(recon_data, risk_report):
    prompt = f"""
You are a professional cybersecurity analyst.
Use ONLY the provided data.

Recon Data:
{json.dumps(recon_data)}

Risk Report:
{json.dumps(risk_report)}

Tasks:
1. Identify critical risks
2. Explain impact
3. Describe attack scenarios
"""

    response = requests.post(
        OLLAMA_URL,
        json={
            "model": MODEL,
            "prompt": prompt,
            "stream": True
        },
        stream=True
    )

    result = ""
    for line in response.iter_lines():
        if line:
            data = json.loads(line.decode("utf-8"))
            result += data.get("response", "")

    return result
