#!/var/ossec/framework/python/bin/python3
"""SmartSOC: Wazuh -> LLM local (Ollama) -> TheHive.

Wazuh ejecuta este script como integración personalizada:
    custom-thehive <alert_file> <api_key> <hook_url>

Lee la alerta, pide a un LLM local un triaje estructurado y crea una
alerta enriquecida (con observables) en TheHive.
"""
import json
import os
import sys
from datetime import datetime, timezone

import requests

OLLAMA_URL = os.getenv("SMARTSOC_OLLAMA_URL", "http://172.17.0.1:11434/api/generate")
OLLAMA_MODEL = os.getenv("SMARTSOC_MODEL", "tinyllama")
OLLAMA_TIMEOUT = int(os.getenv("SMARTSOC_OLLAMA_TIMEOUT", "60"))
# IPs separadas por comas. Vacío = procesar todas (en el TFM se filtraba la IP del atacante de laboratorio).
SRC_ALLOWLIST = {ip.strip() for ip in os.getenv("SMARTSOC_SRC_FILTER", "").split(",") if ip.strip()}
VERIFY_TLS = os.getenv("SMARTSOC_VERIFY_TLS", "false").lower() == "true"
LOG_FILE = os.getenv("SMARTSOC_LOG", "/var/ossec/logs/integrations.log")

PROMPT = """Eres un analista SOC N2. Analiza esta alerta de Wazuh y responde SOLO con JSON válido
con las claves: "resumen" (1-2 frases en español), "tactica_mitre" (nombre o "desconocida"),
"severidad" ("baja"|"media"|"alta"|"critica"), "acciones" (lista de 2-4 pasos concretos).

Regla: {rule}
Log: {log}"""

SEVERITY_MAP = {"baja": 1, "media": 2, "alta": 3, "critica": 4}


def log(msg: str) -> None:
    try:
        with open(LOG_FILE, "a") as f:
            f.write(f"{datetime.now(timezone.utc).isoformat()} [smartsoc] {msg}\n")
    except OSError:
        print(msg, file=sys.stderr)


def extract_src_ip(alert: dict) -> str | None:
    data = alert.get("data", {})
    return (
        data.get("srcip")
        or data.get("win", {}).get("eventdata", {}).get("sourceAddress")
        or data.get("win", {}).get("eventdata", {}).get("sourceIp")
    )


def wazuh_level_to_thehive(level: int) -> int:
    """Wazuh 0-15 -> TheHive 1-4."""
    if level >= 13:
        return 4
    if level >= 10:
        return 3
    if level >= 7:
        return 2
    return 1


def ask_llm(rule: str, full_log: str) -> dict:
    """Devuelve el triaje del LLM; si falla o no es JSON, degrada a texto libre."""
    payload = {
        "model": OLLAMA_MODEL,
        "prompt": PROMPT.format(rule=rule, log=full_log[:4000]),
        "stream": False,
        "format": "json",
    }
    try:
        r = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
        r.raise_for_status()
        raw = r.json().get("response", "")
    except Exception as e:  # el SOC no debe perder la alerta si la IA cae
        log(f"[WARN] LLM no disponible: {e}")
        return {"resumen": "IA local no disponible; revisar log manualmente.", "acciones": []}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"resumen": raw.strip() or "IA local sin respuesta.", "acciones": []}


def build_alert(alert: dict, triage: dict, src_ip: str | None) -> dict:
    rule = alert.get("rule", {})
    level = int(rule.get("level", 0))
    severity = SEVERITY_MAP.get(str(triage.get("severidad", "")).lower(), wazuh_level_to_thehive(level))
    acciones = "\n".join(f"- {a}" for a in triage.get("acciones", []) or []) or "- (sin sugerencias)"
    agent = alert.get("agent", {})

    description = (
        f"### Análisis IA ({OLLAMA_MODEL})\n{triage.get('resumen', '')}\n\n"
        f"**Táctica MITRE (sugerida):** {triage.get('tactica_mitre', 'desconocida')}\n\n"
        f"**Acciones recomendadas:**\n{acciones}\n\n"
        f"### Detalles Wazuh\n"
        f"* **Regla:** {rule.get('id')} – {rule.get('description')} (nivel {level})\n"
        f"* **Agente:** {agent.get('name')} ({agent.get('ip', 'n/a')})\n"
        f"* **IP origen:** {src_ip or 'n/a'}\n"
        f"* **Log:** `{alert.get('full_log', 'Sin registro detallado')}`\n\n"
        f"_Triaje generado automáticamente: validar antes de actuar._"
    )

    observables = []
    if src_ip:
        observables.append({"dataType": "ip", "data": src_ip, "message": "IP origen"})
    if agent.get("name"):
        observables.append({"dataType": "hostname", "data": agent["name"], "message": "Host afectado"})

    tags = ["wazuh", "smartsoc", f"rule:{rule.get('id')}"]
    tags += [f"mitre:{t}" for t in rule.get("mitre", {}).get("id", [])]

    return {
        "type": "SIEM-Alert",
        "source": "Wazuh-SmartSOC",
        "sourceRef": str(alert.get("id", datetime.now().timestamp())),
        "title": f"[Wazuh] {rule.get('description', 'Alerta de seguridad')} – {src_ip or agent.get('name', '')}",
        "description": description,
        "severity": severity,
        "tags": tags,
        "observables": observables,
    }


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print("Uso: custom-thehive <alert_file> <api_key> <hook_url>", file=sys.stderr)
        return 1
    alert_file, api_key, hook_url = argv[1], argv[2], argv[3].rstrip("/")

    try:
        with open(alert_file) as f:
            alert = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        log(f"[ERROR] No se pudo leer la alerta: {e}")
        return 1

    src_ip = extract_src_ip(alert)
    if SRC_ALLOWLIST and src_ip not in SRC_ALLOWLIST:
        return 0

    rule = alert.get("rule", {})
    triage = ask_llm(rule.get("description", ""), alert.get("full_log", ""))
    payload = build_alert(alert, triage, src_ip)

    try:
        r = requests.post(
            f"{hook_url}/api/v1/alert",
            json=payload,
            headers={"Authorization": f"Bearer {api_key}"},
            verify=VERIFY_TLS,
            timeout=15,
        )
        log(f"[OK] TheHive status={r.status_code} src={src_ip} rule={rule.get('id')}")
        return 0 if r.ok else 1
    except requests.RequestException as e:
        log(f"[ERROR] Envío a TheHive: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
