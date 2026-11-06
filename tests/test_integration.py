import importlib.util
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("smartsoc", ROOT / "integration" / "custom-thehive.py")
smartsoc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smartsoc)

ALERT = json.loads((ROOT / "tests" / "fixtures" / "alert_ssh_bruteforce.json").read_text())


def test_extract_src_ip():
    assert smartsoc.extract_src_ip(ALERT) == "192.168.0.170"
    win = {"data": {"win": {"eventdata": {"sourceAddress": "10.0.0.5"}}}}
    assert smartsoc.extract_src_ip(win) == "10.0.0.5"


def test_level_mapping():
    assert smartsoc.wazuh_level_to_thehive(3) == 1
    assert smartsoc.wazuh_level_to_thehive(10) == 3
    assert smartsoc.wazuh_level_to_thehive(15) == 4


def test_llm_down_does_not_lose_alert():
    with patch.object(smartsoc.requests, "post", side_effect=ConnectionError("down")):
        triage = smartsoc.ask_llm("rule", "log")
    assert "no disponible" in triage["resumen"]


def test_llm_non_json_degrades_to_text():
    resp = MagicMock(**{"json.return_value": {"response": "texto libre"}})
    with patch.object(smartsoc.requests, "post", return_value=resp):
        assert smartsoc.ask_llm("r", "l")["resumen"] == "texto libre"


def test_build_alert_has_observables_and_mitre():
    triage = {"resumen": "Fuerza bruta SSH", "severidad": "alta", "acciones": ["Bloquear IP"]}
    a = smartsoc.build_alert(ALERT, triage, "192.168.0.170")
    assert a["severity"] == 3
    assert {"dataType": "ip", "data": "192.168.0.170", "message": "IP origen"} in a["observables"]
    assert "mitre:T1110" in a["tags"]
    assert "Bloquear IP" in a["description"]
