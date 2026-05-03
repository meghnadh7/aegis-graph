"""Builds Wazuh-shaped alerts off the templates in templates/.

Per-technique label split is roughly 40/35/25 (TP/FP/escalate). Hostnames,
IPs, hashes, timestamps are jittered, but the jitter is seeded so a given
seed always produces the same alert — useful for reproducible evals.
"""
from __future__ import annotations
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

TEMPLATES_DIR = Path(__file__).parent / "templates"

TENANT_HOST_POOLS = {
    "tenant_a": [
        "fintech-ws-042", "fintech-ws-101", "payment-processor-01", "db-master-01",
        "auth-server-01", "pci-vault-01", "fintech-ws-077",
    ],
    "tenant_b": [
        "hc-ws-091", "ehr-server-01", "radiology-pacs-01", "ad-dc-01",
        "hc-ws-005", "backup-nas-01", "hc-ws-200",
    ],
}

LABEL_DISTRIBUTION = ["true_positive"] * 40 + ["false_positive"] * 35 + ["escalate"] * 25


def load_template(technique: str) -> Dict[str, Any]:
    path = TEMPLATES_DIR / f"{technique.replace('.', '_').lower()}.json"
    with path.open() as fh:
        return json.load(fh)


def list_template_names() -> List[str]:
    return sorted(p.stem for p in TEMPLATES_DIR.glob("*.json"))


def _pick_variant(template: Dict[str, Any], target_label: str, rng: random.Random) -> Dict[str, Any]:
    matching = [v for v in template["variants"] if v.get("label") == target_label]
    if not matching:
        matching = template["variants"]
    return rng.choice(matching)


def _jittered_ip(seed: str) -> str:
    h = int(hashlib.sha256(seed.encode()).hexdigest()[:8], 16)
    return f"{(h % 200) + 30}.{(h >> 8) % 256}.{(h >> 16) % 256}.{(h >> 4) % 254 + 1}"


def _jittered_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()


def generate_alert(
    technique: str,
    tenant_id: str,
    label: Optional[str] = None,
    seed: Optional[int] = None,
    alert_id: Optional[str] = None,
) -> Dict[str, Any]:
    template = load_template(technique)
    rng = random.Random(seed if seed is not None else uuid4().int)
    label = label or rng.choice(LABEL_DISTRIBUTION)
    variant = _pick_variant(template, label, rng)

    host_pool = TENANT_HOST_POOLS.get(tenant_id, ["host-01", "host-02"])
    host = rng.choice(host_pool)
    seed_str = f"{technique}-{tenant_id}-{seed}-{label}-{host}"
    ip = variant.get("ip") or _jittered_ip(seed_str)
    rule_id = rng.choice(template["rule_id_pool"])
    ts = datetime.now(timezone.utc) - timedelta(minutes=rng.randint(0, 720))
    aid = alert_id or f"AL-{uuid4().hex[:10].upper()}"

    eventdata: Dict[str, Any] = {
        "image": variant.get("image", ""),
        "commandLine": variant.get("command_line", ""),
        "parentImage": variant.get("parent_image", ""),
        "user": variant.get("user", "unknown"),
        "computer": host,
    }
    if variant.get("hash"):
        eventdata["hashes"] = f"SHA256={variant['hash']}"
    else:
        eventdata["hashes"] = f"SHA256={_jittered_hash(seed_str)[:64]}"

    if variant.get("url"):
        eventdata["targetUrl"] = variant["url"]
    if variant.get("domain"):
        eventdata["targetDomain"] = variant["domain"]

    alert = {
        "id": aid,
        "timestamp": ts.isoformat(),
        "rule": {
            "id": rule_id,
            "level": variant.get("level", 8),
            "description": variant["description"],
            "mitre": {
                "id": [template["technique_id"]],
                "technique": [template["technique_name"]],
                "tactic": [template["tactic"]],
            },
        },
        "agent": {"name": host, "ip": ip, "id": f"00{rng.randint(1, 99):02d}"},
        "data": {
            "win": {
                "system": {
                    "computer": host,
                    "eventID": "1" if "powershell" in variant.get("image", "").lower() or "exe" in variant.get("image", "").lower() else "4624",
                    "providerName": "Microsoft-Windows-Sysmon",
                },
                "eventdata": eventdata,
            }
        },
        "_synthetic": {
            "label": label,
            "technique_id": template["technique_id"],
            "tenant_id": tenant_id,
            "seed": seed,
        },
    }
    return alert


def _label_schedule(per_technique: int) -> List[str]:
    """Build a per-technique label list that hits the 40/35/25 TP/FP/escalate split.

    The previous version did `LABEL_DISTRIBUTION[i % 100]` which collapsed to
    all-TP when per_technique was 40 (because the first 40 slots of the
    distribution are all TP). This builds the right counts up front and
    interleaves them so consecutive alerts of the same technique aren't
    always the same label.
    """
    n_tp = round(per_technique * 0.40)
    n_fp = round(per_technique * 0.35)
    n_esc = per_technique - n_tp - n_fp  # remainder ≈ 25%
    # Interleave so the order is TP,FP,ESC,TP,FP,ESC,... up to the smallest
    # bucket, then drain whatever's left.
    out: List[str] = []
    pools = {"true_positive": n_tp, "false_positive": n_fp, "escalate": n_esc}
    order = ["true_positive", "false_positive", "escalate"]
    while sum(pools.values()) > 0:
        for label in order:
            if pools[label] > 0:
                out.append(label)
                pools[label] -= 1
    return out[:per_technique]


def generate_dataset(per_technique: int = 40, tenants: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Generate a balanced dataset across all 5 templates and 2 tenants."""
    tenants = tenants or ["tenant_a", "tenant_b"]
    alerts: List[Dict[str, Any]] = []
    techniques = list_template_names()
    schedule = _label_schedule(per_technique)
    seed_counter = 0
    for tech in techniques:
        for i in range(per_technique):
            tenant = tenants[i % len(tenants)]
            label = schedule[i]
            alerts.append(generate_alert(tech, tenant, label=label, seed=seed_counter))
            seed_counter += 1
    return alerts
