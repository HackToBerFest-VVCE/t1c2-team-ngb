"""Evidence-led attack-family trend analysis for the ML Insights workspace.

This module describes patterns in published NVD vulnerabilities. It does not
claim that a CVE was exploited or predict a specific future intrusion.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import re
from urllib.parse import quote

import pandas as pd


HORIZONS = {90, 180, 730, 1095}
ATTACK_FAMILIES = [
    ("Remote code execution", re.compile(r"remote code execution|arbitrary code execution|execute arbitrary code|command injection|improper control of code generation", re.I), "Apply the vendor patch; restrict exposed services; isolate vulnerable systems until patched; review process and egress telemetry."),
    ("Authentication and access-control bypass", re.compile(r"authentication bypass|bypass authentication|improper authentication|authorization bypass|access control|privilege escalation|gain(?:s|ed)? (?:administrator|root|privileged) access", re.I), "Patch promptly; enforce MFA; remove unnecessary privileged access; review authentication, authorization, and admin audit logs."),
    ("Cross-site scripting (XSS)", re.compile(r"cross.site scripting|\bxss\b", re.I), "Upgrade the affected component; encode output by context; sanitize untrusted input; deploy a restrictive Content Security Policy."),
    ("SQL injection", re.compile(r"sql injection|sql command|improper neutralization of special elements used in an sql command", re.I), "Patch the affected application; use parameterized queries; reduce database privileges; rotate exposed credentials if evidence warrants."),
    ("Path traversal and file access", re.compile(r"path traversal|directory traversal|improper limitation of a pathname|arbitrary file (?:read|write|deletion)|local file inclusion", re.I), "Patch; canonicalize and constrain file paths to an allowlisted root; restrict service account filesystem permissions."),
    ("Server-side request forgery (SSRF)", re.compile(r"server.side request forgery|\bssrf\b", re.I), "Patch; restrict outbound network access; block metadata and private address ranges; validate and allowlist destination hosts."),
    ("Denial of service (DoS)", re.compile(r"denial.of.service|resource exhaustion|uncontrolled resource consumption|\bdos\b", re.I), "Apply vendor mitigations; rate-limit exposed endpoints; cap resource-intensive inputs; monitor availability and resource saturation."),
    ("Deserialization and unsafe object handling", re.compile(r"deseriali[sz]|unsafe object|untrusted data.*object", re.I), "Patch; avoid deserializing untrusted data; use safe formats and strict type allowlists; isolate affected services."),
    ("Memory corruption", re.compile(r"buffer overflow|out.of.bounds|use.after.free|use after free|double.free|memory corruption|heap overflow|stack overflow", re.I), "Install the fixed vendor release; use vendor mitigations; restrict exposure and monitor for crashes or anomalous process behavior."),
    ("Information disclosure", re.compile(r"information disclosure|sensitive information|exposure of sensitive|read.*sensitive data|credential disclosure", re.I), "Patch; restrict access to affected data; review access logs; rotate secrets only when exposure is confirmed or plausible."),
]


def build_forecast(frame: pd.DataFrame, days: int, source: dict, now: pd.Timestamp | None = None) -> dict:
    """Summarize all dated Critical/High rows and derive transparent 30d signals."""
    if days not in HORIZONS:
        raise ValueError("days must be one of 90, 180, 730, or 1095")
    now = now or pd.Timestamp.now(tz="UTC")
    if now.tzinfo is None:
        now = now.tz_localize("UTC")
    now = now.tz_convert("UTC")
    start = now - pd.Timedelta(days=days)

    dated = frame.dropna(subset=["published"]).copy()
    window = dated[(dated.published >= start) & (dated.published <= now)].copy()
    severity = window.severity.fillna("").astype(str).str.upper()
    severe = window[severity.isin({"CRITICAL", "HIGH"})].copy()
    text = severe.description.fillna("").astype(str) + " " + severe.cwe.fillna("").astype(str)
    family = pd.Series("Other / unclassified high-severity weakness", index=severe.index, dtype=object)
    unmatched = pd.Series(True, index=severe.index)
    for name, pattern, _ in ATTACK_FAMILIES:
        matched = unmatched & text.str.contains(pattern, na=False)
        family.loc[matched] = name
        unmatched.loc[matched] = False
    severe["attack_family"] = family

    recent_start = now - pd.Timedelta(days=30)
    recent = severe[severe.published >= recent_start]
    historical = severe[severe.published < recent_start]
    effective_start = max(start, dated.published.min()) if not dated.empty else start
    baseline_days = max(int((recent_start - effective_start).total_seconds() // 86400), 0)
    baseline_rate = len(historical) / baseline_days * 30 if baseline_days else 0.0
    families = []
    recent_ids = severe.sort_values("published", ascending=False).head(12)
    for family, records in severe.groupby("attack_family", sort=False):
        recent_count = int((records.published >= recent_start).sum())
        historical_count = int(len(records) - recent_count)
        historical_rate = historical_count / baseline_days * 30 if baseline_days else 0.0
        if historical_count == 0 and recent_count:
            direction = "new in latest 30 days"
        elif historical_rate == 0:
            direction = "insufficient comparison history"
        elif recent_count / historical_rate >= 1.25:
            direction = "rising"
        elif recent_count / historical_rate <= 0.75:
            direction = "falling"
        else:
            direction = "steady"
        examples = records.sort_values("published", ascending=False).head(5)
        mean_cvss = records.cvss_score.dropna().mean() if "cvss_score" in records else None
        remedy = next((entry[2] for entry in ATTACK_FAMILIES if entry[0] == family),
                      "Review each linked NVD record and vendor advisory; verify affected assets and apply confirmed fixes.")
        expected_outcome = (
            "If affected assets are confirmed and the recommended fix or control is verified, this should reduce exposure to the grouped weakness. "
            "Confirm deployed versions and monitor relevant telemetry; no remediation outcome is assumed by this report."
        )
        families.append({
            "name": family,
            "count": int(len(records)),
            "critical": int((records.severity.astype(str).str.upper() == "CRITICAL").sum()),
            "high": int((records.severity.astype(str).str.upper() == "HIGH").sum()),
            "latest_30d": recent_count,
            "historical_per_30d": round(historical_rate, 1),
            "direction": direction,
            "mean_cvss": round(float(mean_cvss), 2) if pd.notna(mean_cvss) else None,
            "cve_examples": examples.cve_id.dropna().astype(str).tolist(),
            "remedy": remedy,
            "expected_outcome": expected_outcome,
        })
    families.sort(key=lambda item: (item["latest_30d"], item["count"], item["mean_cvss"] or 0), reverse=True)
    watchlist = [
        {
            "name": item["name"],
            "observed_latest_30d": item["latest_30d"],
            "direction": item["direction"],
            "reason": (
                f"{item['latest_30d']} Critical/High disclosures in the latest 30 days; "
                f"historical pace was {item['historical_per_30d']:.1f} per 30 days."
            ),
            "defensive_action": item["remedy"],
            "expected_outcome": item["expected_outcome"],
            "cve_examples": item["cve_examples"],
        }
        for item in families[:5]
        if item["latest_30d"] > 0
    ]

    recent_high_critical = []
    for row in recent_ids.itertuples():
        recent_high_critical.append({
            "cve_id": str(row.cve_id),
            "published": row.published.isoformat() if pd.notna(row.published) else None,
            "severity": str(row.severity or "UNKNOWN").upper(),
            "cvss_score": float(row.cvss_score) if pd.notna(row.cvss_score) else None,
            "attack_family": str(row.attack_family),
            "source_url": f"https://nvd.nist.gov/vuln/detail/{quote(str(row.cve_id), safe='')}",
        })

    confidence = "low" if len(severe) < 30 or baseline_days < 30 else "moderate" if len(severe) < 250 else "pattern signal only"
    payload = {
        "window_days": days,
        "from": start.isoformat(),
        "to": now.isoformat(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "window_records": int(len(window)),
        "high_critical_records": int(len(severe)),
        "latest_30d_high_critical": int(len(recent)),
        "historical_high_critical_per_30d": round(baseline_rate, 1),
        "coverage": {
            "from": dated.published.min().isoformat() if not dated.empty else None,
            "to": dated.published.max().isoformat() if not dated.empty else None,
            "dated_records_loaded": int(len(dated)),
            "window_limited_by_source_history": bool(not dated.empty and dated.published.min() > start),
        },
        "confidence": confidence,
        "families": families,
        "near_term_watchlist": watchlist,
        "recent_high_critical": recent_high_critical,
        "method": "Groups every dated NVD Critical/High record in the selected rolling publication window by explicit description keywords. Direction compares the latest 30 days with the preceding window normalized to a 30-day rate; it is descriptive, not a predictive model.",
        "limitations": "NVD records describe published vulnerabilities, not confirmed attacks or exploitation. Family labels are heuristic keyword groupings. A rising disclosure rate does not establish that attackers will use that technique next. Validate NVD entries, vendor advisories, asset exposure, and authoritative exploitation intelligence before action.",
    }
    payload["cortex_prompt"] = _cortex_prompt(payload)
    return payload


def _cortex_prompt(report: dict) -> str:
    families = [{key: item[key] for key in ("name", "count", "critical", "high", "latest_30d", "historical_per_30d", "direction", "mean_cvss", "cve_examples")} for item in report["families"][:12]]
    recent = [{key: item[key] for key in ("cve_id", "published", "severity", "cvss_score", "attack_family")} for item in report["recent_high_critical"][:12]]
    safe = {key: report[key] for key in ("window_days", "from", "to", "window_records", "high_critical_records", "latest_30d_high_critical", "historical_high_critical_per_30d", "confidence", "coverage")}
    safe.update({"attack_families": families, "recent_high_critical_cves": recent})
    return (
        "You are a defensive vulnerability analyst. Interpret ONLY these aggregate NVD publication facts. "
        "NVD publication trends are not evidence of active exploitation; never claim certainty or assign unsupported probabilities. "
        "Return concise headings: Observed patterns, Near-term watchlist (directional, not a prediction), "
        "Defensive priorities, Evidence to verify, Limitations. Cite only CVE IDs present below. "
        "Recommendations should be general defensive controls and direct users to verify vendor fixes.\n"
        + json.dumps(safe, ensure_ascii=True, separators=(",", ":"))
    )


def add_cortex_interpretation(report: dict) -> dict:
    """Ask configured Snowflake Cortex to interpret bounded aggregate signals."""
    from .ai import configuration
    from .provider import get_provider

    try:
        cfg = configuration("cortex")
        if not cfg.get("configured"):
            report.update({
                "analysis_provider": "local",
                "cortex_status": "unavailable",
                "cortex_notice": "Snowflake Cortex is not available in this account configuration; deterministic NVD pattern analysis is shown.",
            })
            return report
        interpretation = get_provider().cortex_complete(report["cortex_prompt"], cfg["model"])
        report.update({
            "analysis_provider": "snowflake_cortex",
            "cortex_model": cfg["model"],
            "cortex_interpretation": interpretation,
            "cortex_status": "complete",
        })
    except Exception:
        report.update({
            "analysis_provider": "local",
            "cortex_status": "fallback",
            "cortex_notice": "Cortex could not complete this report; local NVD pattern analysis is shown. Check the backend Cortex entitlement and Snowflake connectivity if you expected a Cortex response.",
        })
    return report
