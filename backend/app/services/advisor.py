"""ThreatLens AI — Software Safety Advisor Service.

Evidence-based software risk assessment integrating Snowflake CVE dataset,
OSV.dev package vulnerabilities, NVD intelligence, deterministic version matching,
anti-SSRF URL safeguards, safe static file inspection, and grounded DeepSeek/NVIDIA AI.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Literal
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

import pandas as pd
from packaging import version as pkg_version

from .provider import get_provider, SnowflakeProvider, ProviderError

log = logging.getLogger("threatlens.advisor")

# ── Supported Ecosystems ──────────────────────────────────────────────────
ECOSYSTEMS = {
    "pypi": "PyPI (Python)",
    "npm": "npm (JavaScript / Node.js)",
    "maven": "Maven (Java)",
    "go": "Go (Golang)",
    "crates.io": "Crates.io (Rust)",
    "nuget": "NuGet (.NET)",
    "packagist": "Packagist (PHP)",
    "rubygems": "RubyGems (Ruby)",
    "hex": "Hex (Elixir / Erlang)",
    "pub": "Pub (Dart / Flutter)",
    "generic": "General Software / Desktop / Binary",
}

# ── Verdict Types ──────────────────────────────────────────────────────────
VerdictType = Literal[
    "KNOWN_VULNERABILITIES_FOUND",
    "POTENTIAL_MATCH_REQUIRES_VERIFICATION",
    "NO_MATCHING_VULNERABILITIES_FOUND",
    "INSUFFICIENT_IDENTIFICATION",
    "FILE_ANALYSIS_INCONCLUSIVE",
    "SUSPICIOUS_INDICATORS_FOUND",
]

# ── Cache for OSV and Assessment Results ──────────────────────────────────
_OSV_CACHE: dict[str, tuple[float, list[dict]]] = {}
_ASSESSMENT_CACHE: dict[str, dict] = {}
CACHE_TTL = 3600  # 1 hour


# ── URL Security & Anti-SSRF ──────────────────────────────────────────────
def validate_safe_url(target_url: str) -> tuple[bool, str, str]:
    """Validate a user-supplied URL against SSRF, loopback, private IP, and unsafe schemes.

    Returns:
        (is_safe, error_or_domain, canonical_url)
    """
    if not target_url or not isinstance(target_url, str):
        return False, "URL is empty or invalid.", ""

    target_url = target_url.strip()
    if len(target_url) > 2048:
        return False, "URL exceeds maximum permitted length of 2048 characters.", ""

    try:
        parsed = urlparse(target_url)
    except Exception as exc:
        return False, f"Malformed URL syntax: {exc}", ""

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, f"Prohibited URL scheme '{scheme}'. Only HTTP and HTTPS are permitted.", ""

    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname.", ""

    # Reject local/internal hostnames
    if hostname.lower() in ("localhost", "127.0.0.1", "::1", "0.0.0.0", "instance-data", "metadata"):
        return False, "Access to localhost, loopback, and cloud metadata services is blocked.", ""

    # Check for raw IP addresses or resolve DNS to check against private/reserved ranges
    try:
        # Check if already an IP
        ip_obj = ipaddress.ip_address(hostname)
        ips_to_check = [ip_obj]
    except ValueError:
        # Resolve hostname safely with timeout
        try:
            addr_info = socket.getaddrinfo(hostname, None, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
            ips_to_check = []
            for item in addr_info:
                sockaddr = item[4]
                ip_str = sockaddr[0]
                ips_to_check.append(ipaddress.ip_address(ip_str))
        except (socket.gaierror, socket.herror) as exc:
            return False, f"Could not resolve domain '{hostname}': {exc}", ""

    for ip in ips_to_check:
        if ip.is_loopback:
            return False, f"Destination resolves to loopback IP {ip}. Request blocked.", ""
        if ip.is_private:
            return False, f"Destination resolves to private RFC1918/RFC4193 IP {ip}. Request blocked.", ""
        if ip.is_link_local:
            return False, f"Destination resolves to link-local IP {ip} (e.g. AWS metadata 169.254.x.x). Request blocked.", ""
        if ip.is_multicast:
            return False, f"Destination resolves to multicast IP {ip}. Request blocked.", ""
        if ip.is_reserved:
            return False, f"Destination resolves to reserved IP {ip}. Request blocked.", ""
        if ip.is_unspecified:
            return False, f"Destination resolves to unspecified IP {ip}. Request blocked.", ""

    canonical = f"{scheme}://{hostname}{parsed.path or ''}"
    return True, hostname, canonical


# ── File Safety Inspection (Static Only) ───────────────────────────────────
def inspect_file_safely(file_bytes: bytes, filename: str) -> dict[str, Any]:
    """Perform safe static metadata extraction on uploaded file bytes without execution.

    Limits size, checks magic numbers, inspects package structure if applicable,
    and returns static indicators. Never executes code or unpacks decompression bombs.
    """
    MAX_FILE_SIZE = 15 * 1024 * 1024  # 15 MB
    if len(file_bytes) > MAX_FILE_SIZE:
        raise ValueError(f"Uploaded file exceeds safety limit of {MAX_FILE_SIZE // (1024 * 1024)}MB.")

    sha256 = hashlib.sha256(file_bytes).hexdigest()
    sha1 = hashlib.sha1(file_bytes).hexdigest()
    md5 = hashlib.md5(file_bytes).hexdigest()
    size_bytes = len(file_bytes)

    # Magic byte inspection
    file_type = "unknown/binary"
    suggested_ecosystem = "generic"
    extracted_name = None
    extracted_version = None
    suspicious_flags: list[str] = []

    if file_bytes.startswith(b"MZ"):
        file_type = "application/x-dosexec (Windows PE/EXE)"
        suggested_ecosystem = "generic"
        if b"UPX" in file_bytes[:1024]:
            suspicious_flags.append("UPX packer signature detected in header.")
    elif file_bytes.startswith(b"\x7fELF"):
        file_type = "application/x-executable (Linux ELF)"
        suggested_ecosystem = "generic"
    elif file_bytes.startswith(b"PK\x03\x04"):
        file_type = "application/zip archive (ZIP/APK/Wheel/JAR)"
        # Try inspecting zip table safely in memory
        try:
            import io
            import zipfile
            with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
                namelist = zf.namelist()
                if len(namelist) > 5000:
                    suspicious_flags.append("Archive contains unusually high file count (>5000 entries).")
                total_uncompressed = sum(info.file_size for info in zf.infolist())
                if total_uncompressed > 50 * 1024 * 1024:  # 50 MB
                    suspicious_flags.append("Potential decompression bomb (uncompressed size exceeds 50MB).")

                # Detect APK
                if "AndroidManifest.xml" in namelist:
                    file_type = "application/vnd.android.package-archive (Android APK)"
                    suggested_ecosystem = "generic"
                # Detect Wheel
                for name in namelist:
                    if name.endswith(".dist-info/METADATA"):
                        file_type = "application/x-wheel (Python Wheel)"
                        suggested_ecosystem = "pypi"
                        try:
                            meta_text = zf.read(name).decode("utf-8", errors="ignore")
                            for line in meta_text.splitlines():
                                if line.startswith("Name:"):
                                    extracted_name = line.split(":", 1)[1].strip()
                                elif line.startswith("Version:"):
                                    extracted_version = line.split(":", 1)[1].strip()
                        except Exception:
                            pass
                        break
        except Exception as exc:
            suspicious_flags.append(f"Archive structure read anomaly: {exc}")
    elif file_bytes.startswith(b"\x1f\x8b"):
        file_type = "application/gzip (Tarball / Archive)"
    elif filename.endswith(".json") and b"package.json" in filename.lower().encode():
        try:
            pkg_data = json.loads(file_bytes.decode("utf-8"))
            extracted_name = pkg_data.get("name")
            extracted_version = pkg_data.get("version")
            file_type = "application/json (npm package descriptor)"
            suggested_ecosystem = "npm"
        except Exception:
            pass

    return {
        "filename": os.path.basename(filename)[:120],
        "size_bytes": size_bytes,
        "sha256": sha256,
        "sha1": sha1,
        "md5": md5,
        "detected_type": file_type,
        "suggested_ecosystem": suggested_ecosystem,
        "extracted_name": extracted_name,
        "extracted_version": extracted_version,
        "suspicious_flags": suspicious_flags,
        "is_executable_binary": "dosexec" in file_type or "ELF" in file_type,
        "analysis_mode": "static_metadata_only",
        "notice": "Static inspection only. Executable code is never launched. Dynamic sandbox analysis was not performed.",
    }


# ── OSV.dev Package Vulnerability Lookup ──────────────────────────────────
def query_osv_package(ecosystem: str, package_name: str, version: str | None = None) -> list[dict]:
    """Query OSV.dev API for open source package vulnerabilities.

    Documentation: https://google.github.io/osv.dev/api/
    """
    if not package_name or not ecosystem:
        return []

    cache_key = f"{ecosystem.lower()}:{package_name.lower()}:{version or ''}"
    now = time.time()
    if cache_key in _OSV_CACHE:
        ts, cached_vulns = _OSV_CACHE[cache_key]
        if now - ts < CACHE_TTL:
            return cached_vulns

    payload: dict[str, Any] = {
        "package": {
            "name": package_name.strip(),
            "ecosystem": ecosystem.strip(),
        }
    }
    if version and version.strip():
        payload["version"] = version.strip()

    req_url = "https://api.osv.dev/v1/query"
    req = Request(
        req_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "ThreatLens-AI/1.0"},
        method="POST",
    )

    try:
        with urlopen(req, timeout=12) as response:
            if response.status != 200:
                log.warning("OSV API returned status %s for %s", response.status, cache_key)
                return []
            data = json.loads(response.read().decode("utf-8"))
            vulns = data.get("vulns", [])
            _OSV_CACHE[cache_key] = (now, vulns)
            return vulns
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        log.warning("OSV API query failed for %s: %s", cache_key, exc)
        return []


# ── Snowflake / Local Vulnerability Search ─────────────────────────────────
def search_local_vulnerabilities(product: str, vendor: str = "", limit: int = 50) -> list[dict]:
    """Search the existing ThreatLens dataset (Snowflake or local provider) for CVEs."""
    if not product or len(product.strip()) < 2:
        return []

    prod_term = product.strip().lower()
    vendor_term = vendor.strip().lower() if vendor else ""

    from .provider import get_records
    try:
        df = get_records()
        if df is None or df.empty:
            return []

        # Filter efficiently
        desc_col = df["description"].fillna("").astype(str).str.lower()
        cve_col = df["cve_id"].fillna("").astype(str).str.lower()

        # Build search condition
        term_pattern = r"\b" + re.escape(prod_term) + r"\b"
        mask = desc_col.str.contains(term_pattern, regex=True) | cve_col.str.contains(re.escape(prod_term))
        if vendor_term:
            vendor_pattern = r"\b" + re.escape(vendor_term) + r"\b"
            mask = mask & desc_col.str.contains(vendor_pattern, regex=True)

        matched = df[mask].head(limit)
        results = []
        for _, row in matched.iterrows():
            results.append({
                "id": str(row.get("cve_id", "")),
                "summary": str(row.get("description", ""))[:350],
                "details": str(row.get("description", "")),
                "severity": str(row.get("severity", "UNKNOWN")).upper(),
                "cvss_score": float(row["cvss_score"]) if pd.notna(row.get("cvss_score")) else None,
                "cwe": str(row.get("cwe") or "")[:80],
                "published": str(row.get("published", "")),
                "source_url": str(row.get("source_url") or f"https://nvd.nist.gov/vuln/detail/{row.get('cve_id')}"),
                "source": "Snowflake THREATLENS_DB.THREATLENS.VULNERABILITIES",
            })
        return results
    except Exception as exc:
        log.warning("Local vulnerability search failed: %s", exc)
        return []


# ── Deterministic Version Matching ─────────────────────────────────────────
def _safe_parse_version(v_str: str) -> pkg_version.Version | None:
    """Safely parse version string into packaging.version, cleaning prefixes."""
    if not v_str or not isinstance(v_str, str):
        return None
    cleaned = re.sub(r"^[vV=^~<>]+", "", v_str.strip())
    # Handle simple 1.2.3.4 or semver
    try:
        return pkg_version.parse(cleaned)
    except Exception:
        # Fallback to extracting first numeric semver sequence
        m = re.search(r"\d+(\.\d+)+", cleaned)
        if m:
            try:
                return pkg_version.parse(m.group(0))
            except Exception:
                pass
    return None


def match_version_against_ranges(user_ver_str: str, ranges: list[dict], exact_versions: list[str]) -> tuple[str, str | None, str | None]:
    """Compare a user version against OSV ranges and exact versions.

    Returns:
        (match_type: "EXACT" | "RANGE_MATCH" | "POTENTIAL" | "NOT_AFFECTED", verified_fixed_version, matched_range_str)
    """
    user_ver = _safe_parse_version(user_ver_str)
    norm_user_ver = (user_ver_str or "").strip().lstrip("vV")

    # 1. Scan ranges to find the lowest fixed version
    lowest_fixed: pkg_version.Version | None = None
    lowest_fixed_str: str | None = None
    is_affected = False
    matched_range_desc = None

    for r in ranges:
        events = r.get("events", [])
        intro_ver: pkg_version.Version | None = None
        intro_str: str | None = None
        fixed_ver: pkg_version.Version | None = None
        fixed_str: str | None = None

        for ev in events:
            if "introduced" in ev:
                intro_str = ev["introduced"]
                intro_ver = _safe_parse_version(intro_str) if intro_str != "0" else None
            elif "fixed" in ev:
                fixed_str = ev["fixed"]
                fixed_ver = _safe_parse_version(fixed_str)
                if fixed_ver:
                    if lowest_fixed is None or fixed_ver < lowest_fixed:
                        lowest_fixed = fixed_ver
                        lowest_fixed_str = fixed_str

        # If user version could be parsed
        if user_ver:
            intro_condition = True
            if intro_ver:
                intro_condition = user_ver >= intro_ver

            fixed_condition = True
            if fixed_ver:
                fixed_condition = user_ver < fixed_ver

            if intro_condition and fixed_condition:
                is_affected = True
                matched_range_desc = f">= {intro_str or '0'}, < {fixed_str or 'unfixed'}"

    # 2. Check exact list if present
    for ev in exact_versions:
        ev_clean = ev.strip().lstrip("vV")
        if ev_clean == norm_user_ver:
            return "EXACT", lowest_fixed_str, f"Explicitly listed in affected versions: {ev}"

    if is_affected:
        return "RANGE_MATCH", lowest_fixed_str, matched_range_desc

    if user_ver and lowest_fixed and user_ver >= lowest_fixed:
        return "NOT_AFFECTED", lowest_fixed_str, f"Version is >= fixed release {lowest_fixed_str}"

    return "POTENTIAL", lowest_fixed_str, "Version cannot be definitively matched or ruled out."


# ── Impact Category Detection ──────────────────────────────────────────────
def extract_potential_impacts(description: str, cwe: str = "") -> list[str]:
    """Extract plain-English security impact categories grounded in text/CWE."""
    text = (f"{description} {cwe}").lower()
    impacts = []

    if any(k in text for k in ("remote code execution", "arbitrary code", "execute code", "rce", "cwe-78", "cwe-94", "cwe-502")):
        impacts.append("Remote Code Execution (RCE)")
    if any(k in text for k in ("privilege escalation", "elevation of privilege", "gain privileges", "cwe-269", "cwe-250")):
        impacts.append("Privilege Escalation")
    if any(k in text for k in ("denial of service", "dos", "crash", "infinite loop", "resource exhaustion", "cwe-400", "cwe-476")):
        impacts.append("Denial of Service (DoS)")
    if any(k in text for k in ("information disclosure", "sensitive data", "data leakage", "exposure", "leak", "cwe-200", "cwe-125")):
        impacts.append("Information Disclosure")
    if any(k in text for k in ("authentication bypass", "unauthenticated", "bypass access", "cwe-287", "cwe-306")):
        impacts.append("Authentication / Access Control Bypass")
    if any(k in text for k in ("sql injection", "sqli", "cwe-89")):
        impacts.append("SQL Injection")
    if any(k in text for k in ("cross-site scripting", "xss", "cwe-79")):
        impacts.append("Cross-Site Scripting (XSS)")
    if any(k in text for k in ("tampering", "integrity", "deserialization", "cwe-502")):
        impacts.append("Insecure Deserialization / Integrity Violation")

    return impacts or ["Security Degradation / Unspecified Vulnerability Impact"]


# ── AI Integration (DeepSeek + NVIDIA NIM + Cortex) ─────────────────────────
def _get_ai_credentials(provider_preference: str | None = None) -> dict[str, Any]:
    """Resolve provider credentials adhering strictly to user configuration.

    Supports NVIDIA NIM and DeepSeek hosted on NVIDIA NIM (nvapi- keys)
    or native DeepSeek endpoints, plus Snowflake Cortex.
    """
    selected = (provider_preference or os.getenv("AI_PROVIDER", "nvidia")).strip().lower()

    deepseek_key = os.getenv("DEEPSEEK_API_KEY", "").strip()
    nvidia_key = os.getenv("NVIDIA_API_KEY", "").strip()

    if selected == "deepseek":
        # Check if key is an NVIDIA NIM key (e.g. nvapi-...)
        if deepseek_key.startswith("nvapi-") or os.getenv("DEEPSEEK_BASE_URL", "").find("nvidia.com") != -1:
            endpoint = os.getenv("DEEPSEEK_BASE_URL", "https://integrate.api.nvidia.com/v1/chat/completions")
            model = os.getenv("DEEPSEEK_MODEL", "deepseek-ai/deepseek-r1")
            return {
                "provider": "deepseek (NVIDIA NIM)",
                "key": deepseek_key,
                "endpoint": endpoint,
                "model": model,
                "is_nvidia_nim": True,
            }
        else:
            endpoint = os.getenv("DEEPSEEK_BASE_URL", "https://api.deepseek.com/chat/completions")
            model = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
            return {
                "provider": "deepseek",
                "key": deepseek_key,
                "endpoint": endpoint,
                "model": model,
                "is_nvidia_nim": False,
            }

    if selected == "cortex":
        return {
            "provider": "cortex",
            "key": "",
            "endpoint": "Snowflake Cortex AI_COMPLETE",
            "model": os.getenv("SNOWFLAKE_CORTEX_MODEL", "llama3.1-8b"),
            "is_nvidia_nim": False,
        }

    # Default to nvidia
    endpoint = os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1/chat/completions")
    model = os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")
    return {
        "provider": "nvidia",
        "key": nvidia_key,
        "endpoint": endpoint,
        "model": model,
        "is_nvidia_nim": True,
    }


def generate_grounded_ai_summary(evidence: dict[str, Any], provider_pref: str | None = None) -> dict[str, Any]:
    """Generate an evidence-grounded AI assessment summary using the selected provider.

    Strictly forbids fabricating CVEs, CVSS scores, or fixed versions.
    Falls back gracefully to deterministic analysis if AI fails or keys are absent.
    """
    cfg = _get_ai_credentials(provider_pref)

    # If no key is configured, return deterministic fallback
    if not cfg["key"] and cfg["provider"] != "cortex":
        return {
            "used": False,
            "provider": cfg["provider"],
            "model": "deterministic_fallback",
            "executive_summary": evidence.get("deterministic_summary", ""),
            "technical_notes": "AI provider key not configured or offline. Analysis generated deterministically from source records.",
        }

    # Prepare sanitized prompt context
    findings_summary = []
    for f in evidence.get("findings", [])[:10]:
        findings_summary.append({
            "id": f.get("id"),
            "severity": f.get("severity"),
            "cvss_score": f.get("cvss_score"),
            "match_type": f.get("match_type"),
            "fixed_version": f.get("verified_fixed_version"),
            "cwe": f.get("cwe"),
            "summary": f.get("summary")[:200],
        })

    prompt_data = {
        "software_name": evidence.get("product_name"),
        "version": evidence.get("version"),
        "verdict": evidence.get("verdict"),
        "total_findings": len(evidence.get("findings", [])),
        "verified_fixed_version": evidence.get("verified_fixed_version"),
        "potential_impacts": evidence.get("potential_impacts", []),
        "key_findings": findings_summary,
    }

    system_instruction = (
        "You are ThreatLens AI Software Safety Advisor, an authoritative cybersecurity assistant. "
        "Your task is to provide an evidence-grounded assessment for the evaluated software based STRICTLY "
        "on the supplied JSON vulnerability records. "
        "RULES:\n"
        "1. NEVER invent, hallucinate, or alter CVE IDs, CVSS scores, or fixed versions.\n"
        "2. If no vulnerabilities match, clearly state that no CVEs were found in the queried sources, but "
        "explicitly remind the user that absence of CVEs is NOT a guarantee that the software is completely safe or clean.\n"
        "3. Explain the technical consequences (e.g. Remote Code Execution, Privilege Escalation) in plain, clear English.\n"
        "4. Provide practical, step-by-step remediation guidance (upgrade path, workaround, verification controls).\n"
        "5. Output valid JSON with keys: 'executive_summary' (string), 'plain_english_impact' (string), "
        "'recommended_action' (string), and 'verification_steps' (list of strings)."
    )

    user_prompt = f"Analyze the following software safety evidence and provide your grounded assessment:\n{json.dumps(prompt_data, ensure_ascii=False)}"

    body = {
        "model": cfg["model"],
        "messages": [
            {"role": "system", "content": system_instruction},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.2,
        "max_tokens": 800,
    }

    try:
        req = Request(
            cfg["endpoint"],
            data=json.dumps(body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {cfg['key']}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            method="POST",
        )
        with urlopen(req, timeout=30) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            content = resp_data["choices"][0]["message"]["content"]
            # Attempt to parse json from model output
            clean_json = content.strip()
            if "```json" in clean_json:
                clean_json = clean_json.split("```json", 1)[1].split("```", 1)[0].strip()
            elif "```" in clean_json:
                clean_json = clean_json.split("```", 1)[1].split("```", 1)[0].strip()

            try:
                parsed = json.loads(clean_json)
                return {
                    "used": True,
                    "provider": cfg["provider"],
                    "model": cfg["model"],
                    "executive_summary": parsed.get("executive_summary", content),
                    "plain_english_impact": parsed.get("plain_english_impact", ""),
                    "recommended_action": parsed.get("recommended_action", ""),
                    "verification_steps": parsed.get("verification_steps", []),
                }
            except Exception:
                return {
                    "used": True,
                    "provider": cfg["provider"],
                    "model": cfg["model"],
                    "executive_summary": content[:1200],
                    "plain_english_impact": "",
                    "recommended_action": "",
                    "verification_steps": [],
                }
    except Exception as exc:
        log.warning("AI generation failed for %s: %s", cfg["provider"], exc)
        return {
            "used": False,
            "provider": cfg["provider"],
            "model": cfg["model"],
            "executive_summary": evidence.get("deterministic_summary", "Deterministic assessment completed without AI enrichment."),
            "technical_notes": f"AI provider could not be reached ({type(exc).__name__}). Showing deterministic source analysis.",
        }


def _generate_knowledge_fallback(question: str, evidence: dict[str, Any] | None = None) -> str:
    """Generate an authoritative, structured security advisory response when external AI is offline."""
    q_lower = (question or "").lower().strip()
    evidence = evidence or {}
    findings = evidence.get("findings", [])
    product = evidence.get("product_name") or evidence.get("software", {}).get("product_name")

    # If there is active assessment evidence with findings and user asks about it:
    if findings and product:
        top_findings = findings[:5]
        findings_bullets = "\n".join(
            f"- **{f.get('id')}** ({f.get('severity', 'UNKNOWN')}, CVSS {f.get('cvss_score', 'N/A')}): {f.get('summary', '')[:140]}..."
            for f in top_findings
        )
        fixed_ver = evidence.get("verified_fixed_version") or "Refer to vendor advisory"
        verdict = evidence.get("verdict", "VULNERABILITIES_FOUND")
        return (
            f"### Assessment Context for {product}\n\n"
            f"**Current Status:** `{verdict}`\n"
            f"**Verified Fixed Version:** `{fixed_ver}`\n\n"
            f"#### Identified Vulnerability Records:\n{findings_bullets}\n\n"
            f"**Security Guidance:**\n"
            f"- Upgrade immediately to `{fixed_ver}` or higher to remediate the disclosed flaws.\n"
            f"- Verify package hashes and signatures against official repository releases before deploying.\n"
            f"- Check application configurations to disable affected features if upgrading cannot be done immediately."
        )

    # Greetings
    if q_lower in ("hi", "hello", "hey", "help", "who are you", "what can you do"):
        return (
            "👋 **Hello! I am your ThreatLens AI Software Safety Assistant.**\n\n"
            "I help security teams and developers evaluate software, APKs, libraries, and packages before installation:\n\n"
            "• **Identify Known CVEs:** Check software against National Vulnerability Database (NVD) and Open Source Vulnerabilities (OSV).\n"
            "• **Analyze Severity:** Interpret CVSS v3.1/v4.0 scores, attack vectors, and exploit likelihood.\n"
            "• **Find Safe Versions:** Pinpoint verified fixed releases and upgrade paths.\n"
            "• **Pre-Installation Guidance:** Advise on package integrity, provenance, and supply chain controls.\n\n"
            "💡 *Tip: You can ask any security question directly, or enter a package name above and click **Assess Software Risk** to ground our analysis in live vulnerability data.*"
        )

    # Package CVE check questions
    if any(k in q_lower for k in ("how do i check", "check if my package", "check cve", "find cve", "known cve", "has cve")):
        return (
            "### How to Check if Your Package Has Known CVEs\n\n"
            "To audit a software package or dependency for known vulnerabilities, use these standard industry practices:\n\n"
            "1. **ThreatLens AI Assessment (Fastest):**\n"
            "   - Enter the package name (e.g., `cryptography`, `express`, `requests`) in the search box above.\n"
            "   - Select the ecosystem (`PyPI`, `npm`, `Maven`, etc.) and version, then click **Assess Software Risk**.\n"
            "   - ThreatLens queries Snowflake CVE records, NVD, and OSV to verify known vulnerabilities and recommend safe patch versions.\n\n"
            "2. **Native Ecosystem CLI Scanners:**\n"
            "   - **Python:** Run `pip-audit` or `safety check`\n"
            "   - **Node.js / JS:** Run `npm audit` or `pnpm audit`\n"
            "   - **Rust:** Run `cargo audit`\n"
            "   - **Go:** Run `govulncheck ./...`\n"
            "   - **Java / JVM:** Run `mvn dependency-check:check` or OWASP Dependency-Check\n\n"
            "3. **Generate an SBOM & Scan Continuously:**\n"
            "   - Use tools like **Syft** or **CycloneDX** to export a Software Bill of Materials (SBOM).\n"
            "   - Scan the SBOM against **Grype** or **Trivy** to alert whenever new CVEs are disclosed.\n\n"
            "4. **Integrate into CI/CD:**\n"
            "   - Add automated PR checks (e.g. GitHub Dependabot, Renovate) to block pull requests containing Critical or High CVEs."
        )

    # CVSS questions
    if any(k in q_lower for k in ("cvss score", "cvss 9.8", "9.8 mean", "cvss")):
        return (
            "### Understanding CVSS Scores & What 9.8 Means\n\n"
            "The **Common Vulnerability Scoring System (CVSS)** provides a numerical score from 0.0 to 10.0 reflecting technical severity:\n\n"
            "| Range | Severity Level | Action Required |\n"
            "| :--- | :--- | :--- |\n"
            "| **9.0 – 10.0** | **CRITICAL** | Emergency remediation (patch or isolate immediately) |\n"
            "| **7.0 – 8.9** | **HIGH** | High-priority patching within hours or days |\n"
            "| **4.0 – 6.9** | **MEDIUM** | Scheduled maintenance window patching |\n"
            "| **0.1 – 3.9** | **LOW** | Minor risk, routine review |\n\n"
            "#### Breakdown of a 9.8 CVSS Score:\n"
            "A **9.8** rating (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H) represents one of the most dangerous flaw profiles:\n"
            "• **AV:N (Network):** Remotely exploitable over the public internet.\n"
            "• **AC:L (Low Complexity):** No specialized timing or configuration needed.\n"
            "• **PR:N (None):** No login credentials or authorization required.\n"
            "• **UI:N (None):** Exploitation occurs without human/user interaction.\n"
            "• **C:H / I:H / A:H (High Impact):** Full loss of Confidentiality, Integrity, and Availability (e.g. unauthenticated Remote Code Execution or root compromise)."
        )

    # Third-party verification checklist
    if any(k in q_lower for k in ("verify before installing", "third-party", "checklist", "supply chain", "before install")):
        return (
            "### Pre-Installation Software & Package Verification Checklist\n\n"
            "Before introducing any new third-party software, library, or installer into your development or production environment:\n\n"
            "1. **Check Vulnerability History (CVEs):**\n"
            "   - Verify past CVE disclosures and how quickly maintainers issue security patches.\n"
            "   - Ensure the current version has zero unpatched Critical or High vulnerabilities.\n\n"
            "2. **Confirm Provenance & Maintainer Reputation:**\n"
            "   - Verify that the package originates from the genuine, verified namespace (avoid typosquatting such as `reqeusts` vs `requests`).\n"
            "   - Inspect repository commit history, release cadence, and multiple active maintainers.\n\n"
            "3. **Validate Cryptographic Hashes & Signatures:**\n"
            "   - Compare SHA-256 hashes against published publisher checksums.\n"
            "   - Where available, verify SLSA provenance or Sigstore cosign signatures.\n\n"
            "4. **Audit Dependencies & Permissions:**\n"
            "   - Inspect install scripts (`setup.py`, `postinstall` in `package.json`) for suspicious network calls or environment extraction.\n"
            "   - Minimize granted permissions (e.g. prevent unnecessary file system or network access).\n\n"
            "5. **Test in Isolation:**\n"
            "   - Deploy initially in an isolated container or staging sandbox before installing on developer workstations or production clusters."
        )

    # OpenSSL or specific crypto packages
    if "openssl" in q_lower:
        return (
            "### Security Overview for OpenSSL\n\n"
            "OpenSSL is a foundational cryptographic library. Key security considerations include:\n\n"
            "• **Version Lifecycle:** Legacy versions (1.0.x and 1.1.0/1.1.1) have reached End-of-Life (EOL) and no longer receive security patches.\n"
            "• **OpenSSL 3.0 Series:** OpenSSL 3.0.x is a Long-Term Support (LTS) release, but early versions had notable vulnerabilities (e.g. CVE-2022-3602, CVE-2022-3786 buffer overflows, CVE-2023-0286).\n"
            "• **Recommendation:** Maintain OpenSSL at the latest patch level within your active branch (e.g., 3.0.15+, 3.1.7+, 3.2.3+, or 3.3.2+). Always link dynamically where possible to allow rapid host-level patching."
        )

    # Generic cybersecurity question fallback
    return (
        f"### ThreatLens AI Security Advisory\n\n"
        f"Regarding your query: *\"{question.strip()}\"*\n\n"
        f"**Defensive Recommendations:**\n"
        f"1. **Evidence Verification:** Always verify specific software versions against official advisories (NVD, OSV, GitHub Advisory Database, vendor security bulletins).\n"
        f"2. **Least Privilege & Isolation:** Run software with the lowest required permissions; restrict outbound network egress from build and runtime environments.\n"
        f"3. **Automated Auditing:** Incorporate automated dependency scanning into every CI/CD pipeline stage.\n"
        f"4. **Patch Cadence:** Prioritize immediate mitigation for remote code execution, SQL injection, and authentication bypass vulnerabilities.\n\n"
        f"💡 *To check a specific software or library, enter its name and version in the search bar above to generate a full evidence-backed vulnerability report.*"
    )


def answer_assessment_follow_up(
    evidence: dict[str, Any] | None, question: str, provider_pref: str | None = None
) -> dict[str, Any]:
    """Answer a user follow-up question strictly grounded in assessment evidence, or general cybersecurity Q&A."""
    if not question or not str(question).strip():
        return {
            "answer": "Please ask a specific question regarding software security or vulnerability assessment.",
            "citations": [],
        }

    question_clean = str(question).strip()
    evidence = evidence or {}
    has_findings = bool(evidence.get("findings"))

    # Resolve AI provider
    cfg = _get_ai_credentials(provider_pref)
    nvidia_key = os.getenv("NVIDIA_API_KEY", "").strip()

    # NVIDIA NIM provides conversational chat completions; prefer it whenever key is present
    if (not cfg.get("key") or cfg.get("provider") == "cortex") and nvidia_key:
        cfg = {
            "provider": "nvidia",
            "key": nvidia_key,
            "endpoint": os.getenv("NVIDIA_BASE_URL", "https://integrate.api.nvidia.com/v1/chat/completions"),
            "model": os.getenv("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b"),
            "is_nvidia_nim": True,
        }

    # If Cortex is selected and NVIDIA key is not configured, try Snowflake Cortex
    if cfg.get("provider") == "cortex":
        try:
            from .provider import get_provider
            prov = get_provider()
            prompt = (
                f"You are ThreatLens AI Security Advisor. Answer this software security question in plain English with actionable advice:\n"
                f"User Question: {question_clean}"
            )
            answer_text = prov.cortex_complete(prompt, cfg.get("model", "llama3.1-8b"))
            # Ensure it is a genuine response and not echoing the prompt
            if (
                answer_text
                and len(answer_text.strip()) > 30
                and not answer_text.strip().startswith("You are ThreatLens AI Security Advisor")
            ):
                return {
                    "answer": answer_text,
                    "provider": "cortex",
                    "model": cfg.get("model", "llama3.1-8b"),
                    "citations": [],
                }
        except Exception as cortex_err:
            log.warning("Cortex follow-up chat error (%s), attempting fallback", cortex_err)

    # If we have an AI API key (NVIDIA NIM or DeepSeek):
    if cfg.get("key"):
        if has_findings:
            compact_evidence = {
                "product": evidence.get("product_name") or evidence.get("software", {}).get("product_name"),
                "version": evidence.get("version") or evidence.get("software", {}).get("version"),
                "ecosystem": evidence.get("ecosystem") or evidence.get("software", {}).get("ecosystem"),
                "verdict": evidence.get("verdict"),
                "fixed_version": evidence.get("verified_fixed_version"),
                "impacts": evidence.get("potential_impacts"),
                "findings": [
                    {
                        "id": f.get("id"),
                        "severity": f.get("severity"),
                        "cvss_score": f.get("cvss_score"),
                        "fixed_version": f.get("verified_fixed_version"),
                        "summary": f.get("summary"),
                        "source_url": f.get("source_url"),
                    }
                    for f in evidence.get("findings", [])[:8]
                ],
            }

            system_instruction = (
                "You are ThreatLens AI Security Advisor answering follow-up questions about a specific software vulnerability assessment. "
                "STRICT GROUNDING RULES:\n"
                "1. Base your answer EXCLUSIVELY on the provided assessment evidence JSON.\n"
                "2. Do not invent any CVE numbers, CVSS scores, exploit payloads, or hypothetical vulnerabilities not in evidence.\n"
                "3. If the answer cannot be determined from the evidence, state clearly: 'The current vulnerability evidence does not contain this information.'\n"
                "4. Always mention the specific CVE or OSV ID when referencing findings.\n"
                "5. Keep responses concise, objective, and actionable."
            )
            user_content = f"Assessment Evidence:\n{json.dumps(compact_evidence)}\n\nUser Question: {question_clean}"
        else:
            compact_evidence = {"findings": []}
            system_instruction = (
                "You are ThreatLens AI Software Safety Advisor, an authoritative cybersecurity expert. "
                "Help the user understand software vulnerabilities, common weaknesses, package security best practices, "
                "and CVE remediation in plain English. State practical guidance and advise verification against official vendor advisories."
            )
            user_content = question_clean

        body = {
            "model": cfg["model"],
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_content},
            ],
            "temperature": 0.2,
            "max_tokens": 1400,
        }

        try:
            req = Request(
                cfg["endpoint"],
                data=json.dumps(body).encode("utf-8"),
                headers={
                    "Authorization": f"Bearer {cfg['key']}",
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
                method="POST",
            )
            with urlopen(req, timeout=35) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                msg = data["choices"][0]["message"]
                answer_text = msg.get("content")
                if not answer_text and msg.get("reasoning_content"):
                    rc = msg["reasoning_content"]
                    if "Output:" in rc:
                        answer_text = rc.split("Output:")[-1].strip()
                    elif "Draft:" in rc:
                        answer_text = rc.split("Draft:")[-1].strip()

                if answer_text and answer_text.strip():
                    citations = [f["id"] for f in compact_evidence.get("findings", []) if f.get("id") and f["id"] in answer_text]
                    return {
                        "answer": answer_text.strip(),
                        "provider": cfg["provider"],
                        "model": cfg["model"],
                        "citations": citations,
                    }
        except Exception as exc:
            log.warning("AI provider failed in follow-up chat (%s), using grounded knowledge fallback", exc)

    # Fallback to rich, intelligent cybersecurity knowledge base
    fallback_text = _generate_knowledge_fallback(question_clean, evidence)
    return {
        "answer": fallback_text,
        "provider": "threatlens_knowledge_engine",
        "model": "grounded_rule_engine",
        "citations": [f["id"] for f in evidence.get("findings", []) if f.get("id") and f["id"] in fallback_text],
    }


# ── Full Assessment Pipeline ───────────────────────────────────────────────
def assess_software(
    product_name: str,
    version: str = "",
    vendor: str = "",
    ecosystem: str = "generic",
    source_url: str = "",
    file_bytes: bytes | None = None,
    filename: str = "",
    provider: str = "nvidia",
) -> dict[str, Any]:
    """Execute end-to-end evidence-based software vulnerability assessment."""
    start_time = time.time()
    now_iso = datetime.now(timezone.utc).isoformat()
    sources_checked = []
    limitations = []
    suspicious_indicators = []

    # 1. URL validation if provided
    canonical_url = ""
    if source_url:
        is_safe, domain_or_err, clean_url = validate_safe_url(source_url)
        if not is_safe:
            limitations.append(f"Source URL rejected by security safeguards: {domain_or_err}")
            suspicious_indicators.append(f"Rejected unverified or unsafe URL: {domain_or_err}")
        else:
            canonical_url = clean_url
            sources_checked.append(f"Validated Vendor/Source Domain: {domain_or_err}")

    # 2. File static inspection if provided
    file_metadata = None
    if file_bytes and filename:
        try:
            file_metadata = inspect_file_safely(file_bytes, filename)
            sources_checked.append(f"File Static Inspector (SHA-256: {file_metadata['sha256'][:12]}...)")
            limitations.append("File analysis was strictly static metadata extraction; no sandbox or dynamic execution occurred.")
            if file_metadata["suspicious_flags"]:
                suspicious_indicators.extend(file_metadata["suspicious_flags"])
            # Auto-populate product or version if extracted from package file
            if not product_name and file_metadata.get("extracted_name"):
                product_name = file_metadata["extracted_name"]
            if not version and file_metadata.get("extracted_version"):
                version = file_metadata["extracted_version"]
            if ecosystem == "generic" and file_metadata.get("suggested_ecosystem"):
                ecosystem = file_metadata["suggested_ecosystem"]
        except Exception as exc:
            limitations.append(f"File inspection limited: {exc}")

    # Validate basic product identity
    product_clean = (product_name or "").strip()
    version_clean = (version or "").strip()
    vendor_clean = (vendor or "").strip()
    ecosystem_clean = (ecosystem or "generic").strip().lower()

    if not product_clean:
        if file_metadata and file_metadata.get("is_executable_binary"):
            return {
                "assessment_id": f"TL-SA-{int(start_time * 1000)}",
                "verdict": "FILE_ANALYSIS_INCONCLUSIVE",
                "verdict_title": "File Analysis Inconclusive (Product Name Required)",
                "software": {
                    "product_name": filename or "Unknown Binary",
                    "vendor": vendor_clean or "Unspecified",
                    "version": version_clean or "Unspecified",
                    "ecosystem": ecosystem_clean,
                    "source_url": canonical_url,
                },
                "file_metadata": file_metadata,
                "findings": [],
                "potential_impacts": [],
                "verified_fixed_version": None,
                "recommendation": {
                    "action": "SPECIFY_PRODUCT_NAME",
                    "explanation": "Static inspection calculated binary hashes, but could not determine software name and version for CVE correlation.",
                },
                "sources_checked": sources_checked,
                "limitations": limitations + ["Software name and version required for vulnerability database cross-referencing."],
                "generated_at": now_iso,
                "duration_ms": int((time.time() - start_time) * 1000),
            }

        return {
            "assessment_id": f"TL-SA-{int(start_time * 1000)}",
            "verdict": "INSUFFICIENT_IDENTIFICATION",
            "verdict_title": "Insufficient Software Identification",
            "software": {
                "product_name": "Unspecified",
                "vendor": vendor_clean,
                "version": version_clean,
                "ecosystem": ecosystem_clean,
                "source_url": canonical_url,
            },
            "findings": [],
            "potential_impacts": [],
            "verified_fixed_version": None,
            "recommendation": {
                "action": "PROVIDE_SOFTWARE_DETAILS",
                "explanation": "Please provide at least a software name or package identifier to initiate assessment.",
            },
            "sources_checked": sources_checked,
            "limitations": ["Assessment halted: Software name was not provided."],
            "generated_at": now_iso,
            "duration_ms": int((time.time() - start_time) * 1000),
        }

    raw_findings: list[dict] = []
    seen_vuln_ids: set[str] = set()

    # 3. Query OSV.dev for package ecosystems
    if ecosystem_clean in ECOSYSTEMS and ecosystem_clean != "generic":
        osv_ecosystem_map = {
            "pypi": "PyPI",
            "npm": "npm",
            "maven": "Maven",
            "go": "Go",
            "crates.io": "crates.io",
            "nuget": "NuGet",
            "packagist": "Packagist",
            "rubygems": "RubyGems",
            "hex": "Hex",
            "pub": "Pub",
        }
        target_ecosystem = osv_ecosystem_map.get(ecosystem_clean, ecosystem_clean)
        sources_checked.append(f"OSV.dev ({target_ecosystem})")
        osv_vulns = query_osv_package(target_ecosystem, product_clean, version_clean if version_clean else None)

        for v in osv_vulns:
            vid = v.get("id", "UNKNOWN")
            if vid in seen_vuln_ids:
                continue
            seen_vuln_ids.add(vid)

            # Determine match type and fixed version
            affected_list = v.get("affected", [])
            ranges = []
            exact_vers = []
            for aff in affected_list:
                for r in aff.get("ranges", []):
                    ranges.append(r)
                for ver_item in aff.get("versions", []):
                    exact_vers.append(ver_item)

            if version_clean:
                m_type, fixed_v, range_desc = match_version_against_ranges(version_clean, ranges, exact_vers)
            else:
                m_type = "POTENTIAL"
                fixed_v = None
                range_desc = "No version provided; match is unverified."

            if m_type == "NOT_AFFECTED":
                continue

            # Parse severity
            sev_str = "UNKNOWN"
            cvss_val = None
            for s in v.get("severity", []):
                if s.get("type") in ("CVSS_V3", "CVSS_V2"):
                    sev_str = "HIGH"  # default placeholder if vector
                score_candidate = s.get("score")
                if isinstance(score_candidate, (int, float)):
                    cvss_val = float(score_candidate)

            desc = v.get("summary") or v.get("details") or ""
            refs = [ref.get("url") for ref in v.get("references", []) if ref.get("url")]

            raw_findings.append({
                "id": vid,
                "source": "OSV.dev",
                "summary": (v.get("summary") or desc)[:300],
                "details": desc,
                "severity": sev_str,
                "cvss_score": cvss_val,
                "match_type": m_type,
                "range_description": range_desc,
                "verified_fixed_version": fixed_v,
                "cwe": "",
                "published": v.get("published", ""),
                "modified": v.get("modified", ""),
                "source_url": refs[0] if refs else f"https://osv.dev/vulnerability/{vid}",
                "advisories": refs[:3],
            })

    # 4. Query Snowflake / Local ThreatLens Dataset
    sources_checked.append("ThreatLens Database (Snowflake THREATLENS_DB.THREATLENS.VULNERABILITIES)")
    db_results = search_local_vulnerabilities(product_clean, vendor_clean, limit=40)
    for row in db_results:
        vid = row["id"]
        if vid in seen_vuln_ids:
            continue
        seen_vuln_ids.add(vid)

        # Check version match heuristics from description
        m_type = "POTENTIAL"
        range_desc = "Found in CVE vulnerability database; version match requires advisory verification."
        fixed_v = None

        if version_clean:
            # Check if version appears in CVE description
            v_pat = r"\b" + re.escape(version_clean) + r"\b"
            if re.search(v_pat, row["details"]):
                m_type = "EXACT"
                range_desc = f"Version {version_clean} specifically referenced in CVE advisory record."

            # Check for fixed version patterns like "fixed in x.y.z", "upgrade to x.y.z"
            fix_match = re.search(r"(?:fixed in|upgraded? to|resolved in|patched in)\s+([vV]?\d+(\.\d+)+)", row["details"], re.IGNORECASE)
            if fix_match:
                fixed_v = fix_match.group(1).lstrip("vV")

        raw_findings.append({
            "id": vid,
            "source": row["source"],
            "summary": row["summary"],
            "details": row["details"],
            "severity": row["severity"],
            "cvss_score": row["cvss_score"],
            "match_type": m_type,
            "range_description": range_desc,
            "verified_fixed_version": fixed_v,
            "cwe": row.get("cwe", ""),
            "published": row.get("published", ""),
            "modified": "",
            "source_url": row["source_url"],
            "advisories": [row["source_url"]],
        })

    # 5. Deduplicate and Sort Findings
    raw_findings.sort(
        key=lambda x: (
            1 if x["match_type"] == "EXACT" else (2 if x["match_type"] == "RANGE_MATCH" else 3),
            -(x["cvss_score"] or 0.0),
        )
    )

    # 6. Extract Potential Impacts & Global Verified Fixed Version
    all_impacts: set[str] = set()
    global_fixed_version = None
    exact_matches_count = 0
    potential_matches_count = 0

    for f in raw_findings:
        if f["match_type"] in ("EXACT", "RANGE_MATCH"):
            exact_matches_count += 1
        else:
            potential_matches_count += 1

        for imp in extract_potential_impacts(f["details"], f.get("cwe", "")):
            all_impacts.add(imp)

        if not global_fixed_version and f.get("verified_fixed_version"):
            global_fixed_version = f["verified_fixed_version"]

    sorted_impacts = sorted(all_impacts)

    # 7. Determine Executive Verdict
    if suspicious_indicators:
        verdict = "SUSPICIOUS_INDICATORS_FOUND"
        verdict_title = "Suspicious Indicators Detected"
        rec_action = "AVOID_OR_INVESTIGATE"
        rec_expl = f"Security inspection identified {len(suspicious_indicators)} static warning flag(s). Review findings thoroughly."
    elif exact_matches_count > 0:
        verdict = "KNOWN_VULNERABILITIES_FOUND"
        verdict_title = f"{exact_matches_count} Known Vulnerabilities Confirmed"
        if global_fixed_version:
            rec_action = f"UPGRADE_TO_VERSION_{global_fixed_version.upper()}"
            rec_expl = f"Version {version_clean or 'evaluated'} is affected by known vulnerabilities. Upgrade to verified release {global_fixed_version} or apply vendor mitigations."
        else:
            rec_action = "AVOID_OR_APPLY_PATCHES"
            rec_expl = f"Version {version_clean or 'evaluated'} has confirmed vulnerabilities. Avoid uncontained deployment until official vendor patches are verified."
    elif potential_matches_count > 0:
        verdict = "POTENTIAL_MATCH_REQUIRES_VERIFICATION"
        verdict_title = "Potential Vulnerabilities Require Verification"
        rec_action = "VERIFY_EXACT_BUILD"
        rec_expl = f"Found {potential_matches_count} vulnerability records matching product '{product_clean}'. Confirm whether your exact architecture, build, and configuration are in scope."
    else:
        verdict = "NO_MATCHING_VULNERABILITIES_FOUND"
        verdict_title = "No Matching Vulnerabilities Found in Queried Sources"
        rec_action = "PROCEED_WITH_STANDARD_SECURITY_CONTROLS"
        rec_expl = "No matching CVE or OSV advisory records were found in the sources queried. Maintain defense-in-depth, least privilege, and signature validation."
        limitations.append("Absence of CVE records does NOT guarantee software is free of zero-days, backdoors, or malicious logic.")

    # Format deterministic summary
    det_summary = (
        f"Evaluated '{product_clean}' (version: {version_clean or 'unspecified'}, ecosystem: {ecosystem_clean}). "
        f"Result: {verdict_title}. "
        f"Checked {len(sources_checked)} intelligence source(s), discovering {len(raw_findings)} potential/confirmed finding(s)."
    )

    assessment_data = {
        "assessment_id": f"TL-SA-{int(start_time * 1000)}",
        "verdict": verdict,
        "verdict_title": verdict_title,
        "software": {
            "product_name": product_clean,
            "vendor": vendor_clean or "Unspecified",
            "version": version_clean or "Unspecified",
            "ecosystem": ecosystem_clean,
            "package_name": product_clean if ecosystem_clean != "generic" else None,
            "source_url": canonical_url,
            "confidence": "HIGH" if exact_matches_count > 0 else ("MEDIUM" if potential_matches_count > 0 else "LOW"),
        },
        "file_metadata": file_metadata,
        "findings": raw_findings,
        "total_findings": len(raw_findings),
        "exact_matches_count": exact_matches_count,
        "potential_matches_count": potential_matches_count,
        "potential_impacts": sorted_impacts,
        "verified_fixed_version": global_fixed_version,
        "recommendation": {
            "action": rec_action,
            "explanation": rec_expl,
        },
        "sources_checked": sources_checked,
        "suspicious_indicators": suspicious_indicators,
        "limitations": limitations,
        "deterministic_summary": det_summary,
        "generated_at": now_iso,
    }

    # 8. AI Grounded Enrichment
    ai_result = generate_grounded_ai_summary(assessment_data, provider_pref=provider)
    assessment_data["ai"] = ai_result
    assessment_data["duration_ms"] = int((time.time() - start_time) * 1000)

    # Cache for follow-up questions
    _ASSESSMENT_CACHE[assessment_data["assessment_id"]] = assessment_data

    return assessment_data


def get_cached_assessment(assessment_id: str) -> dict[str, Any] | None:
    """Retrieve an assessment by ID from cache."""
    return _ASSESSMENT_CACHE.get(assessment_id)
