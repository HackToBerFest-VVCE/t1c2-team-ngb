"""Curated public dataset and project-template catalog.

Entries describe discovery targets; they do not imply that a source is connected
or that a Marketplace listing is installed in the current Snowflake account.
"""

DATASETS = [
    {
        "id": "nvd-cve",
        "name": "NIST National Vulnerability Database (NVD)",
        "category": "Vulnerability intelligence",
        "source_type": "Public API / NVD-origin Snowflake table",
        "license": "NVD data terms apply",
        "url": "https://nvd.nist.gov/developers/vulnerabilities",
        "connected_by_default": True,
        "description": "CVE records, CVSS assessments, weaknesses, affected products, and publication history.",
        "schema": ["cve_id", "description", "published", "cvss_score", "severity", "cwe", "affected_products"],
    },
    {
        "id": "hf-cvefixes",
        "name": "CVEfixes",
        "category": "Vulnerability remediation",
        "source_type": "Hugging Face public dataset",
        "license": "Apache-2.0 (review source card before reuse)",
        "url": "https://huggingface.co/datasets/hitoshura25/cvefixes",
        "connected_by_default": False,
        "description": "Vulnerability and fixing-commit examples for code-focused research and classification.",
        "schema": ["CVE", "repository", "commit", "file", "code_before", "code_after"],
    },
    {
        "id": "hf-cybersecurity-attacks",
        "name": "Cybersecurity Attacks",
        "category": "Intrusion detection",
        "source_type": "Hugging Face public dataset",
        "license": "Unlicense (review source card before reuse)",
        "url": "https://huggingface.co/datasets/vinitvek/cybersecurityattacks",
        "connected_by_default": False,
        "description": "Labeled cybersecurity event examples for task-specific attack-type classification.",
        "schema": ["timestamp", "source_ip", "destination_ip", "protocol", "attack_type"],
    },
    {
        "id": "snowflake-sample-data",
        "name": "Snowflake shared sample schemas",
        "category": "Warehouse exploration",
        "source_type": "Snowflake shared database",
        "license": "Snowflake sample-data terms",
        "url": "https://docs.snowflake.com/en/user-guide/sample-data-using",
        "connected_by_default": False,
        "description": "Account-dependent SNOWFLAKE_SAMPLE_DATA schemas such as TPC-H/TPC-DS; examples are not cybersecurity data.",
        "schema": ["SNOWFLAKE_SAMPLE_DATA.TPCH_SF1.*", "SNOWFLAKE_SAMPLE_DATA.TPCDS_SF10TCL.*"],
    },
    {
        "id": "snowflake-marketplace",
        "name": "Snowflake Data Marketplace",
        "category": "Marketplace discovery",
        "source_type": "Account-specific listings",
        "license": "Listing-specific; inspect provider terms",
        "url": "https://marketplace.snowflake.com/",
        "connected_by_default": False,
        "description": "Search public listings and review the provider data dictionary. Availability, trials, and install permissions vary by account.",
        "schema": ["Listing-provided objects vary by provider"],
    },
]

TEMPLATES = [
    {
        "id": "vulnerability-prioritization",
        "name": "Vulnerability Prioritization",
        "description": "Rank source-scored CVEs for analyst review using CVSS and verified asset context.",
        "datasets": ["nvd-cve"],
        "metrics": ["source CVSS coverage", "severity distribution", "reviewed remediation backlog"],
        "guardrail": "CVSS is severity; asset exposure and exploitation must be independently verified.",
    },
    {
        "id": "code-flaw-classifier",
        "name": "Code Flaw Classifier",
        "description": "Evaluate a code weakness classifier against grouped, held-out vulnerability examples.",
        "datasets": ["hf-cvefixes"],
        "metrics": ["macro F1", "per-class recall", "grouped holdout leakage check"],
        "guardrail": "Keep repositories/CVEs grouped across splits and review dataset licensing.",
    },
    {
        "id": "intrusion-detection",
        "name": "Intrusion Detection",
        "description": "Train and evaluate a task-specific classifier on labeled network-security events.",
        "datasets": ["hf-cybersecurity-attacks"],
        "metrics": ["macro F1", "false-positive rate", "per-class recall"],
        "guardrail": "Dataset labels are not live threat detections; validate on operational telemetry before use.",
    },
]


def project_catalog() -> dict:
    return {"datasets": DATASETS, "templates": TEMPLATES}
