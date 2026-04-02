"""Shared fixtures and sample data for nvd-importer tests."""

# ── Sample NVD API v2.0 CVE objects (the inner "cve" dict) ───────────────

SAMPLE_NVD_CVE_FULL = {
    "id": "CVE-2024-1001",
    "published": "2024-01-15T10:30:00.000",
    "descriptions": [
        {"lang": "en", "value": "A vulnerability in the Linux kernel BPF subsystem allows local privilege escalation."},
    ],
    "metrics": {
        "cvssMetricV31": [
            {
                "cvssData": {
                    "baseScore": 7.8,
                    "baseSeverity": "HIGH",
                    "vectorString": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                }
            }
        ]
    },
    "weaknesses": [
        {
            "description": [
                {"lang": "en", "value": "CWE-416"},
            ]
        }
    ],
}

SAMPLE_NVD_CVE_V30 = {
    "id": "CVE-2023-5000",
    "published": "2023-06-01T00:00:00.000",
    "descriptions": [
        {"lang": "en", "value": "Use-after-free in Bluetooth L2CAP."},
    ],
    "metrics": {
        "cvssMetricV30": [
            {
                "cvssData": {
                    "baseScore": 5.5,
                    "baseSeverity": "MEDIUM",
                    "vectorString": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
                }
            }
        ]
    },
    "weaknesses": [],
}

SAMPLE_NVD_CVE_V2_ONLY = {
    "id": "CVE-2019-0001",
    "published": "2019-03-10T12:00:00.000",
    "descriptions": [
        {"lang": "en", "value": "Old kernel vulnerability with only CVSS v2."},
    ],
    "metrics": {
        "cvssMetricV2": [
            {
                "baseSeverity": "HIGH",
                "cvssData": {
                    "baseScore": 7.2,
                    "vectorString": "AV:L/AC:L/Au:N/C:C/I:C/A:C",
                },
            }
        ]
    },
    "weaknesses": [
        {
            "description": [
                {"lang": "en", "value": "NVD-CWE-noinfo"},
            ]
        }
    ],
}

SAMPLE_NVD_CVE_MINIMAL = {
    "id": "CVE-2024-9999",
    "descriptions": [],
    "metrics": {},
    "weaknesses": [],
}

# ── Sample NVD API paginated response wrapper ────────────────────────────

SAMPLE_NVD_PAGE_1 = {
    "resultsPerPage": 2,
    "startIndex": 0,
    "totalResults": 3,
    "vulnerabilities": [
        {"cve": SAMPLE_NVD_CVE_FULL},
        {"cve": SAMPLE_NVD_CVE_V30},
    ],
}

SAMPLE_NVD_PAGE_2 = {
    "resultsPerPage": 2,
    "startIndex": 2,
    "totalResults": 3,
    "vulnerabilities": [
        {"cve": SAMPLE_NVD_CVE_V2_ONLY},
    ],
}
