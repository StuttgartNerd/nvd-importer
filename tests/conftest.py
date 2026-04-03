"""Shared fixtures and sample data for nvd-importer tests."""

# ── Sample NVD API v2.0 CVE objects (the inner "cve" dict) ───────────────

SAMPLE_NVD_CVE_FULL = {
    "id": "CVE-2024-1001",
    "published": "2024-01-15T10:30:00.000",
    "lastModified": "2024-02-20T14:00:00.000",
    "vulnStatus": "Analyzed",
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
    "references": [
        {"url": "https://bugzilla.redhat.com/1234567", "source": "redhat", "tags": ["Issue Tracking"]},
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

# ── CVEs with references for fix commit extraction ──────────────────────

SAMPLE_NVD_CVE_WITH_PATCH_REF = {
    "id": "CVE-2013-1957",
    "published": "2013-04-24T19:55:01.000",
    "vulnStatus": "Analyzed",
    "descriptions": [
        {"lang": "en", "value": "The clone_mnt function in fs/namespace.c does not properly restrict changes."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {
            "url": "https://bugzilla.redhat.com/show_bug.cgi?id=921443",
            "source": "redhat",
            "tags": ["Issue Tracking"],
        },
        {
            "url": "https://github.com/torvalds/linux/commit/132c94e31b8bca8ea921f9f96a57d684fa4ae0a9",
            "source": "confirm",
            "tags": ["Patch"],
        },
    ],
}

SAMPLE_NVD_CVE_WITH_STABLE_REF = {
    "id": "CVE-2021-4000",
    "descriptions": [
        {"lang": "en", "value": "A stable-tree-only reference CVE."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {
            "url": "https://git.kernel.org/stable/c/abcdef1234567890abcdef1234567890abcdef12",
            "source": "kernel.org",
            "tags": [],
        },
    ],
}

SAMPLE_NVD_CVE_WITH_SHORT_HASH = {
    "id": "CVE-2015-0001",
    "descriptions": [
        {"lang": "en", "value": "A CVE with an abbreviated commit hash."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {
            "url": "https://github.com/torvalds/linux/commit/132c94e",
            "source": "confirm",
            "tags": ["Patch"],
        },
    ],
}

SAMPLE_NVD_CVE_WITH_MIXED_REFS = {
    "id": "CVE-2022-5000",
    "descriptions": [
        {"lang": "en", "value": "CVE with both mainline and stable refs."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {
            "url": "https://git.kernel.org/stable/c/1111111111111111111111111111111111111111",
            "source": "kernel.org",
            "tags": ["Patch"],
        },
        {
            "url": "https://github.com/torvalds/linux/commit/2222222222222222222222222222222222222222",
            "source": "confirm",
            "tags": ["Patch"],
        },
        {
            "url": "https://git.kernel.org/stable/c/3333333333333333333333333333333333333333",
            "source": "kernel.org",
            "tags": ["Patch"],
        },
    ],
}

SAMPLE_NVD_CVE_WITH_NO_KERNEL_REFS = {
    "id": "CVE-2020-9999",
    "descriptions": [
        {"lang": "en", "value": "CVE with only non-kernel references."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {"url": "https://bugzilla.redhat.com/1234567", "source": "redhat", "tags": ["Issue Tracking"]},
        {"url": "https://www.openwall.com/lists/oss-security/2020/01/01/1", "source": "oss-security", "tags": ["Mailing List"]},
    ],
}

SAMPLE_NVD_CVE_WITH_CISA = {
    "id": "CVE-2024-1086",
    "published": "2024-01-31T00:00:00.000",
    "vulnStatus": "Analyzed",
    "cisaExploitAdd": "2024-05-30",
    "cisaActionDue": "2024-06-20",
    "cisaRequiredAction": "Apply mitigations per vendor instructions or discontinue use of the product.",
    "descriptions": [
        {"lang": "en", "value": "Use-after-free in nf_tables component of Linux kernel."},
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
        {"description": [{"lang": "en", "value": "CWE-416"}]},
    ],
    "references": [
        {
            "url": "https://github.com/torvalds/linux/commit/f342de4e2f33e0e39165d8571571f4c659e25e85",
            "source": "confirm",
            "tags": ["Patch"],
        },
    ],
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
