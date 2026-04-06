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
        {"lang": "en", "value": "A CVE with a very short (7-char) commit hash."},
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

SAMPLE_NVD_CVE_WITH_12CHAR_HASH = {
    "id": "CVE-2023-6200",
    "descriptions": [
        {"lang": "en", "value": "A CVE with a 12-char abbreviated commit hash."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {
            "url": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dade3f6a1e4e",
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

# ── CVEs with URL patterns that were previously unmatched ──────────────────

SAMPLE_NVD_CVE_WITH_ENCODED_URL = {
    "id": "CVE-2011-1598",
    "descriptions": [
        {"lang": "en", "value": "bcm_release in net/can/bcm.c allows denial of service."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {
            "url": "http://git.kernel.org/?p=linux/kernel/git/torvalds/linux-2.6.git%3Ba=commit%3Bh=c6914a6f261aca0c9f715f883a353ae7ff51fe83",
            "source": "confirm",
            "tags": ["Patch"],
        },
    ],
}

SAMPLE_NVD_CVE_WITH_SUBTREE_URL = {
    "id": "CVE-2017-5897",
    "descriptions": [
        {"lang": "en", "value": "ip6gre_err in net/ipv6/ip6_gre.c allows out-of-bounds access."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {
            "url": "https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git/commit/?id=7892032cfe67f4bde6fc2ee967e45a8fbaf33756",
            "source": "confirm",
            "tags": ["Patch"],
        },
    ],
}

SAMPLE_NVD_CVE_WITH_CGIT_URL = {
    "id": "CVE-2024-25739",
    "descriptions": [
        {"lang": "en", "value": "create_empty_lvol in ubi allows crash via crafted UBI image."},
    ],
    "metrics": {},
    "weaknesses": [],
    "references": [
        {
            "url": "https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=68a24aba7c593eafa8fd00f2f76407b9b32b47a9",
            "source": "confirm",
            "tags": ["Patch"],
        },
    ],
}

SAMPLE_NVD_CVE_NVIDIA_WITH_CPE = {
    "id": "CVE-2022-34674",
    "descriptions": [
        {"lang": "en", "value": "NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer handler."},
    ],
    "metrics": {},
    "weaknesses": [],
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                        },
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:nvidia:gpu_display_driver:*:*:*:*:*:linux:*:*",
                        },
                    ],
                }
            ]
        }
    ],
}

# ── CVEs for CPE-based filtering ─────────────────────────────────────────

SAMPLE_NVD_CVE_WITH_KERNEL_CPE = {
    "id": "CVE-2024-5555",
    "descriptions": [
        {"lang": "en", "value": "A vulnerability in the Linux kernel netfilter subsystem."},
    ],
    "metrics": {},
    "weaknesses": [],
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "6.8",
                        }
                    ],
                }
            ]
        }
    ],
}

SAMPLE_NVD_CVE_WITH_NON_KERNEL_CPE = {
    "id": "CVE-2026-31890",
    "descriptions": [
        {"lang": "en", "value": "Inspektor Gadget is a set of tools for data collection on Kubernetes clusters and Linux hosts using eBPF."},
    ],
    "metrics": {},
    "weaknesses": [],
    "configurations": [
        {
            "nodes": [
                {
                    "operator": "OR",
                    "negate": False,
                    "cpeMatch": [
                        {
                            "vulnerable": True,
                            "criteria": "cpe:2.3:a:linuxfoundation:inspektor_gadget:*:*:*:*:*:*:*:*",
                            "versionEndExcluding": "0.50.1",
                        }
                    ],
                }
            ]
        }
    ],
}

SAMPLE_NVD_CVE_NO_CPE = {
    "id": "CVE-2010-0001",
    "descriptions": [
        {"lang": "en", "value": "Buffer overflow in the Linux kernel allows local users to gain privileges."},
    ],
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
