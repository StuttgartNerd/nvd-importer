"""Tests for nvd_importer.transformer."""

from nvd_importer.transformer import (
    _extract_fix_commit,
    _extract_references,
    build_ingest_payload,
    is_linux_kernel_cve,
    transform_batch,
    transform_cve,
)
from tests.conftest import (
    SAMPLE_NVD_CVE_FULL,
    SAMPLE_NVD_CVE_MINIMAL,
    SAMPLE_NVD_CVE_NO_CPE,
    SAMPLE_NVD_CVE_V2_ONLY,
    SAMPLE_NVD_CVE_V30,
    SAMPLE_NVD_CVE_WITH_CGIT_URL,
    SAMPLE_NVD_CVE_WITH_CISA,
    SAMPLE_NVD_CVE_WITH_ENCODED_URL,
    SAMPLE_NVD_CVE_WITH_KERNEL_CPE,
    SAMPLE_NVD_CVE_WITH_MIXED_REFS,
    SAMPLE_NVD_CVE_WITH_NO_KERNEL_REFS,
    SAMPLE_NVD_CVE_WITH_NON_KERNEL_CPE,
    SAMPLE_NVD_CVE_WITH_PATCH_REF,
    SAMPLE_NVD_CVE_WITH_SHORT_HASH,
    SAMPLE_NVD_CVE_WITH_STABLE_REF,
    SAMPLE_NVD_CVE_WITH_SUBTREE_URL,
    SAMPLE_NVD_CVE_WITH_12CHAR_HASH,
    SAMPLE_NVD_CVE_NVIDIA_WITH_CPE,
    SAMPLE_NVD_CVE_WITH_LINUS_SHORTHAND,
    SAMPLE_NVD_CVE_WITH_BRANCH_QUALIFIED_URL,
    SAMPLE_NVD_CVE_WITH_SUBPATH_URL,
    SAMPLE_NVD_CVE_WITH_PATCH_URL,
    SAMPLE_NVD_CVE_WITH_TORVALDS_C_SHORTHAND,
    SAMPLE_NVD_CVE_WITH_STABLE_BRANCH_URL,
    SAMPLE_NVD_CVE_WITH_BPF_SHORTHAND,
)


class TestTransformCve:
    def test_full_cve(self):
        result = transform_cve(SAMPLE_NVD_CVE_FULL)
        assert result["id"] == "CVE-2024-1001"
        assert "BPF subsystem" in result["description"]
        assert result["published_at"] == "2024-01-15T10:30:00Z"
        assert result["cvss_score"] == 7.8
        assert result["cvss_severity"] == "HIGH"
        assert result["cvss_vector"] == "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
        assert result["cwe_id"] == "CWE-416"
        assert result["introduced_in"] is None
        assert result["fixed_in"] == []
        # No kernel git refs in SAMPLE_NVD_CVE_FULL → no fix_commit key
        assert "fix_commit" not in result

    def test_full_cve_nvd_metadata(self):
        result = transform_cve(SAMPLE_NVD_CVE_FULL)
        assert result["nvd_status"] == "Analyzed"
        assert result["nvd_last_modified"] == "2024-02-20T14:00:00Z"

    def test_full_cve_references(self):
        result = transform_cve(SAMPLE_NVD_CVE_FULL)
        assert len(result["references"]) == 1
        assert result["references"][0]["url"] == "https://bugzilla.redhat.com/1234567"
        assert result["references"][0]["tags"] == ["Issue Tracking"]

    def test_cvss_v30_fallback(self):
        result = transform_cve(SAMPLE_NVD_CVE_V30)
        assert result["cvss_score"] == 5.5
        assert result["cvss_severity"] == "MEDIUM"
        assert result["cvss_vector"].startswith("CVSS:3.0/")

    def test_cvss_v2_fallback(self):
        result = transform_cve(SAMPLE_NVD_CVE_V2_ONLY)
        assert result["cvss_score"] == 7.2
        assert result["cvss_severity"] == "HIGH"
        assert result["cvss_vector"] == "AV:L/AC:L/Au:N/C:C/I:C/A:C"

    def test_placeholder_cwe_skipped(self):
        """NVD-CWE-noinfo and NVD-CWE-Other should be treated as no CWE."""
        result = transform_cve(SAMPLE_NVD_CVE_V2_ONLY)
        assert result["cwe_id"] is None

    def test_minimal_cve(self):
        result = transform_cve(SAMPLE_NVD_CVE_MINIMAL)
        assert result["id"] == "CVE-2024-9999"
        assert result["description"] is None
        assert result["published_at"] is None
        assert result["cvss_score"] is None
        assert result["cvss_severity"] is None
        assert result["cvss_vector"] is None
        assert result["cwe_id"] is None
        assert result["references"] == []
        assert result["nvd_status"] is None
        assert result["nvd_last_modified"] is None
        assert result["cisa_exploit_add"] is None
        assert result["cisa_action_due"] is None
        assert result["cisa_required_action"] is None

    def test_date_with_timezone_preserved(self):
        cve = {**SAMPLE_NVD_CVE_MINIMAL, "published": "2024-01-01T00:00:00+05:00"}
        result = transform_cve(cve)
        assert result["published_at"] == "2024-01-01T00:00:00+05:00"

    def test_date_already_has_z(self):
        cve = {**SAMPLE_NVD_CVE_MINIMAL, "published": "2024-01-01T00:00:00Z"}
        result = transform_cve(cve)
        assert result["published_at"] == "2024-01-01T00:00:00Z"

    def test_non_english_fallback(self):
        cve = {
            **SAMPLE_NVD_CVE_MINIMAL,
            "descriptions": [{"lang": "es", "value": "Vulnerabilidad en el kernel."}],
        }
        result = transform_cve(cve)
        assert result["description"] == "Vulnerabilidad en el kernel."

    def test_multiple_weaknesses_picks_first_valid(self):
        cve = {
            **SAMPLE_NVD_CVE_MINIMAL,
            "weaknesses": [
                {"description": [{"lang": "en", "value": "NVD-CWE-Other"}]},
                {"description": [{"lang": "en", "value": "CWE-787"}]},
            ],
        }
        result = transform_cve(cve)
        assert result["cwe_id"] == "CWE-787"


class TestTransformBatch:
    def test_batch(self):
        results = transform_batch([SAMPLE_NVD_CVE_FULL, SAMPLE_NVD_CVE_V30])
        assert len(results) == 2
        assert results[0]["id"] == "CVE-2024-1001"
        assert results[1]["id"] == "CVE-2023-5000"

    def test_empty_batch(self):
        assert transform_batch([]) == []


class TestBuildIngestPayload:
    def test_wraps_cves(self):
        cves = [{"id": "CVE-1"}]
        payload = build_ingest_payload(cves)
        assert payload["source"] == "nvd"
        assert payload["cves"] == cves

    def test_custom_source(self):
        payload = build_ingest_payload([], source="manual")
        assert payload["source"] == "manual"


class TestExtractFixCommit:
    def test_patch_tagged_mainline(self):
        """Mainline commit tagged as Patch is extracted."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_PATCH_REF)
        assert result["fix_commit"] == "132c94e31b8bca8ea921f9f96a57d684fa4ae0a9"

    def test_mainline_preferred_over_stable(self):
        """When both mainline and stable are patch-tagged, mainline wins."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_MIXED_REFS)
        assert result["fix_commit"] == "2222222222222222222222222222222222222222"

    def test_untagged_stable_fallback(self):
        """Stable ref without Patch tag is still extracted."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_STABLE_REF)
        assert result["fix_commit"] == "abcdef1234567890abcdef1234567890abcdef12"

    def test_very_short_hash_ignored(self):
        """Very short hashes (< 12 chars) are not returned."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_SHORT_HASH)
        assert "fix_commit" not in result

    def test_12char_hash_accepted(self):
        """12+ char abbreviated hashes are now accepted."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_12CHAR_HASH)
        assert result["fix_commit"] == "dade3f6a1e4e"

    def test_url_encoded_git_url(self):
        """Old-style URL-encoded git.kernel.org URLs (%3B) are decoded and matched."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_ENCODED_URL)
        assert result["fix_commit"] == "c6914a6f261aca0c9f715f883a353ae7ff51fe83"

    def test_subtree_git_url(self):
        """Subtree URLs (davem/net.git, netdev, bpf) are matched."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_SUBTREE_URL)
        assert result["fix_commit"] == "7892032cfe67f4bde6fc2ee967e45a8fbaf33756"

    def test_cgit_url(self):
        """cgit-path URLs (git.kernel.org/cgit/...) are matched."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_CGIT_URL)
        assert result["fix_commit"] == "68a24aba7c593eafa8fd00f2f76407b9b32b47a9"

    def test_full_hash_preferred_over_short(self):
        """When both full and short hashes exist, full hash wins."""
        refs = [
            {"url": "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=dade3f6a1e4e", "tags": ["Patch"]},
            {"url": "https://github.com/torvalds/linux/commit/aaaa" + "b" * 36, "tags": ["Patch"]},
        ]
        result = _extract_fix_commit(refs)
        assert result == "aaaa" + "b" * 36

    def test_mainline_preferred_over_subsystem(self):
        """When both mainline and subsystem refs exist, mainline wins."""
        refs = [
            {"url": "https://git.kernel.org/pub/scm/linux/kernel/git/davem/net.git/commit/?id=" + "a" * 40, "tags": ["Patch"]},
            {"url": "https://github.com/torvalds/linux/commit/" + "b" * 40, "tags": ["Patch"]},
        ]
        result = _extract_fix_commit(refs)
        assert result == "b" * 40

    def test_no_kernel_refs_returns_none(self):
        """Non-kernel URLs yield no fix_commit."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_NO_KERNEL_REFS)
        assert "fix_commit" not in result

    def test_no_refs_returns_none(self):
        """Missing references key yields no fix_commit."""
        result = transform_cve(SAMPLE_NVD_CVE_MINIMAL)
        assert "fix_commit" not in result

    def test_fix_commit_key_absent_when_no_match(self):
        """The fix_commit key should be absent (not None) when no match found."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_NO_KERNEL_REFS)
        assert "fix_commit" not in result

    def test_direct_extract_fix_commit(self):
        """Test _extract_fix_commit directly with reference list."""
        refs = [
            {"url": "https://github.com/torvalds/linux/commit/aaaa" + "b" * 36, "tags": ["Patch"]},
        ]
        assert _extract_fix_commit(refs) == "aaaa" + "b" * 36

    def test_direct_extract_fix_commit_empty(self):
        assert _extract_fix_commit([]) is None

    def test_linus_shorthand_url(self):
        """git.kernel.org/linus/{hash} shorthand is matched as mainline."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_LINUS_SHORTHAND)
        assert result["fix_commit"] == "42d84c8490f9f0931786f1623191fcab397c3d64"

    def test_branch_qualified_url(self):
        """commit/?h=branch&id=HASH is matched despite the ?h= parameter."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_BRANCH_QUALIFIED_URL)
        assert result["fix_commit"] == "f94b47c6bde624d6c07f43054087607c52054a95"

    def test_subpath_url(self):
        """commit/fs/ksmbd?id=HASH with subpath between commit/ and ?id= is matched."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_SUBPATH_URL)
        assert result["fix_commit"] == "02f76c401d17e409ed45bf7887148fcc22c93c85"

    def test_patch_url(self):
        """patch/?id=HASH is matched alongside commit/?id=."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_PATCH_URL)
        assert result["fix_commit"] == "6788ba8aed4e28e90f72d68a9d794e34eac17295"

    def test_torvalds_c_shorthand(self):
        """git.kernel.org/torvalds/c/{hash} shorthand is matched as mainline."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_TORVALDS_C_SHORTHAND)
        assert result["fix_commit"] == "3bb2a01caa813d3a1845d378bbe4169ef280b4a6"

    def test_stable_branch_qualified_url(self):
        """Stable tree commit/?h=linux-5.10.y&id=HASH is matched."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_STABLE_BRANCH_URL)
        assert result["fix_commit"] == "75454b4bbfc7e6a4dd8338556f36ea9107ddf61a"

    def test_bpf_shorthand_url(self):
        """git.kernel.org/bpf/bpf/c/{hash} shorthand is matched as subsystem."""
        result = transform_cve(SAMPLE_NVD_CVE_WITH_BPF_SHORTHAND)
        assert result["fix_commit"] == "abc123def456abc123def456abc123def456abc1"


class TestExtractReferences:
    def test_normal_extraction(self):
        refs = _extract_references(SAMPLE_NVD_CVE_WITH_PATCH_REF)
        assert len(refs) == 2
        assert refs[0]["url"] == "https://bugzilla.redhat.com/show_bug.cgi?id=921443"
        assert refs[0]["tags"] == ["Issue Tracking"]
        assert refs[1]["tags"] == ["Patch"]

    def test_empty_refs(self):
        refs = _extract_references({"references": []})
        assert refs == []

    def test_missing_key(self):
        refs = _extract_references({})
        assert refs == []

    def test_source_field_stripped(self):
        """The NVD 'source' field should not be in the output."""
        refs = _extract_references(SAMPLE_NVD_CVE_WITH_PATCH_REF)
        for ref in refs:
            assert "source" not in ref


class TestCisaFields:
    def test_cisa_fields_present(self):
        result = transform_cve(SAMPLE_NVD_CVE_WITH_CISA)
        assert result["cisa_exploit_add"] == "2024-05-30"
        assert result["cisa_action_due"] == "2024-06-20"
        assert result["cisa_required_action"].startswith("Apply mitigations")

    def test_cisa_fields_absent(self):
        result = transform_cve(SAMPLE_NVD_CVE_MINIMAL)
        assert result["cisa_exploit_add"] is None
        assert result["cisa_action_due"] is None
        assert result["cisa_required_action"] is None

    def test_cisa_cve_also_has_fix_commit(self):
        result = transform_cve(SAMPLE_NVD_CVE_WITH_CISA)
        assert result["fix_commit"] == "f342de4e2f33e0e39165d8571571f4c659e25e85"


class TestNvdMetadata:
    def test_vuln_status(self):
        result = transform_cve(SAMPLE_NVD_CVE_WITH_PATCH_REF)
        assert result["nvd_status"] == "Analyzed"

    def test_vuln_status_absent(self):
        result = transform_cve(SAMPLE_NVD_CVE_MINIMAL)
        assert result["nvd_status"] is None

    def test_last_modified(self):
        result = transform_cve(SAMPLE_NVD_CVE_FULL)
        assert result["nvd_last_modified"] == "2024-02-20T14:00:00Z"

    def test_last_modified_absent(self):
        result = transform_cve(SAMPLE_NVD_CVE_MINIMAL)
        assert result["nvd_last_modified"] is None


class TestIsLinuxKernelCve:
    def test_kernel_cpe_accepted(self):
        assert is_linux_kernel_cve(SAMPLE_NVD_CVE_WITH_KERNEL_CPE) is True

    def test_non_kernel_cpe_rejected(self):
        """CVE with CPE for a non-kernel product (e.g. Inspektor Gadget) is rejected."""
        assert is_linux_kernel_cve(SAMPLE_NVD_CVE_WITH_NON_KERNEL_CPE) is False

    def test_no_cpe_falls_back_to_description(self):
        """Old CVEs without CPE data are kept (description heuristic)."""
        assert is_linux_kernel_cve(SAMPLE_NVD_CVE_NO_CPE) is True

    def test_no_cpe_nvidia_rejected(self):
        """CVE without CPE but NVIDIA description is still rejected."""
        cve = {**SAMPLE_NVD_CVE_NO_CPE, "descriptions": [
            {"lang": "en", "value": "NVIDIA GPU driver vulnerability in kernel module."},
        ]}
        assert is_linux_kernel_cve(cve) is False

    def test_batch_filters_non_kernel(self):
        """transform_batch with filter=True drops non-kernel CPE CVEs."""
        batch = [SAMPLE_NVD_CVE_WITH_KERNEL_CPE, SAMPLE_NVD_CVE_WITH_NON_KERNEL_CPE]
        results = transform_batch(batch, filter_linux=True)
        assert len(results) == 1
        assert results[0]["id"] == "CVE-2024-5555"

    def test_nvidia_gpu_driver_rejected_by_description(self):
        """NVIDIA GPU Display Driver CVEs without CPE are rejected."""
        cve = {
            **SAMPLE_NVD_CVE_NO_CPE,
            "descriptions": [
                {"lang": "en", "value": "NVIDIA GPU Display Driver for Linux contains a vulnerability in the kernel mode layer."},
            ],
        }
        assert is_linux_kernel_cve(cve) is False

    def test_nvidia_with_kernel_cpe_still_accepted(self):
        """NVIDIA CVEs that also have linux_kernel CPE are accepted (CPE is authoritative)."""
        assert is_linux_kernel_cve(SAMPLE_NVD_CVE_NVIDIA_WITH_CPE) is True
