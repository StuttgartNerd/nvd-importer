"""Tests for nvd_importer.cli."""

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from nvd_importer.cli import main
from tests.conftest import SAMPLE_NVD_CVE_FULL, SAMPLE_NVD_PAGE_1


class TestCliOutput:
    def test_stdout_output(self, capsys, tmp_path):
        """With --input and no --output or --post, writes JSON to stdout."""
        # Create an NVD-format input file
        input_file = tmp_path / "nvd.json"
        input_file.write_text(json.dumps({
            "vulnerabilities": [{"cve": SAMPLE_NVD_CVE_FULL}]
        }))

        with patch("sys.argv", ["nvd-importer", "--input", str(input_file), "-q"]):
            main()

        out = capsys.readouterr().out
        payload = json.loads(out)
        assert payload["source"] == "nvd"
        assert len(payload["cves"]) == 1
        assert payload["cves"][0]["id"] == "CVE-2024-1001"

    def test_file_output(self, tmp_path):
        """With --output, writes JSON to file."""
        input_file = tmp_path / "nvd.json"
        input_file.write_text(json.dumps({
            "vulnerabilities": [{"cve": SAMPLE_NVD_CVE_FULL}]
        }))
        output_file = tmp_path / "out.json"

        with patch("sys.argv", [
            "nvd-importer", "--input", str(input_file),
            "--output", str(output_file), "-q",
        ]):
            main()

        payload = json.loads(output_file.read_text())
        assert payload["cves"][0]["id"] == "CVE-2024-1001"

    def test_pretty_output(self, capsys, tmp_path):
        input_file = tmp_path / "nvd.json"
        input_file.write_text(json.dumps({
            "vulnerabilities": [{"cve": SAMPLE_NVD_CVE_FULL}]
        }))

        with patch("sys.argv", [
            "nvd-importer", "--input", str(input_file), "--pretty", "-q",
        ]):
            main()

        out = capsys.readouterr().out
        # Pretty-printed JSON has newlines and indentation
        assert "\n  " in out


class TestCliInputFormats:
    def test_ingest_format_passthrough(self, capsys, tmp_path):
        """Files in ingest format pass through without transformation."""
        ingest_data = {
            "cves": [
                {"id": "CVE-2024-1001", "description": "test", "fixed_in": [{"branch": "6.6", "version": "6.6.15"}]},
            ]
        }
        input_file = tmp_path / "ingest.json"
        input_file.write_text(json.dumps(ingest_data))

        with patch("sys.argv", ["nvd-importer", "--input", str(input_file), "-q"]):
            main()

        payload = json.loads(capsys.readouterr().out)
        assert payload["cves"][0]["fixed_in"] == [{"branch": "6.6", "version": "6.6.15"}]

    def test_nvd_response_format(self, capsys, tmp_path):
        """Files in NVD API response format are transformed."""
        input_file = tmp_path / "nvd.json"
        input_file.write_text(json.dumps(SAMPLE_NVD_PAGE_1))

        with patch("sys.argv", ["nvd-importer", "--input", str(input_file), "-q"]):
            main()

        payload = json.loads(capsys.readouterr().out)
        assert len(payload["cves"]) == 2
        assert payload["cves"][0]["cvss_score"] == 7.8

    def test_raw_cve_list_format(self, capsys, tmp_path):
        """Files with a list of raw NVD CVE dicts are transformed."""
        input_file = tmp_path / "raw.json"
        input_file.write_text(json.dumps([SAMPLE_NVD_CVE_FULL]))

        with patch("sys.argv", ["nvd-importer", "--input", str(input_file), "-q"]):
            main()

        payload = json.loads(capsys.readouterr().out)
        assert payload["cves"][0]["id"] == "CVE-2024-1001"


class TestCliFetch:
    def test_fetches_from_nvd(self, capsys):
        """Without --input, fetches from NVD API."""
        with patch("nvd_importer.fetcher.fetch_all_cves_sync") as mock_fetch:
            mock_fetch.return_value = [SAMPLE_NVD_CVE_FULL]
            with patch("sys.argv", ["nvd-importer", "-q"]):
                main()

        mock_fetch.assert_called_once()
        payload = json.loads(capsys.readouterr().out)
        assert len(payload["cves"]) == 1

    def test_api_key_passed(self, capsys):
        with patch("nvd_importer.fetcher.fetch_all_cves_sync") as mock_fetch:
            mock_fetch.return_value = []
            with patch("sys.argv", ["nvd-importer", "--api-key", "abc123", "-q"]):
                main()

        assert mock_fetch.call_args.kwargs["api_key"] == "abc123"

    def test_custom_keyword(self, capsys):
        with patch("nvd_importer.fetcher.fetch_all_cves_sync") as mock_fetch:
            mock_fetch.return_value = []
            with patch("sys.argv", ["nvd-importer", "--keyword", "linux kernel 6.6", "-q"]):
                main()

        assert mock_fetch.call_args.kwargs["keyword"] == "linux kernel 6.6"


class TestCliPost:
    def test_posts_to_backend(self, tmp_path):
        input_file = tmp_path / "nvd.json"
        input_file.write_text(json.dumps({
            "vulnerabilities": [{"cve": SAMPLE_NVD_CVE_FULL}]
        }))

        with patch("nvd_importer.poster.httpx.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=MagicMock(return_value={"ingested": 1, "created": 1, "updated": 0}),
                raise_for_status=MagicMock(),
            )
            with patch("sys.argv", [
                "nvd-importer", "--input", str(input_file),
                "--post", "http://localhost:8000", "-q",
            ]):
                main()

        mock_post.assert_called_once()
        payload = mock_post.call_args.kwargs["json"]
        assert payload["cves"][0]["id"] == "CVE-2024-1001"
