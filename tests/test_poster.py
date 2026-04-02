"""Tests for nvd_importer.poster."""

from unittest.mock import patch, MagicMock

import httpx
import pytest

from nvd_importer.poster import post_cves


def _mock_post_response(created: int, updated: int) -> httpx.Response:
    total = created + updated
    return httpx.Response(
        200,
        json={"ingested": total, "created": created, "updated": updated},
        request=httpx.Request("POST", "https://test"),
    )


class TestPostCves:
    def test_single_batch(self):
        cves = [{"id": f"CVE-{i}"} for i in range(3)]

        with patch("nvd_importer.poster.httpx.post") as mock_post:
            mock_post.return_value = _mock_post_response(3, 0)
            result = post_cves("http://localhost:8000", cves, batch_size=500)

        assert result == {"ingested": 3, "created": 3, "updated": 0}
        mock_post.assert_called_once()
        call_kwargs = mock_post.call_args
        assert call_kwargs.args[0] == "http://localhost:8000/api/cves"
        assert len(call_kwargs.kwargs["json"]["cves"]) == 3

    def test_multi_batch(self):
        cves = [{"id": f"CVE-{i}"} for i in range(5)]

        with patch("nvd_importer.poster.httpx.post") as mock_post:
            mock_post.side_effect = [
                _mock_post_response(2, 0),
                _mock_post_response(2, 0),
                _mock_post_response(1, 0),
            ]
            result = post_cves("http://localhost:8000", cves, batch_size=2)

        assert result == {"ingested": 5, "created": 5, "updated": 0}
        assert mock_post.call_count == 3

    def test_counts_accumulate(self):
        cves = [{"id": f"CVE-{i}"} for i in range(4)]

        with patch("nvd_importer.poster.httpx.post") as mock_post:
            mock_post.side_effect = [
                _mock_post_response(1, 1),  # batch 1: 1 new, 1 updated
                _mock_post_response(0, 2),  # batch 2: 0 new, 2 updated
            ]
            result = post_cves("http://localhost:8000", cves, batch_size=2)

        assert result == {"ingested": 4, "created": 1, "updated": 3}

    def test_empty_cves(self):
        with patch("nvd_importer.poster.httpx.post") as mock_post:
            result = post_cves("http://localhost:8000", [])

        assert result == {"ingested": 0, "created": 0, "updated": 0}
        mock_post.assert_not_called()

    def test_http_error_propagates(self):
        cves = [{"id": "CVE-1"}]

        with patch("nvd_importer.poster.httpx.post") as mock_post:
            error_resp = httpx.Response(500, request=httpx.Request("POST", "https://test"))
            mock_post.return_value = error_resp

            with pytest.raises(httpx.HTTPStatusError):
                post_cves("http://localhost:8000", cves)

    def test_trailing_slash_stripped(self):
        cves = [{"id": "CVE-1"}]

        with patch("nvd_importer.poster.httpx.post") as mock_post:
            mock_post.return_value = _mock_post_response(1, 0)
            post_cves("http://localhost:8000/", cves)

        assert mock_post.call_args.args[0] == "http://localhost:8000/api/cves"

    def test_source_passed_through(self):
        cves = [{"id": "CVE-1"}]

        with patch("nvd_importer.poster.httpx.post") as mock_post:
            mock_post.return_value = _mock_post_response(1, 0)
            post_cves("http://localhost:8000", cves, source="manual")

        payload = mock_post.call_args.kwargs["json"]
        assert payload["source"] == "manual"
