"""Tests for nvd_importer.fetcher."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from nvd_importer.fetcher import DELAY_NO_KEY, DELAY_WITH_KEY, fetch_all_cves
from tests.conftest import SAMPLE_NVD_PAGE_1, SAMPLE_NVD_PAGE_2


def _mock_response(data: dict) -> httpx.Response:
    resp = httpx.Response(200, json=data, request=httpx.Request("GET", "https://test"))
    return resp


class TestFetchAllCves:
    @pytest.mark.asyncio
    async def test_single_page(self):
        single_page = {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": SAMPLE_NVD_PAGE_1["vulnerabilities"],
        }

        with patch("nvd_importer.fetcher.httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.get = AsyncMock(return_value=_mock_response(single_page))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            cves = await fetch_all_cves(keyword="linux kernel")

        assert len(cves) == 2
        assert cves[0]["id"] == "CVE-2024-1001"
        assert cves[1]["id"] == "CVE-2023-5000"
        client.get.assert_called_once()

    @pytest.mark.asyncio
    async def test_multi_page_pagination(self):
        with patch("nvd_importer.fetcher.httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.get = AsyncMock(
                side_effect=[
                    _mock_response(SAMPLE_NVD_PAGE_1),
                    _mock_response(SAMPLE_NVD_PAGE_2),
                ]
            )
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("nvd_importer.fetcher.asyncio.sleep", new_callable=AsyncMock):
                cves = await fetch_all_cves(keyword="linux kernel")

        assert len(cves) == 3
        assert cves[2]["id"] == "CVE-2019-0001"
        assert client.get.call_count == 2

    @pytest.mark.asyncio
    async def test_api_key_in_headers(self):
        empty_page = {
            "resultsPerPage": 0,
            "startIndex": 0,
            "totalResults": 0,
            "vulnerabilities": [],
        }

        with patch("nvd_importer.fetcher.httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.get = AsyncMock(return_value=_mock_response(empty_page))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await fetch_all_cves(api_key="my-secret-key")

        call_kwargs = client.get.call_args
        assert call_kwargs.kwargs["headers"]["apiKey"] == "my-secret-key"

    @pytest.mark.asyncio
    async def test_empty_results(self):
        empty_page = {
            "resultsPerPage": 0,
            "startIndex": 0,
            "totalResults": 0,
            "vulnerabilities": [],
        }

        with patch("nvd_importer.fetcher.httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.get = AsyncMock(return_value=_mock_response(empty_page))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            cves = await fetch_all_cves()

        assert cves == []

    @pytest.mark.asyncio
    async def test_http_error_propagates(self):
        with patch("nvd_importer.fetcher.httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            error_resp = httpx.Response(
                403, request=httpx.Request("GET", "https://test")
            )
            client.get = AsyncMock(
                side_effect=httpx.HTTPStatusError("forbidden", request=error_resp.request, response=error_resp)
            )
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with pytest.raises(httpx.HTTPStatusError):
                await fetch_all_cves()

    @pytest.mark.asyncio
    async def test_progress_callback(self):
        single_page = {
            "resultsPerPage": 2,
            "startIndex": 0,
            "totalResults": 2,
            "vulnerabilities": SAMPLE_NVD_PAGE_1["vulnerabilities"],
        }

        progress_calls = []

        with patch("nvd_importer.fetcher.httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.get = AsyncMock(return_value=_mock_response(single_page))
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            await fetch_all_cves(on_progress=lambda f, t: progress_calls.append((f, t)))

        assert progress_calls == [(2, 2)]

    @pytest.mark.asyncio
    async def test_rate_limit_delay_without_key(self):
        with patch("nvd_importer.fetcher.httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.get = AsyncMock(
                side_effect=[
                    _mock_response(SAMPLE_NVD_PAGE_1),
                    _mock_response(SAMPLE_NVD_PAGE_2),
                ]
            )
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("nvd_importer.fetcher.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                await fetch_all_cves(keyword="linux kernel")

            mock_sleep.assert_called_once_with(DELAY_NO_KEY)

    @pytest.mark.asyncio
    async def test_rate_limit_delay_with_key(self):
        with patch("nvd_importer.fetcher.httpx.AsyncClient") as MockClient:
            client = AsyncMock()
            client.get = AsyncMock(
                side_effect=[
                    _mock_response(SAMPLE_NVD_PAGE_1),
                    _mock_response(SAMPLE_NVD_PAGE_2),
                ]
            )
            MockClient.return_value.__aenter__ = AsyncMock(return_value=client)
            MockClient.return_value.__aexit__ = AsyncMock(return_value=False)

            with patch("nvd_importer.fetcher.asyncio.sleep", new_callable=AsyncMock) as mock_sleep:
                await fetch_all_cves(keyword="linux kernel", api_key="key123")

            mock_sleep.assert_called_once_with(DELAY_WITH_KEY)
