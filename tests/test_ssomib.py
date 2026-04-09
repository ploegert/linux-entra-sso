#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright 2025 Siemens AG
"""
Unit tests for the MSAL-based SsoMib in linux-entra-sso.py.

These tests exercise the pure-Python logic (account format conversion,
account lookup, token-response marshalling) without requiring a live
microsoft-identity-broker daemon or a real MSAL token cache.

Run with:
    python -m pytest tests/test_ssomib.py -v
or:
    python tests/test_ssomib.py
"""

import importlib
import json
import sys
import time
import unittest
from unittest.mock import MagicMock, patch

# Import the module under test using importlib because the file name contains a
# hyphen and cannot be imported with a normal `import` statement.
les = importlib.import_module("linux-entra-sso")
SsoMib = les.SsoMib


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MOCK_TENANT = "f52f0148-c8bb-4ee1-899b-8f93b0e4d63d"
MOCK_OID = "a975168d-a362-458b-af1c-a8982b1e8aac"
MOCK_USERNAME = "test.account@my-org.example.com"

# home_account_id as returned by MSAL: "oid.tid"
MOCK_HOME_ACCOUNT_ID = f"{MOCK_OID}.{MOCK_TENANT}"

# Minimal MSAL account dict (as returned by msal_app.get_accounts())
MSAL_ACCOUNT = {
    "username": MOCK_USERNAME,
    "home_account_id": MOCK_HOME_ACCOUNT_ID,
    "local_account_id": MOCK_OID,
    "realm": MOCK_TENANT,
    "environment": "login.microsoftonline.com",
    "authority_type": "MSSTS",
}

# The broker-format account that the JS extension will send back when
# requesting tokens (derived from MSAL_ACCOUNT via _msal_account_to_broker).
BROKER_ACCOUNT = {
    "name": MOCK_USERNAME,
    "givenName": MOCK_USERNAME,
    "username": MOCK_USERNAME,
    "homeAccountId": MOCK_HOME_ACCOUNT_ID,
    "localAccountId": MOCK_OID,
    "clientInfo": "eyJ1aWQiOiAiYTk3NTE2OGQtYTM2Mi00NThiLWFmMWMtYTg5ODJiMWU4YWFjIiwgInV0aWQiOiAiZjUyZjAxNDgtYzhiYi00ZWUxLTg5OWItOGY5M2IwZTRkNjNkIn0",  # noqa: E501
    "realm": MOCK_TENANT,
}


def _make_ssomib_with_mock_app(msal_app_mock):
    """Return a SsoMib whose _msal_app is replaced with *msal_app_mock*."""
    with patch("msal.PublicClientApplication") as pca_cls:
        pca_cls.return_value = msal_app_mock
        ssomib = SsoMib(daemon=False)
    return ssomib


# ---------------------------------------------------------------------------
# Tests: _msal_account_to_broker
# ---------------------------------------------------------------------------

class TestMsalAccountToBroker(unittest.TestCase):
    def test_fields_present(self):
        result = SsoMib._msal_account_to_broker(MSAL_ACCOUNT)
        for field in ("name", "givenName", "username", "homeAccountId",
                      "localAccountId", "clientInfo", "realm"):
            self.assertIn(field, result, f"missing field '{field}'")

    def test_username_mapped(self):
        result = SsoMib._msal_account_to_broker(MSAL_ACCOUNT)
        self.assertEqual(result["username"], MOCK_USERNAME)

    def test_home_account_id_mapped(self):
        result = SsoMib._msal_account_to_broker(MSAL_ACCOUNT)
        self.assertEqual(result["homeAccountId"], MOCK_HOME_ACCOUNT_ID)

    def test_local_account_id_mapped(self):
        result = SsoMib._msal_account_to_broker(MSAL_ACCOUNT)
        self.assertEqual(result["localAccountId"], MOCK_OID)

    def test_realm_mapped(self):
        result = SsoMib._msal_account_to_broker(MSAL_ACCOUNT)
        self.assertEqual(result["realm"], MOCK_TENANT)

    def test_client_info_is_base64url(self):
        import base64
        result = SsoMib._msal_account_to_broker(MSAL_ACCOUNT)
        # Should not raise, and the decoded JSON must have uid/utid keys
        padded = result["clientInfo"] + "=" * (4 - len(result["clientInfo"]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(padded))
        self.assertIn("uid", decoded)
        self.assertIn("utid", decoded)
        self.assertEqual(decoded["uid"], MOCK_OID)
        self.assertEqual(decoded["utid"], MOCK_TENANT)

    def test_name_falls_back_to_username(self):
        # MSAL doesn't provide display name; should match username
        result = SsoMib._msal_account_to_broker(MSAL_ACCOUNT)
        self.assertEqual(result["name"], MOCK_USERNAME)

    def test_empty_account(self):
        result = SsoMib._msal_account_to_broker({})
        self.assertEqual(result["username"], "")
        self.assertEqual(result["homeAccountId"], "")


# ---------------------------------------------------------------------------
# Tests: _find_msal_account
# ---------------------------------------------------------------------------

class TestFindMsalAccount(unittest.TestCase):
    def _make_ssomib(self, accounts):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.return_value = accounts
        app_mock.get_accounts.side_effect = lambda username=None: (
            [a for a in accounts if a.get("username") == username]
            if username else accounts
        )
        return _make_ssomib_with_mock_app(app_mock)

    def test_found_by_username(self):
        ssomib = self._make_ssomib([MSAL_ACCOUNT])
        result = ssomib._find_msal_account({"username": MOCK_USERNAME})
        self.assertEqual(result, MSAL_ACCOUNT)

    def test_found_by_home_account_id_fallback(self):
        # get_accounts(username=...) returns empty; fallback to scan by id
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.side_effect = lambda username=None: (
            [] if username else [MSAL_ACCOUNT]
        )
        ssomib = _make_ssomib_with_mock_app(app_mock)
        result = ssomib._find_msal_account(
            {"username": "", "homeAccountId": MOCK_HOME_ACCOUNT_ID}
        )
        self.assertEqual(result, MSAL_ACCOUNT)

    def test_not_found_returns_none(self):
        ssomib = self._make_ssomib([MSAL_ACCOUNT])
        result = ssomib._find_msal_account({"username": "nobody@example.com"})
        self.assertIsNone(result)


# ---------------------------------------------------------------------------
# Tests: get_accounts
# ---------------------------------------------------------------------------

class TestGetAccounts(unittest.TestCase):
    def test_returns_accounts_list(self):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.return_value = [MSAL_ACCOUNT]
        ssomib = _make_ssomib_with_mock_app(app_mock)
        result = ssomib.get_accounts()
        self.assertIn("accounts", result)
        self.assertEqual(len(result["accounts"]), 1)

    def test_empty_accounts(self):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.return_value = []
        ssomib = _make_ssomib_with_mock_app(app_mock)
        result = ssomib.get_accounts()
        self.assertEqual(result["accounts"], [])

    def test_account_format_converted(self):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.return_value = [MSAL_ACCOUNT]
        ssomib = _make_ssomib_with_mock_app(app_mock)
        account = ssomib.get_accounts()["accounts"][0]
        # Must use camelCase keys as expected by the JS extension
        self.assertIn("homeAccountId", account)
        self.assertIn("localAccountId", account)
        self.assertNotIn("home_account_id", account)
        self.assertNotIn("local_account_id", account)


# ---------------------------------------------------------------------------
# Tests: acquire_token_silently
# ---------------------------------------------------------------------------

class TestAcquireTokenSilently(unittest.TestCase):
    def _make_ssomib(self, accounts, msal_result):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.side_effect = lambda username=None: (
            [a for a in accounts if a.get("username") == username]
            if username else accounts
        )
        app_mock.acquire_token_silent.return_value = msal_result
        return _make_ssomib_with_mock_app(app_mock)

    def test_successful_token(self):
        msal_result = {
            "access_token": "fake_access_token",
            "id_token": "fake_id_token",
            "expires_in": 3600,
            "ext_expires_in": 7200,
            "scope": "https://graph.microsoft.com/.default profile",
        }
        ssomib = self._make_ssomib([MSAL_ACCOUNT], msal_result)
        result = ssomib.acquire_token_silently(BROKER_ACCOUNT)
        btr = result["brokerTokenResponse"]
        self.assertNotIn("error", btr)
        self.assertEqual(btr["accessToken"], "fake_access_token")
        self.assertEqual(btr["idToken"], "fake_id_token")
        self.assertIn("expiresOn", btr)
        self.assertIn("extendedExpiresOn", btr)
        self.assertIn("grantedScopes", btr)
        self.assertIsInstance(btr["grantedScopes"], list)

    def test_expiry_in_milliseconds(self):
        before_ms = int(time.time() * 1000)
        msal_result = {
            "access_token": "tok",
            "expires_in": 3600,
            "ext_expires_in": 7200,
            "scope": "scope1",
        }
        ssomib = self._make_ssomib([MSAL_ACCOUNT], msal_result)
        result = ssomib.acquire_token_silently(BROKER_ACCOUNT)
        btr = result["brokerTokenResponse"]
        after_ms = int(time.time() * 1000)
        # expiresOn should be roughly now + 3600 seconds in ms
        self.assertGreaterEqual(btr["expiresOn"], before_ms + 3600 * 1000)
        self.assertLessEqual(btr["expiresOn"], after_ms + 3600 * 1000)

    def test_account_not_found_returns_error(self):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.return_value = []
        ssomib = _make_ssomib_with_mock_app(app_mock)
        result = ssomib.acquire_token_silently({"username": "ghost@example.com"})
        self.assertIn("error", result["brokerTokenResponse"])
        self.assertEqual(result["brokerTokenResponse"]["error"], "no_account")

    def test_no_token_in_cache_returns_error(self):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.side_effect = lambda username=None: (
            [MSAL_ACCOUNT] if not username or username == MOCK_USERNAME else []
        )
        app_mock.acquire_token_silent.return_value = None  # cache miss
        ssomib = _make_ssomib_with_mock_app(app_mock)
        result = ssomib.acquire_token_silently(BROKER_ACCOUNT)
        self.assertIn("error", result["brokerTokenResponse"])
        self.assertEqual(result["brokerTokenResponse"]["error"], "no_token_in_cache")

    def test_msal_error_propagated(self):
        msal_error = {"error": "invalid_grant", "error_description": "Token expired."}
        app_mock = MagicMock()
        app_mock._enable_broker = True
        app_mock.get_accounts.side_effect = lambda username=None: (
            [MSAL_ACCOUNT] if not username or username == MOCK_USERNAME else []
        )
        app_mock.acquire_token_silent.return_value = msal_error
        ssomib = _make_ssomib_with_mock_app(app_mock)
        result = ssomib.acquire_token_silently(BROKER_ACCOUNT)
        self.assertIn("error", result["brokerTokenResponse"])
        self.assertEqual(result["brokerTokenResponse"]["error"], "invalid_grant")

    def test_scope_split_into_list(self):
        msal_result = {
            "access_token": "tok",
            "expires_in": 3600,
            "ext_expires_in": 7200,
            "scope": "scope1 scope2 scope3",
        }
        ssomib = self._make_ssomib([MSAL_ACCOUNT], msal_result)
        btr = ssomib.acquire_token_silently(BROKER_ACCOUNT)["brokerTokenResponse"]
        self.assertEqual(btr["grantedScopes"], ["scope1", "scope2", "scope3"])

    def test_account_passed_through_in_response(self):
        msal_result = {
            "access_token": "tok",
            "expires_in": 3600,
            "ext_expires_in": 7200,
            "scope": "s",
        }
        ssomib = self._make_ssomib([MSAL_ACCOUNT], msal_result)
        btr = ssomib.acquire_token_silently(BROKER_ACCOUNT)["brokerTokenResponse"]
        self.assertEqual(btr["account"], BROKER_ACCOUNT)


# ---------------------------------------------------------------------------
# Tests: get_broker_version
# ---------------------------------------------------------------------------

class TestGetBrokerVersion(unittest.TestCase):
    def test_returns_native_version(self):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        ssomib = _make_ssomib_with_mock_app(app_mock)
        result = ssomib.get_broker_version()
        self.assertIn("native", result)
        self.assertEqual(result["native"], les.LINUX_ENTRA_SSO_VERSION)

    def test_returns_msal_version(self):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        ssomib = _make_ssomib_with_mock_app(app_mock)
        result = ssomib.get_broker_version()
        self.assertIn("msalVersion", result)

    def test_no_dbus_broker_no_linux_broker_version(self):
        app_mock = MagicMock()
        app_mock._enable_broker = True
        ssomib = _make_ssomib_with_mock_app(app_mock)
        # _dbus_broker is None by default (daemon=False)
        result = ssomib.get_broker_version()
        # linuxBrokerVersion key should not be present if D-Bus is unavailable
        self.assertNotIn("linuxBrokerVersion", result)


# ---------------------------------------------------------------------------
# Tests: mock compatibility – SsoMibMock
# ---------------------------------------------------------------------------

class TestSsoMibMock(unittest.TestCase):
    """Validate that SsoMibMock satisfies the SsoMib contract.

    The mock bypasses MSAL and pydbus entirely, so these tests can run on
    any platform as long as PyJWT is installed.  Skip the class if jwt is
    unavailable (e.g., a minimal CI environment without dev dependencies).
    """

    @classmethod
    def setUpClass(cls):
        try:
            import jwt  # noqa: F401 – only used by the mock when imported
        except ImportError:
            raise unittest.SkipTest("PyJWT not installed (pip install PyJWT)")
        import importlib as _il
        import os as _os
        # Make sure `tests/` is importable as a package.
        tests_dir = _os.path.join(_os.path.dirname(__file__))
        parent_dir = _os.path.dirname(tests_dir)
        if parent_dir not in sys.path:
            sys.path.insert(0, parent_dir)
        # linux_entra_sso_mock monkey-patches les.SsoMib on import;
        # re-load a fresh copy to avoid inter-test state pollution.
        mock_spec = _il.util.spec_from_file_location(
            "linux_entra_sso_mock",
            _os.path.join(tests_dir, "linux_entra_sso_mock.py"),
        )
        mock_mod = _il.util.module_from_spec(mock_spec)
        mock_spec.loader.exec_module(mock_mod)
        cls.SsoMibMock = mock_mod.SsoMibMock

    def _get_mock(self):
        return self.SsoMibMock(daemon=False)

    def test_broker_is_truthy(self):
        m = self._get_mock()
        self.assertTrue(m.broker)

    def test_get_accounts_returns_dict(self):
        m = self._get_mock()
        result = m.get_accounts()
        self.assertIn("accounts", result)
        self.assertIsInstance(result["accounts"], list)
        self.assertGreater(len(result["accounts"]), 0)

    def test_account_has_required_keys(self):
        m = self._get_mock()
        account = m.get_accounts()["accounts"][0]
        for key in ("username", "homeAccountId", "localAccountId",
                    "clientInfo", "realm"):
            self.assertIn(key, account, f"missing key '{key}' in mock account")

    def test_acquire_token_silently_returns_broker_token_response(self):
        m = self._get_mock()
        account = m.get_accounts()["accounts"][0]
        result = m.acquire_token_silently(account)
        self.assertIn("brokerTokenResponse", result)
        btr = result["brokerTokenResponse"]
        self.assertIn("accessToken", btr)
        self.assertIn("expiresOn", btr)

    def test_acquire_prt_sso_cookie_returns_cookie(self):
        m = self._get_mock()
        account = m.get_accounts()["accounts"][0]
        result = m.acquire_prt_sso_cookie(account, "https://login.microsoftonline.com/")
        self.assertIn("cookieName", result)
        self.assertIn("cookieContent", result)

    def test_get_broker_version_has_native(self):
        m = self._get_mock()
        result = m.get_broker_version()
        self.assertIn("native", result)
        self.assertIn("mock", result["native"])
