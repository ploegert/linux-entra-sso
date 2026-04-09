#!/usr/bin/env python3
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright 2024 Siemens AG

# pylint: disable=missing-docstring,invalid-name

# Renable invalid-name check, it should only cover the module name
# pylint: enable=invalid-name

import argparse
import base64
import ctypes
import json
import struct
import sys
import time
import uuid
from enum import Enum
from signal import SIGINT
from threading import RLock, Thread
from xml.etree import ElementTree as ET

import msal

# pydbus and GLib are still required for PRT SSO cookie acquisition and
# broker state monitoring via D-Bus NameOwnerChanged events, because
# acquirePrtSsoCookie has no equivalent in the MSAL Python public API.
try:
    from gi.repository import GLib
    from pydbus import SessionBus
    from pydbus.proxy import CompositeInterface
    _PYDBUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _PYDBUS_AVAILABLE = False

# version is replaced on installation
LINUX_ENTRA_SSO_VERSION = "0.0.0-dev"

# the ssoUrl is a mandatory parameter when requesting a PRT SSO
# Cookie, but the correct value is not checked as of 30.05.2024
# by the authorization backend. By that, a static (fallback)
# value can be used, if no real value is provided.
SSO_URL_DEFAULT = "https://login.microsoftonline.com/"
EDGE_BROWSER_CLIENT_ID = "d7b530a4-7680-4c23-a8bf-c52c121d2e87"
# dbus start service reply codes
START_REPLY_SUCCESS = 1
START_REPLY_ALREADY_RUNNING = 2
# prctl constants
PR_SET_PDEATHSIG = 1

# D-Bus spec limited to the methods still needed after the MSAL migration:
# acquirePrtSsoCookie (no MSAL equivalent) and getLinuxBrokerVersion.
# acquireTokenSilently and getAccounts are now handled by MSAL Python.
BROKER_DBUS_SPEC = r"""<!DOCTYPE node PUBLIC
"-//freedesktop//DTD D-Bus Object Introspection 1.0//EN"
"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
<node name="/com/microsoft/identity/broker1">
 <interface name="com.microsoft.identity.Broker1">
  <method name="acquirePrtSsoCookie" >
   <arg type="s" direction="in"/>
   <arg type="s" direction="in"/>
   <arg type="s" direction="in"/>
   <arg type="s" direction="out"/>
  </method>
  <method name="getLinuxBrokerVersion" >
   <arg type="s" direction="in"/>
   <arg type="s" direction="in"/>
   <arg type="s" direction="in"/>
   <arg type="s" direction="out"/>
  </method>
 </interface>
</node>
"""


class AuthorizationType(Enum):
    PRT_SSO_COOKIE = (8,)


class NativeMessaging:  # pragma: no cover
    @staticmethod
    def get_message():
        """
        Read a message from stdin and decode it.
        """
        raw_length = sys.stdin.buffer.read(4)
        if not raw_length:
            sys.exit(0)
        message_length = struct.unpack("@I", raw_length)[0]
        message = sys.stdin.buffer.read(message_length).decode("utf-8")
        return json.loads(message)

    @staticmethod
    def encode_message(message_content):
        """
        Encode a message for transmission, given its content
        """
        encoded_content = json.dumps(message_content, separators=(",", ":")).encode(
            "utf-8"
        )
        encoded_length = struct.pack("@I", len(encoded_content))
        return {"length": encoded_length, "content": encoded_content}

    @staticmethod
    def send_message(encoded_message):
        """
        Send an encoded message to stdout
        """
        sys.stdout.buffer.write(encoded_message["length"])
        sys.stdout.buffer.write(encoded_message["content"])
        sys.stdout.buffer.flush()


class SsoMib:
    BROKER_NAME = "com.microsoft.identity.broker1"
    BROKER_PATH = "/com/microsoft/identity/broker1"
    GRAPH_SCOPES = ["https://graph.microsoft.com/.default"]
    MSAL_AUTHORITY = "https://login.microsoftonline.com/common"
    MSAL_REDIRECT_URI = "https://login.microsoftonline.com/common/oauth2/nativeclient"

    def __init__(self, daemon=False):
        # Initialize MSAL PublicClientApplication with Linux broker support.
        # MSAL handles get_accounts and acquire_token_silently internally via
        # the microsoft-identity-broker daemon (same underlying service as D-Bus).
        self._msal_app = msal.PublicClientApplication(
            EDGE_BROWSER_CLIENT_ID,
            authority=self.MSAL_AUTHORITY,
            enable_broker_on_linux=True,
        )
        self._session_id = uuid.uuid4()
        self._state_changed_cb = None
        self._last_state_reported = False

        # `broker` is a truthy indicator of broker availability, preserving
        # the original interface expected by run_as_native_messaging().
        # MSAL sets _enable_broker=True only when the broker package is installed
        # and the broker daemon is reachable.
        self.broker = self._msal_app._enable_broker or None

        # D-Bus connection retained only for:
        #   • acquirePrtSsoCookie  (no MSAL equivalent)
        #   • getLinuxBrokerVersion
        #   • NameOwnerChanged event (broker online/offline notifications)
        self._dbus_bus = None
        self._dbus_broker = None

        if daemon:
            if _PYDBUS_AVAILABLE:
                try:
                    self._dbus_bus = SessionBus()
                    self._introspect_dbus_broker()
                    self._monitor_bus()
                except Exception as exc:  # pylint: disable=broad-except
                    print(
                        f"D-Bus setup failed ({exc}). "
                        "PRT SSO cookies and broker version will be unavailable.",
                        file=sys.stderr,
                    )
            else:
                print(
                    "pydbus/GLib not available. PRT SSO cookies, broker version "
                    "queries, and broker state change events will be unavailable.",
                    file=sys.stderr,
                )
            self._report_state_change()

    # ------------------------------------------------------------------
    # D-Bus helpers – state monitoring and PRT SSO cookie only
    # ------------------------------------------------------------------

    def _introspect_dbus_broker(self):
        introspection = ET.fromstring(BROKER_DBUS_SPEC)
        self._dbus_broker = CompositeInterface(introspection)(
            self._dbus_bus, self.BROKER_NAME, self.BROKER_PATH
        )
        # Available if either MSAL enabled the broker or D-Bus connected
        self.broker = self._msal_app._enable_broker or self._dbus_broker
        self._report_state_change()

    def _monitor_bus(self):
        self._dbus_bus.subscribe(
            sender="org.freedesktop.DBus",
            object="/org/freedesktop/DBus",
            signal="NameOwnerChanged",
            arg0=self.BROKER_NAME,
            signal_fired=self._broker_state_changed,
        )

    def _broker_state_changed(
        self, sender, object, iface, signal, params
    ):  # pylint: disable=redefined-builtin,too-many-arguments
        _ = (sender, object, iface, signal)
        # params = (name, old_owner, new_owner)
        new_owner = params[2]
        if new_owner:
            self._introspect_dbus_broker()
        else:
            self._dbus_broker = None
            self.broker = self._msal_app._enable_broker or None
            self._report_state_change()

    def _report_state_change(self):
        current_state = bool(self.broker)
        if self._state_changed_cb and self._last_state_reported != current_state:
            self._state_changed_cb(current_state)
        self._last_state_reported = current_state

    def on_broker_state_changed(self, callback):
        """
        Register a callback to be called when the broker state changes.
        The callback should accept a single boolean argument, indicating
        if the broker is online or not.
        """
        self._state_changed_cb = callback

    # ------------------------------------------------------------------
    # Account format helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _msal_account_to_broker(msal_account):
        """Convert an MSAL account dict to the broker format expected by the JS extension.

        MSAL returns accounts with snake_case keys; the extension expects camelCase
        keys matching the Microsoft Identity Broker D-Bus response schema.
        """
        username = msal_account.get("username", "")
        home_account_id = msal_account.get("home_account_id", "")
        local_account_id = msal_account.get("local_account_id", "")
        realm = msal_account.get("realm", "")

        # Derive `clientInfo` – a base64url-encoded JSON blob {"uid": ..., "utid": ...}
        # from the home_account_id which has the format "uid.utid" in MSAL.
        parts = home_account_id.split(".", 1)
        uid = parts[0] if parts else local_account_id
        utid = parts[1] if len(parts) > 1 else realm
        client_info_bytes = json.dumps(
            {"uid": uid, "utid": utid}, separators=(",", ":")
        ).encode()
        client_info = base64.urlsafe_b64encode(client_info_bytes).rstrip(b"=").decode()

        return {
            # MSAL does not expose the user's display name; fall back to username.
            "name": username,
            "givenName": username,
            "username": username,
            "homeAccountId": home_account_id,
            "localAccountId": local_account_id,
            "clientInfo": client_info,
            "realm": realm,
        }

    def _find_msal_account(self, broker_account):
        """Find the MSAL account object that corresponds to a broker-format account."""
        username = broker_account.get("username", "")
        home_account_id = broker_account.get("homeAccountId", "")

        if username:
            matches = self._msal_app.get_accounts(username=username)
            if matches:
                return matches[0]

        # Fallback: linear search by home_account_id
        if home_account_id:
            for acc in self._msal_app.get_accounts():
                if acc.get("home_account_id") == home_account_id:
                    return acc

        return None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_accounts(self):
        """Return all accounts known to MSAL via the Linux broker."""
        msal_accounts = self._msal_app.get_accounts()
        return {
            "accounts": [self._msal_account_to_broker(a) for a in msal_accounts]
        }

    def acquire_token_silently(
        self, account, scopes=GRAPH_SCOPES
    ):  # pylint: disable=dangerous-default-value
        """Acquire an access token silently via MSAL Python.

        MSAL communicates with the microsoft-identity-broker daemon internally,
        replacing the previous direct D-Bus acquireTokenSilently call.
        """
        msal_account = self._find_msal_account(account)
        if msal_account is None:
            return {
                "brokerTokenResponse": {
                    "error": "no_account",
                    "error_description": (
                        "No MSAL account found matching "
                        f"username '{account.get('username', '')}'"
                    ),
                }
            }

        result = self._msal_app.acquire_token_silent(scopes, account=msal_account)

        if result is None:
            return {
                "brokerTokenResponse": {
                    "error": "no_token_in_cache",
                    "error_description": (
                        "No cached token available for the requested account and "
                        "scopes. Interactive sign-in may be required."
                    ),
                }
            }

        if "error" in result:
            return {"brokerTokenResponse": result}

        now_ms = int(time.time() * 1000)
        expires_on_ms = now_ms + result.get("expires_in", 3600) * 1000
        ext_expires_on_ms = now_ms + result.get("ext_expires_in", 7200) * 1000
        granted_scopes = result.get("scope", " ".join(scopes)).split()

        return {
            "brokerTokenResponse": {
                "accessToken": result["access_token"],
                "accessTokenType": 0,
                "idToken": result.get("id_token", ""),
                "account": account,
                "clientInfo": account.get("clientInfo", ""),
                "expiresOn": expires_on_ms,
                "extendedExpiresOn": ext_expires_on_ms,
                "grantedScopes": granted_scopes,
            }
        }

    def acquire_prt_sso_cookie(
        self, account, sso_url, scopes=GRAPH_SCOPES
    ):  # pylint: disable=dangerous-default-value
        """Acquire a PRT SSO cookie via D-Bus.

        The acquirePrtSsoCookie broker method is not part of the MSAL Python
        public API, so the D-Bus interface is used directly here.
        """
        if not _PYDBUS_AVAILABLE:
            raise RuntimeError(
                "PRT SSO cookie acquisition requires pydbus and PyGObject. "
                "Install them with:  pip install pydbus PyGObject  "
                "or:  apt-get install python3-pydbus python3-gi"
            )
        if self._dbus_broker is None:
            self._introspect_dbus_broker()

        request = {
            "account": account,
            "authParameters": SsoMib._get_prt_auth_parameters(account, scopes, sso_url),
            "mamEnrollment": False,
            "ssoUrl": sso_url,
        }
        token = json.loads(
            self._dbus_broker.acquirePrtSsoCookie(  # pylint: disable=maybe-no-member
                "0.0", str(self._session_id), json.dumps(request)
            )
        )
        return token

    @staticmethod
    def _get_prt_auth_parameters(account, scopes, sso_url):
        return {
            "account": account,
            "additionalQueryParametersForAuthorization": {},
            "authority": "https://login.microsoftonline.com/common",
            "authorizationType": AuthorizationType.PRT_SSO_COOKIE.value[0],
            "clientId": EDGE_BROWSER_CLIENT_ID,
            "redirectUri": SsoMib.MSAL_REDIRECT_URI,
            "requestedScopes": scopes,
            "username": account["username"],
            "uxContextHandle": -1,
            "ssoUrl": sso_url,
        }

    def get_broker_version(self):
        """Return version info for the native host, MSAL library, and identity broker."""
        result = {
            "native": LINUX_ENTRA_SSO_VERSION,
            "msalVersion": getattr(msal, "__version__", "unknown"),
        }

        if _PYDBUS_AVAILABLE and self._dbus_broker is not None:
            try:
                params = json.dumps({"msalCppVersion": LINUX_ENTRA_SSO_VERSION})
                resp = json.loads(
                    self._dbus_broker.getLinuxBrokerVersion(  # pylint: disable=maybe-no-member
                        "0.0", str(self._session_id), params
                    )
                )
                result["linuxBrokerVersion"] = resp.get("linuxBrokerVersion")
            except Exception as exc:  # pylint: disable=broad-except
                print(
                    f"Could not retrieve broker version via D-Bus: {exc}",
                    file=sys.stderr,
                )

        return result


def run_as_native_messaging():
    iomutex = RLock()

    def respond(command, message):
        NativeMessaging.send_message(
            NativeMessaging.encode_message({"command": command, "message": message})
        )

    def notify_state_change(online):
        with iomutex:
            respond("brokerStateChanged", "online" if online else "offline")

    def handle_command(cmd, received_message):
        if cmd == "acquirePrtSsoCookie":
            account = received_message["account"]
            sso_url = received_message["ssoUrl"] or SSO_URL_DEFAULT
            token = ssomib.acquire_prt_sso_cookie(account, sso_url)
            respond(cmd, token)
        elif cmd == "acquireTokenSilently":
            account = received_message["account"]
            scopes = received_message.get("scopes") or ssomib.GRAPH_SCOPES
            token = ssomib.acquire_token_silently(account, scopes)
            respond(cmd, token)
        elif cmd == "getAccounts":
            respond(cmd, ssomib.get_accounts())
        elif cmd == "getVersion":
            respond(cmd, ssomib.get_broker_version())

    def run_dbus_monitor():
        # Inform the other side about the initial state.
        notify_state_change(bool(ssomib.broker))
        # Run the GLib main loop only when pydbus is available; its event loop
        # processes the D-Bus NameOwnerChanged subscription for broker
        # online/offline notifications.  Without pydbus the main thread's
        # while-loop below keeps the process alive.
        if _PYDBUS_AVAILABLE:
            GLib.MainLoop().run()

    def register_terminate_with_parent():
        libc = ctypes.CDLL("libc.so.6")
        libc.prctl(PR_SET_PDEATHSIG, SIGINT, 0, 0, 0)

    print("Running as native messaging instance.", file=sys.stderr)
    print("For interactive mode, start with --interactive", file=sys.stderr)

    # on chrome and chromium, the parent process does not reliably
    # terminate the process when the parent process is killed.
    register_terminate_with_parent()

    ssomib = SsoMib(daemon=True)
    ssomib.on_broker_state_changed(notify_state_change)
    monitor = Thread(target=run_dbus_monitor, daemon=True)
    monitor.start()
    while True:
        received_message = NativeMessaging.get_message()
        with iomutex:
            cmd = received_message["command"]
            try:
                handle_command(cmd, received_message)
            except Exception as exp:  # pylint: disable=broad-except
                err = {"error": f"Failure during request processing: {str(exp)}"}
                respond(cmd, err)


def run_interactive():
    def _get_account(accounts, idx):
        try:
            return accounts["accounts"][idx]
        except IndexError:
            json.dump(
                {"error": f"invalid account index {idx}"},
                indent=2,
                fp=sys.stdout,
            )
            print()
            sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i",
        "--interactive",
        action="store_true",
        help="run in interactive mode",
    )
    parser.add_argument(
        "-a",
        "--account",
        type=int,
        default=0,
        help="account index to use for operations",
    )
    parser.add_argument(
        "-s",
        "--ssoUrl",
        default=SSO_URL_DEFAULT,
        help="ssoUrl part of SSO PRT cookie request",
    )
    parser.add_argument(
        "command",
        choices=[
            "getAccounts",
            "getVersion",
            "acquirePrtSsoCookie",
            "acquireTokenSilently",
            "monitor",
        ],
    )
    args = parser.parse_args()

    monitor_mode = args.command == "monitor"
    ssomib = SsoMib(daemon=monitor_mode)
    if monitor_mode:
        if not _PYDBUS_AVAILABLE:
            print(
                "error: 'monitor' command requires pydbus and PyGObject.",
                file=sys.stderr,
            )
            sys.exit(1)
        print("Monitoring D-Bus for broker availability.")
        ssomib.on_broker_state_changed(
            lambda online: print(
                f"{ssomib.BROKER_NAME} is now " f"{'online' if online else 'offline'}."
            )
        )
        GLib.MainLoop().run()
        return

    accounts = ssomib.get_accounts()
    if len(accounts["accounts"]) == 0:
        print("warning: no accounts registered.", file=sys.stderr)

    if args.command == "getAccounts":
        json.dump(accounts, indent=2, fp=sys.stdout)
    elif args.command == "getVersion":
        json.dump(ssomib.get_broker_version(), indent=2, fp=sys.stdout)
    elif args.command == "acquirePrtSsoCookie":
        account = _get_account(accounts, args.account)
        cookie = ssomib.acquire_prt_sso_cookie(account, args.ssoUrl)
        json.dump(cookie, indent=2, fp=sys.stdout)
    elif args.command == "acquireTokenSilently":
        account = _get_account(accounts, args.account)
        token = ssomib.acquire_token_silently(account)
        json.dump(token, indent=2, fp=sys.stdout)
    # add newline
    print()


if __name__ == "__main__":
    if "--interactive" in sys.argv or "-i" in sys.argv:
        run_interactive()
    else:
        run_as_native_messaging()
