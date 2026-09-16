"""Unit tests for manning.py. No network or real Keychain access is used."""

import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import manning  # noqa: E402


# --------------------------------------------------------------------------- #
# Test doubles
# --------------------------------------------------------------------------- #

class FakeResponse:
    def __init__(self, text="", status_code=200, url="", headers=None, content=b""):
        self.text = text
        self.status_code = status_code
        self.url = url
        self.headers = headers or {}
        self._content = content

    def raise_for_status(self):
        if self.status_code >= 400:
            raise manning.requests.HTTPError(f"HTTP {self.status_code}")

    def iter_content(self, chunk_size=1):
        for i in range(0, len(self._content), chunk_size):
            yield self._content[i:i + chunk_size]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeSession:
    """Returns queued responses and records every call."""

    def __init__(self, get=(), post=()):
        self._get = list(get)
        self._post = list(post)
        self.calls = []

    def get(self, url, **kwargs):
        self.calls.append(("GET", url, kwargs))
        return self._get.pop(0)

    def post(self, url, **kwargs):
        self.calls.append(("POST", url, kwargs))
        return self._post.pop(0)


def fake_run(responses):
    """Build a subprocess.run replacement mapping argv tuples to results."""
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        returncode, stdout = responses[tuple(cmd)]
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr="")

    run.calls = calls
    return run


LOGIN_PAGE = """
<html><body>
<form method="post" id="fm1" action="login">
  <input type="email" name="username" value="">
  <input type="password" name="password" value="">
  <input type="hidden" name="execution" value="abc123token" />
  <input type="hidden" name="_eventId" value="submit" />
  <input type="hidden" name="geolocation" />
</form>
</body></html>
"""

DASHBOARD = """
<table id="productTable">
  <tr class="license-row">
    <td><div class="product-title"> Terraform in Action </div></td>
    <td>
      <form class="download-form" name="downloadForm-winkler">
        <div class="download-selection">
          <input type="hidden" id="1971" value="7850702">
          <input type="hidden" id="1972" value="7850703">
          <input type="hidden" id="1973" value="7850704">
        </div>
      </form>
    </td>
  </tr>
  <tr class="license-row">
    <td><div class="product-title">Free/Author Pick: C++</div></td>
    <td>
      <form class="download-form" name="downloadForm-free-pick">
        <div class="download-selection">
          <input type="hidden" id="2001" value="9000001">
        </div>
      </form>
    </td>
  </tr>
  <tr class="license-row">
    <td><div class="product-title">Subscription row without download form</div></td>
  </tr>
</table>
"""


# --------------------------------------------------------------------------- #
# Keychain
# --------------------------------------------------------------------------- #

def test_read_keychain_with_account_returns_password():
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning", "-a", "me@x.com", "-w"): (0, "s3cret\n"),
    })
    assert manning.read_keychain("manning", "me@x.com", run=run) == ("me@x.com", "s3cret")


def test_read_keychain_without_account_reads_account_attribute():
    attrs = (
        'keychain: "/Users/me/Library/Keychains/login.keychain-db"\n'
        'class: "genp"\n'
        'attributes:\n'
        '    "acct"<blob>="me@x.com"\n'
        '    "svce"<blob>="manning"\n'
    )
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning"): (0, attrs),
        ("security", "find-generic-password", "-s", "manning", "-a", "me@x.com", "-w"): (0, "s3cret\n"),
    })
    assert manning.read_keychain("manning", run=run) == ("me@x.com", "s3cret")


def test_read_keychain_missing_item_raises():
    run = fake_run({
        ("security", "find-generic-password", "-s", "nope", "-a", "me@x.com", "-w"): (44, ""),
    })
    with pytest.raises(manning.CredentialError, match="nope"):
        manning.read_keychain("nope", "me@x.com", run=run)


def test_read_keychain_missing_security_binary_raises():
    def run(cmd, **kwargs):
        raise FileNotFoundError("security")

    with pytest.raises(manning.CredentialError, match="macOS"):
        manning.read_keychain("manning", "me@x.com", run=run)


# --------------------------------------------------------------------------- #
# Credential resolution / CLI
# --------------------------------------------------------------------------- #

def test_resolve_credentials_prefers_keychain():
    args = manning.parse_args(["--keychain", "manning", "-u", "me@x.com"])
    reader = lambda service, account: (account, "from-keychain")  # noqa: E731
    assert manning.resolve_credentials(args, keychain_reader=reader) == ("me@x.com", "from-keychain")


def test_resolve_credentials_plain_password_still_supported():
    args = manning.parse_args(["-u", "me@x.com", "-p", "pw"])
    assert manning.resolve_credentials(args) == ("me@x.com", "pw")


def test_resolve_credentials_rejects_both_sources():
    args = manning.parse_args(["--keychain", "manning", "-u", "me@x.com", "-p", "pw"])
    with pytest.raises(manning.CredentialError):
        manning.resolve_credentials(args)


def test_resolve_credentials_requires_some_source():
    args = manning.parse_args(["-u", "me@x.com"])
    with pytest.raises(manning.CredentialError):
        manning.resolve_credentials(args)


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #

def test_login_form_fields_collects_all_hidden_inputs():
    action, fields = manning.login_form_fields(LOGIN_PAGE, manning.LOGIN_URL)
    assert action == "https://login.manning.com/login"
    assert fields == {"execution": "abc123token", "_eventId": "submit", "geolocation": ""}


def test_login_posts_credentials_with_dynamic_tokens():
    session = FakeSession(
        get=[FakeResponse(LOGIN_PAGE, url=manning.LOGIN_URL)],
        post=[FakeResponse("<html>welcome</html>", url="https://www.manning.com/dashboard")],
    )
    manning.login(session, "me@x.com", "pw")
    method, url, kwargs = session.calls[1]
    assert (method, url) == ("POST", "https://login.manning.com/login")
    assert kwargs["data"]["username"] == "me@x.com"
    assert kwargs["data"]["password"] == "pw"
    assert kwargs["data"]["execution"] == "abc123token"


def test_login_failure_detected_when_form_is_shown_again():
    session = FakeSession(
        get=[FakeResponse(LOGIN_PAGE, url=manning.LOGIN_URL)],
        post=[FakeResponse(LOGIN_PAGE, status_code=401, url=manning.LOGIN_URL)],
    )
    with pytest.raises(manning.LoginError):
        manning.login(session, "me@x.com", "wrong")


def test_login_page_without_form_raises():
    session = FakeSession(get=[FakeResponse("<html>maintenance</html>")])
    with pytest.raises(manning.LoginError):
        manning.login(session, "me@x.com", "pw")


# --------------------------------------------------------------------------- #
# Dashboard parsing
# --------------------------------------------------------------------------- #

def test_parse_dashboard_extracts_products_and_payload():
    products = manning.parse_dashboard(DASHBOARD)
    assert [p.title for p in products] == ["Terraform in Action", "Free/Author Pick: C++"]

    tf = products[0]
    assert tf.external_id == "winkler"
    assert tf.payload[:2] == [("dropbox", "false"), ("productExternalId", "winkler")]
    assert ("1971", "7850702") in tf.payload
    assert ("winkler-restrictedDownloadIds", "1973") in tf.payload
    assert tf.guessed_extension == ".zip"


def test_parse_dashboard_keeps_dashes_in_external_id_and_detects_pdf_only():
    free = manning.parse_dashboard(DASHBOARD)[1]
    assert free.external_id == "free-pick"
    assert free.guessed_extension == ".pdf"


def test_parse_dashboard_unrecognised_layout_raises():
    with pytest.raises(manning.DashboardError):
        manning.parse_dashboard("<html><body>new dashboard</body></html>")


@pytest.mark.parametrize("title, expected", [
    ("Terraform in Action", "Terraform_in_Action"),
    ("Free/Author Pick: C++", "Free_Author_Pick_C++"),
    ("../../etc", "etc"),
])
def test_safe_name(title, expected):
    assert manning.safe_name(title) == expected


# --------------------------------------------------------------------------- #
# Downloading
# --------------------------------------------------------------------------- #

def _product():
    return manning.parse_dashboard(DASHBOARD)[0]


def test_download_writes_file_using_server_filename_extension(tmp_path):
    resp = FakeResponse(
        headers={"Content-Type": "application/pdf",
                 "Content-Disposition": 'attachment; filename="terraform.pdf"'},
        content=b"%PDF-1.7 data",
    )
    session = FakeSession(post=[resp])
    path = manning.download_product(session, _product(), tmp_path)
    assert path == tmp_path / "Terraform_in_Action" / "Terraform_in_Action.pdf"
    assert path.read_bytes() == b"%PDF-1.7 data"
    assert session.calls[0][2]["stream"] is True
    assert not list(tmp_path.rglob("*.part"))


def test_download_skips_existing_file(tmp_path):
    existing = tmp_path / "Terraform_in_Action" / "Terraform_in_Action.zip"
    existing.parent.mkdir()
    existing.write_bytes(b"old")
    session = FakeSession()
    assert manning.download_product(session, _product(), tmp_path) is None
    assert session.calls == []


def test_download_rejects_html_response(tmp_path):
    resp = FakeResponse(headers={"Content-Type": "text/html; charset=UTF-8"}, content=b"<html>login</html>")
    session = FakeSession(post=[resp])
    with pytest.raises(manning.DownloadError):
        manning.download_product(session, _product(), tmp_path)
    assert not list(tmp_path.rglob("*.zip"))
    assert not list(tmp_path.rglob("*.part"))


def test_download_http_error_leaves_no_partial_file(tmp_path):
    session = FakeSession(post=[FakeResponse(status_code=500)])
    with pytest.raises(manning.DownloadError):
        manning.download_product(session, _product(), tmp_path)
    assert not list(tmp_path.rglob("*.part"))
