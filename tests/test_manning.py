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
    """Build a subprocess.run replacement mapping argv tuples to (returncode, stdout, stderr)."""
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        returncode, stdout, stderr = responses[tuple(cmd)]
        return subprocess.CompletedProcess(cmd, returncode, stdout=stdout, stderr=stderr)

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

# Output formats below were captured from real `security find-generic-password -g`
# runs: attributes go to stdout, the password line to stderr. Printable ASCII is
# quoted verbatim (even embedded quotes); anything else is shown as 0xHEX + escapes.

def _attrs(acct_value):
    return (
        'keychain: "/Users/me/Library/Keychains/login.keychain-db"\n'
        'class: "genp"\n'
        'attributes:\n'
        f'    "acct"<blob>={acct_value}\n'
        '    "svce"<blob>="manning"\n'
    )


def test_read_keychain_with_account_returns_password():
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning", "-a", "me@x.com", "-g"):
            (0, _attrs('"me@x.com"'), 'password: "s3cret"\n'),
    })
    assert manning.read_keychain("manning", "me@x.com", run=run) == ("me@x.com", "s3cret")


def test_read_keychain_without_account_reads_account_attribute():
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning", "-g"):
            (0, _attrs('"me@x.com"'), 'password: "s3cret"\n'),
    })
    assert manning.read_keychain("manning", run=run) == ("me@x.com", "s3cret")
    assert len(run.calls) == 1


def test_read_keychain_keeps_quotes_and_spaces_in_ascii_password():
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning", "-g"):
            (0, _attrs('"me@x.com"'), 'password: "pa"ss word"\n'),
    })
    assert manning.read_keychain("manning", run=run) == ("me@x.com", 'pa"ss word')


def test_read_keychain_does_not_mistake_hex_looking_password_for_hex():
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning", "-g"):
            (0, _attrs('"me@x.com"'), 'password: "cafe1234"\n'),
    })
    assert manning.read_keychain("manning", run=run)[1] == "cafe1234"


def test_read_keychain_decodes_non_ascii_password_and_account():
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning", "-g"):
            (0, _attrs('0x6DC3A440782E636F6D  "m\\303\\244@x.com"'),
             'password: 0x70C3A47373776F7274  "p\\303\\244sswort"\n'),
    })
    assert manning.read_keychain("manning", run=run) == ("mä@x.com", "pässwort")


def test_read_keychain_item_without_account_raises():
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning", "-g"):
            (0, _attrs("<NULL>"), 'password: "s3cret"\n'),
    })
    with pytest.raises(manning.CredentialError, match="-u"):
        manning.read_keychain("manning", run=run)


def test_read_keychain_empty_password_raises():
    run = fake_run({
        ("security", "find-generic-password", "-s", "manning", "-a", "me@x.com", "-g"):
            (0, _attrs('"me@x.com"'), 'password: \n'),
    })
    with pytest.raises(manning.CredentialError, match="password"):
        manning.read_keychain("manning", "me@x.com", run=run)


def test_read_keychain_missing_item_raises():
    run = fake_run({
        ("security", "find-generic-password", "-s", "nope", "-a", "me@x.com", "-g"):
            (44, "", "security: SecKeychainSearchCopyNext: The specified item could not be found.\n"),
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


def _no_prompt(*_args):
    raise AssertionError("must not prompt")


def test_resolve_credentials_prompts_for_password_with_getpass():
    args = manning.parse_args(["-u", "me@x.com"])
    creds = manning.resolve_credentials(
        args,
        prompt_username=_no_prompt,
        prompt_password=lambda prompt: "typed-pw",
        is_interactive=lambda: True,
    )
    assert creds == ("me@x.com", "typed-pw")


def test_resolve_credentials_prompts_for_username_and_password():
    args = manning.parse_args([])
    creds = manning.resolve_credentials(
        args,
        prompt_username=lambda prompt: "  me@x.com ",
        prompt_password=lambda prompt: "typed-pw",
        is_interactive=lambda: True,
    )
    assert creds == ("me@x.com", "typed-pw")


def test_resolve_credentials_keychain_does_not_prompt():
    args = manning.parse_args(["--keychain", "manning"])
    creds = manning.resolve_credentials(
        args,
        keychain_reader=lambda service, account: ("me@x.com", "kc"),
        prompt_username=_no_prompt,
        prompt_password=_no_prompt,
        is_interactive=lambda: True,
    )
    assert creds == ("me@x.com", "kc")


def test_resolve_credentials_non_interactive_without_source_raises():
    args = manning.parse_args(["-u", "me@x.com"])
    with pytest.raises(manning.CredentialError, match="--keychain"):
        manning.resolve_credentials(args, prompt_password=_no_prompt, is_interactive=lambda: False)


def test_resolve_credentials_empty_prompted_password_raises():
    args = manning.parse_args(["-u", "me@x.com"])
    with pytest.raises(manning.CredentialError):
        manning.resolve_credentials(args, prompt_password=lambda prompt: "", is_interactive=lambda: True)


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

def _product(title="Terraform in Action", external_id="winkler"):
    return manning.Product(title, external_id, [("dropbox", "false"), ("productExternalId", external_id),
                                                ("1", "a"), ("x", "1"), ("2", "b"), ("x", "2")])


def test_folder_names_unique_titles_unchanged():
    products = [_product("Rust in Action", "a"), _product("Go in Action", "b")]
    assert manning.folder_names(products) == ["Rust_in_Action", "Go_in_Action"]


def test_folder_names_disambiguates_collisions_with_product_id():
    products = [
        _product("C# in Depth", "skeet"),
        _product("C in Depth", "other"),
        _product("c in depth", "lower"),   # case-insensitive filesystems (APFS default)
        _product("Unique", "u"),
    ]
    assert manning.folder_names(products) == [
        "C_in_Depth_skeet", "C_in_Depth_other", "c_in_depth_lower", "Unique",
    ]


def test_download_writes_file_using_server_filename_extension(tmp_path):
    resp = FakeResponse(
        headers={"Content-Type": "application/pdf",
                 "Content-Disposition": 'attachment; filename="terraform.pdf"'},
        content=b"%PDF-1.7 data",
    )
    session = FakeSession(post=[resp])
    path = manning.download_product(session, _product(), tmp_path).path
    assert path == tmp_path / "Terraform_in_Action" / "Terraform_in_Action.pdf"
    assert path.read_bytes() == b"%PDF-1.7 data"
    assert session.calls[0][2]["stream"] is True
    assert not list(tmp_path.rglob("*.part"))


def test_download_skips_existing_file(tmp_path):
    existing = tmp_path / "Terraform_in_Action" / "Terraform_in_Action.zip"
    existing.parent.mkdir()
    existing.write_bytes(b"old")
    session = FakeSession()
    assert manning.download_product(session, _product(), tmp_path).status == "skipped"
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


def test_download_uses_given_folder_name(tmp_path):
    session = FakeSession(post=[FakeResponse(headers={"Content-Type": "application/zip"}, content=b"zip")])
    path = manning.download_product(session, _product(), tmp_path, name="Custom_x").path
    assert path == tmp_path / "Custom_x" / "Custom_x.zip"


def test_download_filesystem_error_becomes_download_error(tmp_path):
    blocker = tmp_path / "Terraform_in_Action"
    blocker.write_text("a file where the book folder should go")
    session = FakeSession()
    with pytest.raises(manning.DownloadError, match="Terraform in Action"):
        manning.download_product(session, _product(), tmp_path)


def _existing(tmp_path, ext=".zip", data=b"12345"):
    path = tmp_path / "Terraform_in_Action" / f"Terraform_in_Action{ext}"
    path.parent.mkdir()
    path.write_bytes(data)
    return path


def test_update_skips_when_remote_size_matches(tmp_path):
    existing = _existing(tmp_path)
    resp = FakeResponse(headers={"Content-Type": "application/zip", "Content-Length": "5"}, content=b"NEWER")
    session = FakeSession(post=[resp])
    assert manning.download_product(session, _product(), tmp_path, update=True).status == "unchanged"
    assert existing.read_bytes() == b"12345"


def test_update_replaces_file_when_remote_size_differs(tmp_path):
    existing = _existing(tmp_path, ext=".pdf")
    resp = FakeResponse(headers={"Content-Type": "application/zip", "Content-Length": "9"}, content=b"new-bytes")
    session = FakeSession(post=[resp])
    path = manning.download_product(session, _product(), tmp_path, update=True).path
    assert path == tmp_path / "Terraform_in_Action" / "Terraform_in_Action.zip"
    assert path.read_bytes() == b"new-bytes"
    assert not existing.exists()  # old file with a different extension is removed


def test_update_redownloads_when_size_unknown(tmp_path):
    _existing(tmp_path)
    resp = FakeResponse(headers={"Content-Type": "application/zip"}, content=b"new-bytes")
    session = FakeSession(post=[resp])
    path = manning.download_product(session, _product(), tmp_path, update=True).path
    assert path.read_bytes() == b"new-bytes"


def test_download_all_continues_after_failures_and_counts_them(tmp_path):
    (tmp_path / "Broken").write_text("blocks folder creation")
    products = [_product("Broken", "b"), _product("Good Book", "g")]
    session = FakeSession(post=[FakeResponse(headers={"Content-Type": "application/zip"}, content=b"ok")])
    summary = manning.download_all(session, products, tmp_path, sleep=lambda s: None)
    assert (summary.downloaded, summary.failed) == (1, 1)
    assert (tmp_path / "Good_Book" / "Good_Book.zip").read_bytes() == b"ok"


def test_download_all_pauses_only_between_network_downloads(tmp_path):
    _existing(tmp_path)  # Terraform in Action is already on disk -> skipped, no pause
    products = [_product(), _product("Book A", "a"), _product("Book B", "b")]
    ok = lambda: FakeResponse(headers={"Content-Type": "application/zip"}, content=b"ok")  # noqa: E731
    session = FakeSession(post=[ok(), ok()])
    pauses = []
    summary = manning.download_all(session, products, tmp_path, delay=2.5, sleep=pauses.append)
    assert (summary.downloaded, summary.skipped, summary.failed) == (2, 1, 0)
    assert pauses == [2.5]


def test_download_all_logs_progress_in_plain_language(tmp_path, caplog):
    caplog.set_level("INFO", logger="manning")
    session = FakeSession(post=[FakeResponse(headers={"Content-Type": "application/zip"}, content=b"x" * 2048)])
    manning.download_all(session, [_product()], tmp_path, sleep=lambda s: None)
    text = caplog.text
    assert "(1/1) Terraform in Action" in text
    assert "saved" in text and "KB" in text


# --------------------------------------------------------------------------- #
# main()
# --------------------------------------------------------------------------- #

class FakeSessionCM(FakeSession):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.headers = {}

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _run_main(monkeypatch, tmp_path, dashboard_html):
    session = FakeSessionCM(get=[FakeResponse(dashboard_html)])
    monkeypatch.setattr(manning.requests, "Session", lambda: session)
    monkeypatch.setattr(manning, "login", lambda s, u, p: None)
    monkeypatch.setattr(manning, "read_keychain", lambda service, account=None: ("me@x.com", "pw"))
    return manning.main(["-k", "manning", "-o", str(tmp_path), "--delay", "0"])


def test_main_saves_dashboard_page_when_no_books_found(monkeypatch, tmp_path, caplog):
    caplog.set_level("INFO", logger="manning")
    html = '<table id="productTable"><tr class="new-layout-row"></tr></table>'
    assert _run_main(monkeypatch, tmp_path, html) == 1
    saved = tmp_path / manning.DASHBOARD_DEBUG_FILE
    assert saved.read_text() == html
    assert str(saved) in caplog.text


def test_main_saves_dashboard_page_when_layout_unrecognised(monkeypatch, tmp_path):
    html = "<html>completely new dashboard</html>"
    assert _run_main(monkeypatch, tmp_path, html) == 1
    assert (tmp_path / manning.DASHBOARD_DEBUG_FILE).read_text() == html


def test_main_explains_each_step(monkeypatch, tmp_path, caplog):
    caplog.set_level("INFO", logger="manning")
    session = FakeSessionCM(
        get=[FakeResponse(DASHBOARD)],
        post=[FakeResponse(headers={"Content-Type": "application/zip"}, content=b"z")] * 2,
    )
    monkeypatch.setattr(manning.requests, "Session", lambda: session)
    monkeypatch.setattr(manning, "login", lambda s, u, p: None)
    monkeypatch.setattr(manning, "read_keychain", lambda service, account=None: ("me@x.com", "pw"))
    assert manning.main(["-k", "manning", "-o", str(tmp_path), "--delay", "0"]) == 0
    text = caplog.text
    for expected in ("macOS Keychain", "Signing in", "me@x.com", "library", "Found 2 books", "Downloaded 2"):
        assert expected in text, expected
