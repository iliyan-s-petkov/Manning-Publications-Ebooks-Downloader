"""Unit tests for manning.py. No network or real Keychain access is used."""

import argparse
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
# Library parsing
# --------------------------------------------------------------------------- #

def _download_menu(product_id, fmt):
    return f"""
    <div class="dropdown">
      <a class="dropdown-toggle" data-toggle="dropdown" href="#">{fmt.lower()}</a>
      <ul class="dropdown-menu">
        <li><a href="https://www.manning.com/dashboard/download?productId={product_id}&amp;downloadFormat={fmt}">download {fmt.lower()}</a></li>
        <li><a href="https://www.manning.com/dashboard/startDropboxLinkProcess" name="dropboxAuth">authorize Dropbox</a></li>
      </ul>
    </div>"""


def _library_item(title, product_id, formats, version=None):
    meap = f'<div class="meap-last-updated">{version}</div>' if version else ""
    menus = "".join(_download_menu(product_id, f) for f in formats)
    return f"""
<div class="col-xs-2 col-md-1 product-cover-image-column"><img src="cover.jpg"></div>
<div class="col-xs-10 col-md-11 product-data-column">
  <div class="row">
    <div class="col-xs-12 col-sm-12 col-md-8">
      <div class="title-column"><div>
        <div class="product-title">
          {title}
          <span class="badge-space"><a href="https://livebook.manning.com/book/x"><img src="badge.svg"></a></span>
        </div>
        <div class="product-authorship">Some Author</div>
        {meap}
      </div></div>
    </div>
    <div class="col-xs-12 col-sm-12 col-md-4 text-right control-column">
      <div class="downloads-and-more">
        <a href="https://livebook.manning.com/book/x"><span>liveBook</span></a>
        {menus}
      </div>
    </div>
  </div>
</div>"""


# Trimmed from a real getLicensesAjax response (same classes and nesting).
LIBRARY = "".join([
    _library_item("AI Model Evaluation", "4001", ["EPUB", "KINDLE", "PDF"],
                  version="version: 5, last updated: 2026-09-14"),
    _library_item("Go in Action, Second Edition", "2057", ["EPUB", "KINDLE", "PDF"]),
    _library_item("Algorithms in Motion", "900", []),  # a video course: nothing to download
    _library_item("Free/Author Pick: C++", "12", ["PDF"]),
])


def test_parse_library_extracts_title_id_formats_and_version():
    products = manning.parse_library(LIBRARY)
    assert products[0] == manning.Product(
        "AI Model Evaluation", "4001", ("EPUB", "KINDLE", "PDF"), "version: 5, last updated: 2026-09-14")
    assert products[1] == manning.Product("Go in Action, Second Edition", "2057", ("EPUB", "KINDLE", "PDF"), None)
    assert products[3] == manning.Product("Free/Author Pick: C++", "12", ("PDF",), None)


def test_parse_library_keeps_items_without_downloads_with_no_formats():
    products = manning.parse_library(LIBRARY)
    assert products[2].title == "Algorithms in Motion"
    assert products[2].formats == ()


def test_parse_library_unrecognised_layout_raises():
    with pytest.raises(manning.DashboardError):
        manning.parse_library("<html><body>new dashboard</body></html>")


def test_fetch_library_requests_ajax_list(monkeypatch):
    session = FakeSession(get=[FakeResponse(LIBRARY)])
    assert manning.fetch_library(session) == LIBRARY
    method, url, kwargs = session.calls[0]
    assert url == manning.LIBRARY_URL
    assert kwargs["headers"]["X-Requested-With"] == "XMLHttpRequest"


@pytest.mark.parametrize("title, expected", [
    ("Terraform in Action", "Terraform_in_Action"),
    ("Free/Author Pick: C++", "Free_Author_Pick_C++"),
    ("../../etc", "etc"),
])
def test_safe_name(title, expected):
    assert manning.safe_name(title) == expected


@pytest.mark.parametrize("value, expected", [
    ("pdf,epub", ["pdf", "epub"]),
    (" EPUB , kindle ", ["epub", "kindle"]),
    ("all", ["pdf", "epub", "kindle", "epub3"]),
])
def test_parse_formats(value, expected):
    assert manning.parse_formats(value) == expected


def test_parse_formats_rejects_unknown_format():
    with pytest.raises(argparse.ArgumentTypeError, match="mobi"):
        manning.parse_formats("pdf,mobi")


def test_default_formats_are_pdf_and_epub():
    assert manning.parse_args([]).formats == ["pdf", "epub"]


# --------------------------------------------------------------------------- #
# Downloading
# --------------------------------------------------------------------------- #

def _product(title="Terraform in Action", product_id="3744", formats=("EPUB", "PDF"), version=None):
    return manning.Product(title, product_id, tuple(formats), version)


def _file_response(content=b"data", content_type="application/pdf", filename=None):
    headers = {"Content-Type": content_type}
    if filename:
        headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    return FakeResponse(headers=headers, content=content)


BOOK_DIR = "Terraform_in_Action"


def test_folder_names_unique_titles_unchanged():
    products = [_product("Rust in Action", "1"), _product("Go in Action", "2")]
    assert manning.folder_names(products) == ["Rust_in_Action", "Go_in_Action"]


def test_folder_names_disambiguates_collisions_with_product_id():
    products = [
        _product("C# in Depth", "10"),
        _product("C in Depth", "11"),
        _product("c in depth", "12"),   # case-insensitive filesystems (APFS default)
        _product("Unique", "13"),
    ]
    assert manning.folder_names(products) == [
        "C_in_Depth_10", "C_in_Depth_11", "c_in_depth_12", "Unique",
    ]


def test_download_file_gets_format_url_and_saves_with_format_extension(tmp_path):
    session = FakeSession(get=[_file_response(b"%PDF-1.7 data")])
    outcome = manning.download_file(session, _product(), "pdf", tmp_path)
    assert outcome.status == "downloaded"
    assert outcome.path == tmp_path / BOOK_DIR / f"{BOOK_DIR}.pdf"
    assert outcome.path.read_bytes() == b"%PDF-1.7 data"
    method, url, kwargs = session.calls[0]
    assert url == "https://www.manning.com/dashboard/download?productId=3744&downloadFormat=PDF"
    assert kwargs["stream"] is True
    assert not list(tmp_path.rglob("*.part"))


def test_download_file_pdf_and_epub_live_side_by_side(tmp_path):
    session = FakeSession(get=[_file_response(b"pdf"), _file_response(b"epub", "application/epub+zip")])
    manning.download_file(session, _product(), "pdf", tmp_path)
    manning.download_file(session, _product(), "epub", tmp_path)
    assert (tmp_path / BOOK_DIR / f"{BOOK_DIR}.pdf").read_bytes() == b"pdf"
    assert (tmp_path / BOOK_DIR / f"{BOOK_DIR}.epub").read_bytes() == b"epub"


def test_download_file_kindle_uses_server_extension(tmp_path):
    session = FakeSession(get=[_file_response(b"k", "application/octet-stream", filename="go.azw3")])
    product = _product(formats=("KINDLE",))
    assert manning.download_file(session, product, "kindle", tmp_path).path.name == f"{BOOK_DIR}.azw3"


def test_download_file_epub3_does_not_overwrite_epub(tmp_path):
    session = FakeSession(get=[_file_response(b"e3", "application/epub+zip")])
    product = _product(formats=("EPUB", "EPUB3"))
    assert manning.download_file(session, product, "epub3", tmp_path).path.name == f"{BOOK_DIR}-epub3.epub"


def test_download_file_skips_existing_file_without_request(tmp_path):
    existing = tmp_path / BOOK_DIR / f"{BOOK_DIR}.pdf"
    existing.parent.mkdir()
    existing.write_bytes(b"old")
    session = FakeSession()
    outcome = manning.download_file(session, _product(), "pdf", tmp_path)
    assert (outcome.status, outcome.path) == ("skipped", existing)
    assert session.calls == []


def test_download_file_force_replaces_existing(tmp_path):
    existing = tmp_path / BOOK_DIR / f"{BOOK_DIR}.pdf"
    existing.parent.mkdir()
    existing.write_bytes(b"old")
    session = FakeSession(get=[_file_response(b"new")])
    assert manning.download_file(session, _product(), "pdf", tmp_path, force=True).status == "downloaded"
    assert existing.read_bytes() == b"new"


def test_download_file_rejects_html_response(tmp_path):
    session = FakeSession(get=[_file_response(b"<html>login</html>", "text/html; charset=UTF-8")])
    with pytest.raises(manning.DownloadError, match="web page"):
        manning.download_file(session, _product(), "pdf", tmp_path)
    assert not [p for p in tmp_path.rglob("*") if p.is_file()]


def test_download_file_http_error_leaves_no_partial_file(tmp_path):
    session = FakeSession(get=[FakeResponse(status_code=500)])
    with pytest.raises(manning.DownloadError):
        manning.download_file(session, _product(), "pdf", tmp_path)
    assert not list(tmp_path.rglob("*.part"))


def test_download_file_filesystem_error_becomes_download_error(tmp_path):
    (tmp_path / BOOK_DIR).write_text("a file where the book folder should go")
    with pytest.raises(manning.DownloadError, match="Terraform in Action"):
        manning.download_file(FakeSession(), _product(), "pdf", tmp_path)


# --------------------------------------------------------------------------- #
# Update decisions (recorded versions)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("exists, recorded, current, force, update, expected", [
    (False, manning.NOT_RECORDED, None, False, False, True),    # new file
    (True, manning.NOT_RECORDED, None, False, False, False),    # present: skip
    (True, "v1", "v2", False, False, False),                    # newer MEAP, but no --update
    (True, "v1", "v2", False, True, True),                      # newer MEAP with --update
    (True, "v2", "v2", False, True, False),                     # same version
    (True, manning.NOT_RECORDED, "v2", False, True, True),      # MEAP never recorded: refresh once
    (True, manning.NOT_RECORDED, None, False, True, False),     # finished book, no version info
    (True, "v2", "v2", True, False, True),                      # --force always
])
def test_needs_download(exists, recorded, current, force, update, expected):
    assert manning.needs_download(exists, recorded, current, force=force, update=update) is expected


def test_state_round_trip(tmp_path):
    assert manning.load_state(tmp_path) == {}
    manning.save_state(tmp_path, {"3744": {"PDF": "version: 5"}})
    assert manning.load_state(tmp_path) == {"3744": {"PDF": "version: 5"}}


def test_load_state_ignores_corrupt_file(tmp_path):
    (tmp_path / manning.STATE_FILE).write_text("{not json")
    assert manning.load_state(tmp_path) == {}


def test_download_file_update_redownloads_newer_meap_version(tmp_path):
    existing = tmp_path / BOOK_DIR / f"{BOOK_DIR}.pdf"
    existing.parent.mkdir()
    existing.write_bytes(b"v4")
    state = {"3744": {"PDF": "version: 4"}}
    session = FakeSession(get=[_file_response(b"v5")])
    product = _product(version="version: 5")
    outcome = manning.download_file(session, product, "pdf", tmp_path, update=True, state=state)
    assert outcome.status == "downloaded"
    assert existing.read_bytes() == b"v5"
    assert state["3744"]["PDF"] == "version: 5"


def test_download_file_update_skips_same_version_without_request(tmp_path):
    existing = tmp_path / BOOK_DIR / f"{BOOK_DIR}.pdf"
    existing.parent.mkdir()
    existing.write_bytes(b"v5")
    session = FakeSession()
    state = {"3744": {"PDF": "version: 5"}}
    outcome = manning.download_file(session, _product(version="version: 5"), "pdf", tmp_path,
                                    update=True, state=state)
    assert outcome.status == "skipped"
    assert session.calls == []


def test_download_file_records_version_in_state(tmp_path):
    state = {}
    session = FakeSession(get=[_file_response()])
    manning.download_file(session, _product(version="version: 2"), "pdf", tmp_path, state=state)
    assert state == {"3744": {"PDF": "version: 2"}}


# --------------------------------------------------------------------------- #
# download_all
# --------------------------------------------------------------------------- #

def test_download_all_fetches_each_requested_format_offered(tmp_path):
    products = [_product(formats=("EPUB", "KINDLE", "PDF")), _product("PDF Only", "12", formats=("PDF",))]
    session = FakeSession(get=[_file_response(), _file_response(), _file_response()])
    summary = manning.download_all(session, products, tmp_path, ["pdf", "epub"], sleep=lambda s: None)
    assert (summary.downloaded, summary.skipped, summary.failed) == (3, 0, 0)
    urls = [url for _, url, _ in session.calls]
    assert not any("KINDLE" in u for u in urls)
    assert (tmp_path / "PDF_Only" / "PDF_Only.pdf").exists()
    assert manning.load_state(tmp_path)["12"] == {"PDF": None}


def test_download_all_continues_after_failures_and_counts_them(tmp_path):
    (tmp_path / "Broken").write_text("blocks folder creation")
    products = [_product("Broken", "1", formats=("PDF",)), _product("Good Book", "2", formats=("PDF",))]
    session = FakeSession(get=[_file_response(b"ok")])
    summary = manning.download_all(session, products, tmp_path, ["pdf"], sleep=lambda s: None)
    assert (summary.downloaded, summary.failed) == (1, 1)
    assert (tmp_path / "Good_Book" / "Good_Book.pdf").read_bytes() == b"ok"


def test_download_all_pauses_only_between_network_downloads(tmp_path):
    existing = tmp_path / BOOK_DIR / f"{BOOK_DIR}.pdf"
    existing.parent.mkdir()
    existing.write_bytes(b"old")  # skipped: no request, no pause
    products = [_product(formats=("PDF",)), _product("Book A", "1", formats=("PDF",)),
                _product("Book B", "2", formats=("PDF",))]
    session = FakeSession(get=[_file_response(), _file_response()])
    pauses = []
    summary = manning.download_all(session, products, tmp_path, ["pdf"], delay=2.5, sleep=pauses.append)
    assert (summary.downloaded, summary.skipped, summary.failed) == (2, 1, 0)
    assert pauses == [2.5]


def test_download_all_logs_progress_in_plain_language(tmp_path, caplog):
    caplog.set_level("INFO", logger="manning")
    session = FakeSession(get=[_file_response(b"x" * 2048)])
    manning.download_all(session, [_product(formats=("PDF",))], tmp_path, ["pdf"], sleep=lambda s: None)
    assert "(1/1) Terraform in Action [pdf]" in caplog.text
    assert "saved" in caplog.text and "KB" in caplog.text


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


def _run_main(monkeypatch, session, *extra):
    monkeypatch.setattr(manning.requests, "Session", lambda: session)
    monkeypatch.setattr(manning, "login", lambda s, u, p: None)
    monkeypatch.setattr(manning, "read_keychain", lambda service, account=None: ("me@x.com", "pw"))
    return manning.main(["-k", "manning", "--delay", "0", *extra])


def test_main_saves_library_page_when_layout_unrecognised(monkeypatch, tmp_path, caplog):
    caplog.set_level("INFO", logger="manning")
    html = "<html>completely new dashboard</html>"
    session = FakeSessionCM(get=[FakeResponse(html)])
    assert _run_main(monkeypatch, session, "-o", str(tmp_path)) == 1
    saved = tmp_path / manning.LIBRARY_DEBUG_FILE
    assert saved.read_text() == html
    assert str(saved) in caplog.text


def test_main_list_shows_books_without_downloading(monkeypatch, tmp_path, caplog):
    caplog.set_level("INFO", logger="manning")
    session = FakeSessionCM(get=[FakeResponse(LIBRARY)])
    assert _run_main(monkeypatch, session, "-o", str(tmp_path / "out"), "--list") == 0
    assert len(session.calls) == 1  # only the library request
    assert not (tmp_path / "out").exists()
    assert "AI Model Evaluation" in caplog.text
    assert "epub, kindle, pdf" in caplog.text
    assert "version: 5, last updated: 2026-09-14" in caplog.text


def test_main_explains_each_step(monkeypatch, tmp_path, caplog):
    caplog.set_level("INFO", logger="manning")
    # 3 books with files, requested pdf+epub: 2 + 2 + 1 (PDF only) = 5 files.
    session = FakeSessionCM(get=[FakeResponse(LIBRARY)] + [_file_response() for _ in range(5)])
    assert _run_main(monkeypatch, session, "-o", str(tmp_path)) == 0
    text = caplog.text
    for expected in ("macOS Keychain", "Signing in", "me@x.com", "library",
                     "Found 3 books with downloadable files", "1 item without files",
                     "pdf, epub", "Downloaded 5"):
        assert expected in text, expected
