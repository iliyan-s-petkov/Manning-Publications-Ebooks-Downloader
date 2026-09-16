#!/usr/bin/env python3
"""
Download all ebooks from your Manning Publications dashboard.

Requires Python 3.10+.

Original author: Lucian Maly (2020)
License: MIT
"""

import argparse
import contextlib
import datetime
import getpass
import logging
import re
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# Manning uses a CAS single sign-on server. The `service` parameter is where CAS
# sends the browser back to (with a ticket) after a successful login, which is
# what establishes the session cookie on www.manning.com.
LOGIN_URL = 'https://login.manning.com/login?service=https://www.manning.com/login/cas'
DASHBOARD_URL = 'https://www.manning.com/dashboard/index?filter=book&max=999&order=lastUpdated&sort=desc'
DOWNLOAD_URL = 'https://www.manning.com/dashboard/download?id=downloadForm-{external_id}'

# A browser-like User-Agent: some sites serve different pages (or block) generic
# HTTP clients. The exact version rarely matters; override with --user-agent.
DEFAULT_USER_AGENT = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36')
TIMEOUT = 60  # seconds, per request (connect/read), not total download time
CHUNK_SIZE = 1024 * 256
# Pause between downloads. Rapid automated requests can get your IP temporarily
# blocked by Manning's servers, so be gentle by default.
DEFAULT_DELAY = 2.0
# Written into the output folder when the dashboard cannot be parsed, so the page
# can be inspected and the parser updated.
DASHBOARD_DEBUG_FILE = 'dashboard-debug.html'

log = logging.getLogger('manning')


class CredentialError(Exception):
    pass


class LoginError(Exception):
    pass


class DashboardError(Exception):
    pass


class DownloadError(Exception):
    pass


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #

Runner = Callable[..., subprocess.CompletedProcess]


def _security(args: list[str], run: Runner) -> subprocess.CompletedProcess:
    try:
        return run(['security', *args], capture_output=True, text=True, check=False)
    except FileNotFoundError as e:
        raise CredentialError('The `security` tool was not found; Keychain lookup only works on macOS.') from e


def _decode_security_value(raw: str) -> str | None:
    """Decode a value as printed by `security find-generic-password -g`.

    Printable ASCII is shown verbatim inside quotes (embedded quotes are not
    escaped), e.g.  "pa"ss"  ->  pa"ss
    Anything else is shown as hex followed by an escaped preview, e.g.
        0x70C3A47373776F7274  "p\\303\\244sswort"  ->  pässwort
    The 0x prefix makes this unambiguous, unlike `-w`, which prints non-ASCII
    passwords as bare hex that is indistinguishable from a password like "cafe1234".
    Returns None for missing values (empty or <NULL>).
    """
    raw = raw.rstrip('\n')
    if raw.startswith('0x'):
        hex_digits = raw[2:].split(maxsplit=1)[0] if raw[2:].strip() else ''
        try:
            return bytes.fromhex(hex_digits).decode('utf-8')
        except (ValueError, UnicodeDecodeError) as e:
            raise CredentialError('Could not decode a Keychain value (not valid UTF-8).') from e
    if len(raw) >= 2 and raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    return None


def read_keychain(service: str, account: str | None = None, run: Runner = subprocess.run) -> tuple[str, str]:
    """Return (account, password) for a generic password item in the macOS Keychain.

    If `account` is omitted, the account name stored in the item itself is used,
    so a single `--keychain manning` flag is enough to log in.
    """
    cmd = ['find-generic-password', '-s', service, *(['-a', account] if account else []), '-g']
    result = _security(cmd, run)
    if result.returncode != 0:
        which = f'service "{service}"' + (f' and account "{account}"' if account else '')
        raise CredentialError(f'No Keychain item found for {which}.')

    # With -g, item attributes go to stdout and the secret to stderr as "password: <value>".
    if account is None:
        match = re.search(r'^\s*"acct"<blob>=(.*)$', result.stdout, re.MULTILINE)
        account = _decode_security_value(match.group(1)) if match else None
        if not account:
            raise CredentialError(f'Keychain item "{service}" has no account; pass -u/--username.')

    # The password may itself contain newlines, so take everything after the prefix.
    match = re.search(r'^password: (.*)\Z', result.stderr, re.MULTILINE | re.DOTALL)
    password = _decode_security_value(match.group(1)) if match else None
    if not password:
        raise CredentialError(f'Keychain item "{service}" has an empty password.')
    return account, password


def resolve_credentials(args: argparse.Namespace,
                        keychain_reader: Callable[[str, str | None], tuple[str, str]] | None = None,
                        prompt_username: Callable[[str], str] = input,
                        prompt_password: Callable[[str], str] = getpass.getpass,
                        is_interactive: Callable[[], bool] = lambda: sys.stdin.isatty(),
                        ) -> tuple[str, str]:
    """Pick the credential source: Keychain, then -p, then an interactive getpass prompt."""
    if args.keychain and args.password:
        raise CredentialError('Use either --keychain or -p/--password, not both.')
    if args.keychain:
        # Resolved at call time (not as a default argument) so it can be swapped in tests.
        return (keychain_reader or read_keychain)(args.keychain, args.username)
    if args.password:
        if not args.username:
            raise CredentialError('-p/--password requires -u/--username.')
        log.warning('Passing the password on the command line exposes it in shell history '
                    'and the process list; prefer --keychain or the interactive prompt.')
        return args.username, args.password

    # No stored secret given: ask on the terminal. Refuse when stdin is not a TTY
    # (cron, pipes) so the script fails fast instead of hanging on a hidden prompt.
    if not is_interactive():
        raise CredentialError('No credentials given and not running interactively. '
                              'Use --keychain SERVICE or -u EMAIL -p PASSWORD.')
    username = args.username or prompt_username('Manning email: ').strip()
    password = prompt_password(f'Manning password for {username}: ')
    if not username or not password:
        raise CredentialError('Email and password must not be empty.')
    return username, password


# --------------------------------------------------------------------------- #
# Login
# --------------------------------------------------------------------------- #

def login_form_fields(html: str, page_url: str) -> tuple[str, dict[str, str]]:
    """Return the sign-in form's absolute action URL and its hidden fields.

    Manning's CAS server issues one-time tokens (formerly `lt`, now `execution`)
    as hidden inputs. Copying every hidden input keeps this working when those
    names change again.
    """
    form = BeautifulSoup(html, 'html.parser').find('form', id='fm1')
    if form is None:
        raise LoginError('Sign-in form not found on the login page; Manning may have changed its site.')
    fields = {
        inp['name']: inp.get('value', '')
        for inp in form.find_all('input', type='hidden')
        if inp.get('name')
    }
    return urljoin(page_url, form.get('action', '')), fields


def login(session: requests.Session, username: str, password: str) -> None:
    page = session.get(LOGIN_URL, timeout=TIMEOUT)
    action, fields = login_form_fields(page.text, getattr(page, 'url', None) or LOGIN_URL)
    data = {**fields, 'username': username, 'password': password}
    resp = session.post(action, data=data, headers={'Origin': 'https://login.manning.com'}, timeout=TIMEOUT)

    # CAS answers a failed login by re-rendering the sign-in form (usually with 401).
    if resp.status_code in (401, 403) or BeautifulSoup(resp.text, 'html.parser').find('form', id='fm1'):
        raise LoginError('Login failed: check your email/password.')


# --------------------------------------------------------------------------- #
# Dashboard
# --------------------------------------------------------------------------- #

@dataclass
class Product:
    title: str
    external_id: str
    payload: list[tuple[str, str]] = field(default_factory=list)

    @property
    def guessed_extension(self) -> str:
        # Some free titles are PDF-only: they have a single format selection, so the
        # payload is the 2 base entries + 2 per format. Anything more is a zip bundle.
        return '.pdf' if len(self.payload) <= 4 else '.zip'


def _build_payload(external_id: str, row) -> list[tuple[str, str]]:
    # EXAMPLE: [('dropbox', 'false'), ('productExternalId', 'winkler'),
    #           ('1971', '7850702'), ('winkler-restrictedDownloadIds', '1971'), ...]
    payload = [('dropbox', 'false'), ('productExternalId', external_id)]
    for selection in row.find_all('div', class_='download-selection'):
        for hidden in selection.find_all('input', type='hidden'):
            payload.append((hidden['id'], hidden['value']))
            payload.append((f'{external_id}-restrictedDownloadIds', hidden['id']))
    return payload


def parse_dashboard(html: str) -> list[Product]:
    table = BeautifulSoup(html, 'html.parser').find('table', id='productTable')
    if table is None:
        raise DashboardError('Product table not found on the dashboard; Manning may have changed its site.')

    products = []
    for row in table.find_all('tr', class_='license-row'):
        title_div = row.find('div', class_='product-title')
        form = row.find('form', class_='download-form')
        if title_div is None or form is None or '-' not in form.get('name', ''):
            continue  # e.g. subscriptions or items without downloadable files
        # Form name is "downloadForm-<externalId>"; the id itself may contain dashes.
        external_id = form['name'].split('-', 1)[1]
        products.append(Product(title_div.get_text(strip=True), external_id, _build_payload(external_id, row)))
    return products


# --------------------------------------------------------------------------- #
# Download
# --------------------------------------------------------------------------- #

def safe_name(title: str) -> str:
    """Turn a book title into a safe single path component (no separators or '..')."""
    name = re.sub(r'[^\w.+\-]+', '_', title).strip('._')
    return name or 'untitled'


def folder_names(products: Sequence[Product]) -> list[str]:
    """Return one folder name per product, guaranteed not to collide.

    Different titles can sanitize to the same name ("C# in Depth" / "C in Depth"),
    and macOS filesystems are case-insensitive by default. Colliding names get the
    product id appended; unique titles keep their plain name so existing download
    folders are still recognised.
    """
    names = [safe_name(p.title) for p in products]
    counts = Counter(n.casefold() for n in names)
    return [
        f'{name}_{safe_name(product.external_id)}' if counts[name.casefold()] > 1 else name
        for name, product in zip(names, products)
    ]


def _extension_from_headers(headers) -> str | None:
    disposition = headers.get('Content-Disposition', '')
    match = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', disposition)
    if match:
        suffix = Path(match.group(1)).suffix.lower()
        if suffix:
            return suffix
    return None


def _same_size(existing: list[Path], headers) -> bool:
    length = headers.get('Content-Length', '')
    return length.isdigit() and any(p.stat().st_size == int(length) for p in existing)


@dataclass
class Outcome:
    """Result of handling one book: 'downloaded', 'skipped' (already on disk) or 'unchanged'."""
    status: str
    path: Path | None = None
    size: int = 0


@dataclass
class Summary:
    downloaded: int = 0
    skipped: int = 0
    unchanged: int = 0
    failed: int = 0


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ('B', 'KB', 'MB'):
        if size < 1024:
            return f'{size:.0f} {unit}' if unit == 'B' else f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} GB'


def download_product(session: requests.Session, product: Product, out_dir: Path, name: str | None = None,
                     force: bool = False, update: bool = False, label: str | None = None) -> Outcome:
    """Download one product into out_dir/<name>/<name>.<ext>.

    Existing books are skipped without any request, unless:
      - force:  always download again;
      - update: ask the server and download again only if the size differs
                (or the server does not say), replacing the old file.
    Data is streamed into a .part file and renamed only on success, so an
    interrupted run never leaves a truncated book that later runs would skip.
    Any network or filesystem problem is raised as DownloadError.
    """
    name = name or safe_name(product.title)
    label = label or product.title
    book_dir = out_dir / name
    tmp = book_dir / f'{name}.part'
    try:
        existing = [p for p in book_dir.glob(f'{name}.*') if p.suffix != '.part']
        if existing and not (force or update):
            log.info('%s: already downloaded, skipping', label)
            return Outcome('skipped', existing[0])

        book_dir.mkdir(parents=True, exist_ok=True)
        if update and existing:
            log.info('%s: checking whether Manning has a newer version...', label)
        else:
            log.info('%s: downloading...', label)
        with session.post(DOWNLOAD_URL.format(external_id=product.external_id),
                          data=product.payload, stream=True, timeout=TIMEOUT) as resp:
            resp.raise_for_status()
            if resp.headers.get('Content-Type', '').startswith('text/html'):
                raise DownloadError(f'Got a web page instead of a file for "{product.title}" '
                                    '(the session may have expired or the download form changed).')
            if update and not force and existing and _same_size(existing, resp.headers):
                log.info('%s: same size as your copy, skipping', label)
                return Outcome('unchanged', existing[0])
            size = 0
            with tmp.open('wb') as fh:
                for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                    fh.write(chunk)
                    size += len(chunk)
            extension = _extension_from_headers(resp.headers) or product.guessed_extension

        target = book_dir / f'{name}{extension}'
        tmp.replace(target)
        # A new version may come with a different extension (e.g. pdf -> zip).
        for old in existing:
            if old != target:
                old.unlink(missing_ok=True)
        log.info('%s: saved %s (%s)', label, target.name, human_size(size))
        return Outcome('downloaded', target, size)
    # requests exceptions subclass OSError, so they must be handled first.
    except requests.RequestException as e:
        _discard(tmp)
        raise DownloadError(f'Download failed for "{product.title}": {e}') from e
    except OSError as e:
        _discard(tmp)
        raise DownloadError(f'Could not save "{product.title}": {e}') from e
    except BaseException:
        _discard(tmp)
        raise


def _discard(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink(missing_ok=True)


def download_all(session: requests.Session, products: Sequence[Product], out_dir: Path,
                 force: bool = False, update: bool = False, delay: float = DEFAULT_DELAY,
                 sleep: Callable[[float], None] = time.sleep) -> Summary:
    """Download every product, continuing past failures.

    Pauses `delay` seconds before a book only if the previous book contacted the
    server; books skipped from disk cost no request and need no pause.
    """
    summary = Summary()
    total = len(products)
    previous_used_network = False
    for index, (product, name) in enumerate(zip(products, folder_names(products)), start=1):
        if previous_used_network and delay > 0:
            sleep(delay)
        label = f'({index}/{total}) {product.title}'
        try:
            outcome = download_product(session, product, out_dir, name=name,
                                       force=force, update=update, label=label)
        except DownloadError as e:
            summary.failed += 1
            previous_used_network = True  # most failures happen after a request was made
            log.error('(%d/%d) %s', index, total, e)
            continue
        setattr(summary, outcome.status, getattr(summary, outcome.status) + 1)
        previous_used_network = outcome.status != 'skipped'
    return summary


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description='Download all ebooks from your Manning dashboard.')
    parser.add_argument('-k', '--keychain', metavar='SERVICE',
                        help='read credentials from the macOS Keychain generic password item with this service name')
    parser.add_argument('-u', '--username', metavar='EMAIL',
                        help='Manning account email (optional with --keychain; prompted if omitted)')
    parser.add_argument('-p', '--password', help='Manning password (insecure: visible in shell history)')
    parser.add_argument('-o', '--output', type=Path,
                        default=Path(f'Manning_{datetime.date.today():%Y-%m-%d}'),
                        help='output directory (default: Manning_<today>)')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('-f', '--force', action='store_true', help='re-download all books, even if they exist')
    mode.add_argument('-U', '--update', action='store_true',
                      help='re-download existing books only when the server reports a different size')
    parser.add_argument('--delay', type=float, default=DEFAULT_DELAY, metavar='SECONDS',
                        help=f'pause between downloads to avoid being rate-limited (default: {DEFAULT_DELAY:g})')
    parser.add_argument('--user-agent', default=DEFAULT_USER_AGENT, help='HTTP User-Agent header to send')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='more detail; -vv also shows every HTTP request')
    return parser.parse_args(list(argv) if argv is not None else None)


class _Formatter(logging.Formatter):
    """Plain messages for progress; a clear prefix for warnings and errors."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if record.levelno >= logging.ERROR:
            return f'Error: {message}'
        if record.levelno >= logging.WARNING:
            return f'Warning: {message}'
        return message


def _setup_logging(verbosity: int) -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(_Formatter('%(message)s'))
    root = logging.getLogger()
    # Replace only a handler we added earlier (main() may run more than once, e.g. in
    # tests) and leave other handlers, such as pytest's log capture, untouched.
    root.handlers[:] = [h for h in root.handlers if not isinstance(h.formatter, _Formatter)] + [handler]
    root.setLevel(logging.INFO)
    log.setLevel(logging.DEBUG if verbosity >= 1 else logging.INFO)
    # Raw connection logs from urllib3 are only useful when debugging HTTP itself.
    logging.getLogger('urllib3').setLevel(logging.DEBUG if verbosity >= 2 else logging.WARNING)


def _credential_source(args: argparse.Namespace) -> str:
    if args.keychain:
        return f'the macOS Keychain (item "{args.keychain}")'
    if args.password:
        return 'the command line'
    return 'the terminal prompt'


def _save_dashboard(html: str, out_dir: Path) -> Path | None:
    path = out_dir / DASHBOARD_DEBUG_FILE
    try:
        path.write_text(html, encoding='utf-8')
    except OSError:
        return None
    return path


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    _setup_logging(args.verbose)
    out_dir = args.output

    try:
        log.info('[1/4] Reading your Manning login from %s...', _credential_source(args))
        username, password = resolve_credentials(args)

        with requests.Session() as session:
            session.headers['User-Agent'] = args.user_agent
            log.info('[2/4] Signing in to Manning as %s...', username)
            login(session, username, password)
            log.info('      Signed in.')

            log.info('[3/4] Loading your library from the Manning dashboard...')
            dashboard = session.get(DASHBOARD_URL, timeout=TIMEOUT)
            dashboard.raise_for_status()
            out_dir.mkdir(parents=True, exist_ok=True)
            try:
                products = parse_dashboard(dashboard.text)
            except DashboardError as e:
                products, reason = [], str(e)
            else:
                reason = 'No downloadable books were found on the dashboard.'
            if not products:
                saved = _save_dashboard(dashboard.text, out_dir)
                log.error('%s Manning has probably changed the page layout, so the script needs updating.', reason)
                if saved:
                    log.error('The dashboard page was saved to %s; share it so the parser can be fixed.', saved)
                return 1
            log.info('      Found %d books with downloadable files.', len(products))

            log.info('[4/4] Downloading into %s (pausing %gs between downloads)...', out_dir.resolve(), args.delay)
            summary = download_all(session, products, out_dir,
                                   force=args.force, update=args.update, delay=args.delay)
    # OSError covers requests exceptions and an unwritable output directory.
    except (CredentialError, LoginError, OSError) as e:
        log.error('%s', e)
        return 1

    log.info('')
    log.info('Done. Downloaded %d, skipped %d (already present), unchanged %d, failed %d.',
             summary.downloaded, summary.skipped, summary.unchanged, summary.failed)
    if summary.skipped and not args.update:
        log.info('Tip: run with --update to check skipped books for newer versions.')
    if summary.failed:
        log.info('Run the same command again to retry the failed books.')
    return 1 if summary.failed else 0


if __name__ == '__main__':
    sys.exit(main())
