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
                        keychain_reader: Callable[[str, str | None], tuple[str, str]] = read_keychain,
                        prompt_username: Callable[[str], str] = input,
                        prompt_password: Callable[[str], str] = getpass.getpass,
                        is_interactive: Callable[[], bool] = lambda: sys.stdin.isatty(),
                        ) -> tuple[str, str]:
    """Pick the credential source: Keychain, then -p, then an interactive getpass prompt."""
    if args.keychain and args.password:
        raise CredentialError('Use either --keychain or -p/--password, not both.')
    if args.keychain:
        return keychain_reader(args.keychain, args.username)
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


def download_product(session: requests.Session, product: Product, out_dir: Path, name: str | None = None,
                     force: bool = False, update: bool = False) -> Path | None:
    """Download one product into out_dir/<name>/<name>.<ext>.

    Returns the file path, or None when skipped. Existing books are skipped
    without any request, unless:
      - force:  always download again;
      - update: ask the server and download again only if the size differs
                (or the server does not say), replacing the old file.
    Data is streamed into a .part file and renamed only on success, so an
    interrupted run never leaves a truncated book that later runs would skip.
    Any network or filesystem problem is raised as DownloadError.
    """
    name = name or safe_name(product.title)
    book_dir = out_dir / name
    tmp = book_dir / f'{name}.part'
    try:
        existing = [p for p in book_dir.glob(f'{name}.*') if p.suffix != '.part']
        if existing and not (force or update):
            log.info('Skipping %s (already downloaded; use --update to check for a newer version)', product.title)
            return None

        book_dir.mkdir(parents=True, exist_ok=True)
        with session.post(DOWNLOAD_URL.format(external_id=product.external_id),
                          data=product.payload, stream=True, timeout=TIMEOUT) as resp:
            resp.raise_for_status()
            if resp.headers.get('Content-Type', '').startswith('text/html'):
                raise DownloadError(f'Got an HTML page instead of a file for "{product.title}" '
                                    '(session expired or download form changed).')
            if update and not force and existing and _same_size(existing, resp.headers):
                log.info('Skipping %s (unchanged)', product.title)
                return None
            log.info('Downloading %s ...', product.title)
            with tmp.open('wb') as fh:
                for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                    fh.write(chunk)
            extension = _extension_from_headers(resp.headers) or product.guessed_extension

        target = book_dir / f'{name}{extension}'
        tmp.replace(target)
        # A new version may come with a different extension (e.g. pdf -> zip).
        for old in existing:
            if old != target:
                old.unlink(missing_ok=True)
        return target
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
                 force: bool = False, update: bool = False) -> int:
    """Download every product, continuing past failures. Returns the failure count."""
    failures = 0
    for product, name in zip(products, folder_names(products)):
        try:
            download_product(session, product, out_dir, name=name, force=force, update=update)
        except DownloadError as e:
            failures += 1
            log.error('%s', e)
    return failures


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
    parser.add_argument('--user-agent', default=DEFAULT_USER_AGENT, help='HTTP User-Agent header to send')
    parser.add_argument('-v', '--verbose', action='store_true', help='debug logging')
    return parser.parse_args(list(argv) if argv is not None else None)


def main(argv: Iterable[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format='%(message)s')

    try:
        username, password = resolve_credentials(args)
        with requests.Session() as session:
            session.headers['User-Agent'] = args.user_agent
            login(session, username, password)
            log.info('Logged in as %s', username)

            dashboard = session.get(DASHBOARD_URL, timeout=TIMEOUT)
            dashboard.raise_for_status()
            products = parse_dashboard(dashboard.text)
            log.info('Found %d downloadable books', len(products))

            args.output.mkdir(parents=True, exist_ok=True)
            failures = download_all(session, products, args.output, force=args.force, update=args.update)
    # OSError covers requests exceptions and an unwritable output directory.
    except (CredentialError, LoginError, DashboardError, OSError) as e:
        log.error('Error: %s', e)
        return 1

    log.info('Done: %d books, %d failed. Output: %s', len(products), failures, args.output.resolve())
    return 1 if failures else 0


if __name__ == '__main__':
    sys.exit(main())
