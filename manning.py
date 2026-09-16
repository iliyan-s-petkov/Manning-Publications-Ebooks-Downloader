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
import json
import logging
import re
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, urljoin, urlparse

import requests
from bs4 import BeautifulSoup

# Manning uses a CAS single sign-on server. The `service` parameter is where CAS
# sends the browser back to (with a ticket) after a successful login, which is
# what establishes the session cookie on www.manning.com.
LOGIN_URL = 'https://login.manning.com/login?service=https://www.manning.com/login/cas'
# The dashboard page is only a shell; its JavaScript loads the book list from this
# endpoint (all items in one response, no paging).
LIBRARY_URL = ('https://www.manning.com/dashboard/getLicensesAjax'
               '?isDropboxIntegrated=&order=lastUpdated&sort=desc&filter=book')
DOWNLOAD_URL = 'https://www.manning.com/dashboard/download?productId={product_id}&downloadFormat={code}'

# A browser-like User-Agent: some sites serve different pages (or block) generic
# HTTP clients. The exact version rarely matters; override with --user-agent.
DEFAULT_USER_AGENT = ('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
                      '(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36')
TIMEOUT = 60  # seconds, per request (connect/read), not total download time
CHUNK_SIZE = 1024 * 256
# Pause between downloads. Rapid automated requests can get your IP temporarily
# blocked by Manning's servers, so be gentle by default.
DEFAULT_DELAY = 2.0
# Written into the output folder when the book list cannot be parsed, so the page
# can be inspected and the parser updated.
LIBRARY_DEBUG_FILE = 'library-debug.html'
# Remembers which MEAP version of each file was downloaded, for --update.
STATE_FILE = '.manning-downloads.json'

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
# Library
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class Format:
    code: str                    # value of the downloadFormat URL parameter
    extensions: tuple[str, ...]  # accepted file extensions; the first is the fallback
    suffix: str = ''             # added to the file name to keep formats apart


# Keys are the names used on the command line (--formats).
FORMATS = {
    'pdf': Format('PDF', ('.pdf',)),
    'epub': Format('EPUB', ('.epub',)),
    'kindle': Format('KINDLE', ('.mobi', '.azw3', '.azw', '.kfx')),
    # A few books offer an extra EPUB 3 edition; keep it next to the regular epub.
    'epub3': Format('EPUB3', ('.epub',), '-epub3'),
}
DEFAULT_FORMATS = ['pdf', 'epub']


@dataclass
class Product:
    title: str
    product_id: str
    formats: tuple[str, ...] = ()  # downloadFormat codes offered, e.g. ('EPUB', 'PDF')
    version: str | None = None     # MEAP "version: N, last updated: YYYY-MM-DD"; None when final


def fetch_library(session: requests.Session) -> str:
    # The header mirrors what the dashboard's own JavaScript sends.
    resp = session.get(LIBRARY_URL, headers={'X-Requested-With': 'XMLHttpRequest'}, timeout=TIMEOUT)
    resp.raise_for_status()
    return resp.text


def _text(tag) -> str:
    return ' '.join(tag.get_text(' ').split()) if tag else ''


def parse_library(html: str) -> list[Product]:
    """Parse the getLicensesAjax response into products (in dashboard order).

    Each item is a `div.product-data-column` holding the title, an optional MEAP
    version line and one dropdown per format whose link is
    /dashboard/download?productId=N&downloadFormat=FMT. Items without such links
    (video courses, liveProjects) are returned with no formats.
    """
    columns = BeautifulSoup(html, 'html.parser').select('div.product-data-column')
    if not columns:
        raise DashboardError('No books found in the library response; Manning may have changed its site.')

    products = []
    for column in columns:
        title_div = column.select_one('.product-title')
        if title_div is None:
            continue
        # The title div also contains badge links; only its own text is the title.
        title = ' '.join(''.join(title_div.find_all(string=True, recursive=False)).split())
        product_id, formats = None, []
        for link in column.select('a[href*="downloadFormat="]'):
            query = parse_qs(urlparse(link['href']).query)
            product_id = product_id or query.get('productId', [None])[0]
            code = query.get('downloadFormat', [''])[0].upper()
            if code and code not in formats:
                formats.append(code)
        version = _text(column.select_one('.meap-last-updated')) or None
        products.append(Product(title, product_id or '', tuple(formats), version))
    return products


# --------------------------------------------------------------------------- #
# Download state (for --update)
# --------------------------------------------------------------------------- #

# Distinguishes "never recorded" from a recorded None (a finished book).
NOT_RECORDED = object()

State = dict[str, dict[str, str | None]]  # product id -> format code -> version


def load_state(out_dir: Path) -> State:
    try:
        data = json.loads((out_dir / STATE_FILE).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def save_state(out_dir: Path, state: State) -> None:
    # Write to a temp file first so an interrupted run never leaves broken JSON.
    path = out_dir / STATE_FILE
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(state, indent=1, sort_keys=True), encoding='utf-8')
    tmp.replace(path)


def needs_download(exists: bool, recorded, current: str | None, force: bool = False, update: bool = False) -> bool:
    """Decide whether to fetch a file.

    Manning only tells us a version for MEAP (early access) books, so --update can
    only detect changes there: it re-downloads when the dashboard shows a different
    version than the one recorded when the file was saved. Files saved before the
    version was recorded are refreshed once.
    """
    if force or not exists:
        return True
    return update and current is not None and recorded != current


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
        f'{name}_{safe_name(product.product_id)}' if counts[name.casefold()] > 1 else name
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


@dataclass
class Outcome:
    """Result of handling one file: 'downloaded' or 'skipped' (kept the copy on disk)."""
    status: str
    path: Path | None = None
    size: int = 0


@dataclass
class Summary:
    downloaded: int = 0
    skipped: int = 0
    failed: int = 0


def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ('B', 'KB', 'MB'):
        if size < 1024:
            return f'{size:.0f} {unit}' if unit == 'B' else f'{size:.1f} {unit}'
        size /= 1024
    return f'{size:.1f} GB'


def download_file(session: requests.Session, product: Product, fmt_name: str, out_dir: Path,
                  name: str | None = None, force: bool = False, update: bool = False,
                  state: State | None = None, label: str | None = None) -> Outcome:
    """Download one format of a product into out_dir/<name>/<name><suffix>.<ext>.

    Whether an existing file is fetched again is decided by needs_download().
    Data is streamed into a .part file and renamed only on success, so an
    interrupted run never leaves a truncated book that later runs would skip.
    On success the product's current version is recorded in `state`.
    Any network or filesystem problem is raised as DownloadError.
    """
    fmt = FORMATS[fmt_name]
    name = name or safe_name(product.title)
    label = label or f'{product.title} [{fmt_name}]'
    state = {} if state is None else state
    book_dir = out_dir / name
    stem = f'{name}{fmt.suffix}'
    tmp = book_dir / f'{stem}.{fmt_name}.part'
    try:
        existing = [p for p in (book_dir / f'{stem}{ext}' for ext in fmt.extensions) if p.is_file()]
        recorded = state.get(product.product_id, {}).get(fmt.code, NOT_RECORDED)
        if not needs_download(bool(existing), recorded, product.version, force=force, update=update):
            log.info('%s: already downloaded, skipping', label)
            return Outcome('skipped', existing[0])

        if existing and not force:
            log.info('%s: Manning has a newer version (%s), downloading...', label, product.version)
        else:
            log.info('%s: downloading...', label)
        book_dir.mkdir(parents=True, exist_ok=True)
        url = DOWNLOAD_URL.format(product_id=product.product_id, code=fmt.code)
        with session.get(url, stream=True, timeout=TIMEOUT) as resp:
            resp.raise_for_status()
            if resp.headers.get('Content-Type', '').startswith('text/html'):
                raise DownloadError(f'Got a web page instead of a file for "{product.title}" [{fmt_name}] '
                                    '(the session may have expired or the download link changed).')
            size = 0
            with tmp.open('wb') as fh:
                for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                    fh.write(chunk)
                    size += len(chunk)
            extension = _extension_from_headers(resp.headers)

        if extension not in fmt.extensions:
            extension = fmt.extensions[0]
        target = book_dir / f'{stem}{extension}'
        tmp.replace(target)
        # A new version may come with a different extension (e.g. .mobi -> .azw3).
        for old in existing:
            if old != target:
                old.unlink(missing_ok=True)
        state.setdefault(product.product_id, {})[fmt.code] = product.version
        log.info('%s: saved %s (%s)', label, target.name, human_size(size))
        return Outcome('downloaded', target, size)
    # requests exceptions subclass OSError, so they must be handled first.
    except requests.RequestException as e:
        _discard(tmp)
        raise DownloadError(f'Download failed for "{product.title}" [{fmt_name}]: {e}') from e
    except OSError as e:
        _discard(tmp)
        raise DownloadError(f'Could not save "{product.title}" [{fmt_name}]: {e}') from e
    except BaseException:
        _discard(tmp)
        raise


def _discard(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink(missing_ok=True)


def download_all(session: requests.Session, products: Sequence[Product], out_dir: Path,
                 formats: Sequence[str] = DEFAULT_FORMATS, force: bool = False, update: bool = False,
                 delay: float = DEFAULT_DELAY, sleep: Callable[[float], None] = time.sleep) -> Summary:
    """Download the requested formats of every product, continuing past failures.

    Formats a book does not offer are silently left out. Pauses `delay` seconds
    before a file only if the previous file contacted the server; files skipped
    from disk cost no request and need no pause. The version state is saved after
    every download, so an interrupted run keeps what it recorded.
    """
    summary = Summary()
    state = load_state(out_dir)
    total = len(products)
    previous_used_network = False
    for index, (product, name) in enumerate(zip(products, folder_names(products)), start=1):
        for fmt_name in formats:
            if FORMATS[fmt_name].code not in product.formats:
                log.debug('(%d/%d) %s: no %s file offered', index, total, product.title, fmt_name)
                continue
            if previous_used_network and delay > 0:
                sleep(delay)
            label = f'({index}/{total}) {product.title} [{fmt_name}]'
            try:
                outcome = download_file(session, product, fmt_name, out_dir, name=name,
                                        force=force, update=update, state=state, label=label)
            except DownloadError as e:
                summary.failed += 1
                previous_used_network = True  # most failures happen after a request was made
                log.error('(%d/%d) %s', index, total, e)
                continue
            previous_used_network = outcome.status == 'downloaded'
            if outcome.status == 'downloaded':
                summary.downloaded += 1
                try:
                    save_state(out_dir, state)
                except OSError as e:
                    log.warning('Could not save download state (%s); --update may re-download this file.', e)
            else:
                summary.skipped += 1
    return summary


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_formats(value: str) -> list[str]:
    """Parse --formats: a comma-separated list of FORMATS keys, or 'all'."""
    if value.strip().lower() == 'all':
        return list(FORMATS)
    names = [part.strip().lower() for part in value.split(',') if part.strip()]
    unknown = [n for n in names if n not in FORMATS]
    if unknown or not names:
        raise argparse.ArgumentTypeError(
            f'unknown format {", ".join(unknown) or "(empty)"}; choose from {", ".join(FORMATS)} or all')
    return list(dict.fromkeys(names))  # drop duplicates, keep order


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
    parser.add_argument('-F', '--formats', type=parse_formats, default=list(DEFAULT_FORMATS), metavar='LIST',
                        help=f'comma-separated formats to download: {", ".join(FORMATS)} or all '
                             f'(default: {",".join(DEFAULT_FORMATS)})')
    parser.add_argument('-l', '--list', action='store_true',
                        help='only list your books and their formats; download nothing')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('-f', '--force', action='store_true', help='re-download all files, even if they exist')
    mode.add_argument('-U', '--update', action='store_true',
                      help='re-download early-access (MEAP) books when Manning shows a newer version')
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


def _save_debug_page(html: str, out_dir: Path) -> Path | None:
    path = out_dir / LIBRARY_DEBUG_FILE
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
        path.write_text(html, encoding='utf-8')
    except OSError:
        return None
    return path


def _format_names(product: Product) -> str:
    by_code = {fmt.code: key for key, fmt in FORMATS.items()}
    return ', '.join(by_code.get(code, code.lower()) for code in product.formats)


def _log_library(products: Sequence[Product]) -> None:
    width = len(str(len(products)))
    for index, product in enumerate(products, start=1):
        details = f'  ({product.version})' if product.version else ''
        log.info('  %*d. %s  [%s]%s', width, index, product.title, _format_names(product), details)


def _plural(count: int, word: str) -> str:
    return f'{count} {word}' + ('' if count == 1 else 's')


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
            html = fetch_library(session)
            try:
                products = parse_library(html)
            except DashboardError as e:
                saved = _save_debug_page(html, out_dir)
                log.error('%s The script needs updating for the new layout.', e)
                if saved:
                    log.error('The page was saved to %s; share it so the parser can be fixed.', saved)
                return 1
            books = [p for p in products if p.formats]
            others = len(products) - len(books)
            log.info('      Found %s with downloadable files%s.', _plural(len(books), 'book'),
                     f' ({_plural(others, "item")} without files, e.g. video courses, ignored)' if others else '')

            if args.list:
                _log_library(books)
                return 0

            log.info('[4/4] Downloading %s into %s (pausing %gs between downloads)...',
                     ', '.join(args.formats), out_dir.resolve(), args.delay)
            out_dir.mkdir(parents=True, exist_ok=True)
            summary = download_all(session, books, out_dir, args.formats,
                                   force=args.force, update=args.update, delay=args.delay)
    # OSError covers requests exceptions and an unwritable output directory.
    except (CredentialError, LoginError, OSError) as e:
        log.error('%s', e)
        return 1

    log.info('')
    log.info('Done. Downloaded %d, skipped %d (already present), failed %d.',
             summary.downloaded, summary.skipped, summary.failed)
    if summary.skipped and not args.update:
        log.info('Tip: run with --update to fetch newer versions of early-access (MEAP) books.')
    if summary.failed:
        log.info('Run the same command again to retry the failed files.')
    return 1 if summary.failed else 0


if __name__ == '__main__':
    sys.exit(main())
