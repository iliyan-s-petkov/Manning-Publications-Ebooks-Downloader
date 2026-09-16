# Manning Publications Ebooks Downloader

[![GitHub license](https://img.shields.io/github/license/iliyan-s-petkov/Manning-Publications-Ebooks-Downloader.svg)](LICENSE)

Download every ebook you own from your [Manning Publications](https://www.manning.com/) dashboard in one go, organised into one folder per book.

> Fork of [luckylittle/Manning-Publications-Ebooks-Downloader](https://github.com/luckylittle/Manning-Publications-Ebooks-Downloader) (2020), modernised for Manning's current login flow, with macOS Keychain support, safer downloads and a test suite.

Screenshot of the owned products dashboard:

![Dashboard](img/dashboard.png)

## Features

- Credentials from the **macOS Keychain**, a **hidden password prompt**, or the command line
- Works with Manning's current sign-in form (one-time tokens are read from the page)
- **Resumable**: books already downloaded are skipped; partial downloads are never kept
- `--update` re-downloads only books whose file size changed on the server (e.g. new MEAP versions)
- Clear errors for wrong password, changed site layout, expired session or disk problems; one failing book does not stop the run
- Book folder names are sanitised and never collide

## Requirements

- Python **3.10+**
- macOS for `--keychain` (all other options work on Linux/Windows too)

```bash
git clone https://github.com/iliyan-s-petkov/Manning-Publications-Ebooks-Downloader.git
cd Manning-Publications-Ebooks-Downloader
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```text
./manning.py [-h] [-k SERVICE] [-u EMAIL] [-p PASSWORD] [-o OUTPUT] [-f | -U] [--delay SECONDS] [--user-agent UA] [-v]
```

| Option | Description |
|---|---|
| `-k`, `--keychain SERVICE` | Read email and password from the macOS Keychain item with this service name |
| `-u`, `--username EMAIL` | Manning account email (optional with `--keychain`; prompted if omitted) |
| `-p`, `--password PASSWORD` | Password on the command line (**insecure**, see below) |
| `-o`, `--output DIR` | Output directory (default: `Manning_<YYYY-MM-DD>`) |
| `-f`, `--force` | Re-download every book, even if it already exists |
| `-U`, `--update` | Re-download existing books only when the server reports a different size |
| `--delay SECONDS` | Pause between downloads so Manning does not rate-limit you (default: `2`) |
| `--user-agent UA` | HTTP User-Agent to send (default: a recent desktop Chrome) |
| `-v`, `--verbose` | More detail; `-vv` also shows every HTTP request |

### Credentials

The script picks the first available source: `--keychain`, then `-p`, then an interactive prompt.

#### 1. macOS Keychain (recommended)

Store your login once. Putting `-w` last makes `security` prompt for the password, so it never lands in your shell history:

```bash
security add-generic-password -s manning -a you@example.com -w
```

Then:

```bash
./manning.py --keychain manning
```

The email is taken from the Keychain item. If you keep several items with the same service name, choose one with `-u you@example.com`. On first use macOS asks whether `security` may access the item; choose **Allow** or **Always Allow**. Passwords and emails with non-ASCII characters are supported.

To change or remove the stored password:

```bash
security add-generic-password -U -s manning -a you@example.com -w   # update
security delete-generic-password -s manning -a you@example.com      # remove
```

#### 2. Interactive prompt

Without `--keychain` or `-p`, the script asks for your email (unless `-u` is given) and reads the password with hidden input:

```bash
./manning.py -u you@example.com
# Manning password for you@example.com:
```

This needs an interactive terminal. In cron jobs or pipes the script exits with an error instead of waiting; use `--keychain` there.

#### 3. Command line (not recommended)

```bash
./manning.py -u you@example.com -p 'secret'
```

Works, but the password is saved in your shell history and visible to other processes (`ps`) while the script runs. A warning is printed.

### Examples

```bash
./manning.py -k manning                        # download everything into Manning_<today>/
./manning.py -k manning -o ~/Books/Manning     # use a fixed library folder
./manning.py -k manning -o ~/Books/Manning -U  # later: fetch only new or changed books
./manning.py -k manning -o ~/Books/Manning -f  # re-download everything
```

Example output:

```text
[1/4] Reading your Manning login from the macOS Keychain (item "manning")...
[2/4] Signing in to Manning as you@example.com...
      Signed in.
[3/4] Loading your library from the Manning dashboard...
      Found 57 books with downloadable files.
[4/4] Downloading into /Users/you/Books/Manning (pausing 2s between downloads)...
(1/57) AWS Security: downloading...
(1/57) AWS Security: saved AWS_Security.zip (13.6 MB)
(2/57) Rust in Action: already downloaded, skipping
...

Done. Downloaded 41, skipped 16 (already present), unchanged 0, failed 0.
Tip: run with --update to check skipped books for newer versions.
```

The exit code is `0` when everything succeeded and `1` if login failed or any book failed.

## Result

One folder per book. Most titles are a `.zip` containing `PDF` and `EPUB` (and, for older books, `MOBI`); some free titles are a single `.pdf`:

```text
Manning_2026-09-16
├── AWS_Security
│   └── AWS_Security.zip
├── Azure_Storage_Streaming_and_Batch_Analytics
│   └── Azure_Storage_Streaming_and_Batch_Analytics.zip
├── Rust_in_Action
│   └── Rust_in_Action.zip
...
```

Folder names keep letters, digits, `.`, `+` and `-`; everything else becomes `_`. If two titles end up with the same name (e.g. `C# in Depth` and `C in Depth`), the Manning product id is appended to both.

While a book is downloading it is written to `<name>.part` and renamed when complete, so an interrupted run can simply be started again.

To unzip everything and remove the archives:

```bash
find Manning_2026-09-16/ -name '*.zip' -execdir unzip -o {} \; -delete
```

## Troubleshooting

| Message | Meaning / fix |
|---|---|
| `No Keychain item found for service "manning"` | Create the item (see above) or check the service name with `security find-generic-password -s manning` |
| `Login failed: check your email/password.` | Wrong credentials, or the account needs a login step the script cannot do (e.g. social login only: set a Manning password first) |
| `Sign-in form not found on the login page` | Manning changed its sign-in page; the parser needs updating. Please open an issue |
| `No downloadable books were found on the dashboard` / `Product table not found` | Manning changed its dashboard. The page is saved as `dashboard-debug.html` in the output folder; attach it to an issue (it lists your library, but contains no password) |
| `Got an HTML page instead of a file` | Session expired or the download form changed; rerun, and open an issue if it persists |
| `Connection refused` / HTTP 403 / timeouts, while other sites work | Manning's servers have probably blocked your IP address for a while after too many automated requests; this also affects your browser. Wait (usually hours up to a day), or use a VPN meanwhile. Contact Manning support if it lasts. Keep `--delay` at 2 seconds or more. You can also try `--user-agent` with your browser's User-Agent string |

## Development

```bash
pip install -r requirements-dev.txt
pytest
```

The tests use fakes for HTTP and the `security` tool, so they need neither network access nor a Manning account.

## Contributors

- Lucian Maly <<lucian@redhat.com>> (original author)
- Iliyan Petkov (modernisation)

## License

[MIT](LICENSE)
