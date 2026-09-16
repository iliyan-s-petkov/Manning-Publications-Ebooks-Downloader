# Manning Publications Ebooks Downloader

[![GitHub license](https://img.shields.io/github/license/iliyan-s-petkov/Manning-Publications-Ebooks-Downloader.svg)](LICENSE)

Download every ebook you own from your [Manning Publications](https://www.manning.com/) dashboard in one go, organised into one folder per book.

> Fork of [luckylittle/Manning-Publications-Ebooks-Downloader](https://github.com/luckylittle/Manning-Publications-Ebooks-Downloader) (2020), modernised for Manning's current login flow, with macOS Keychain support, safer downloads and a test suite.

Screenshot of the owned products dashboard:

![Dashboard](img/dashboard.png)

## Features

- Credentials from the **macOS Keychain**, a **hidden password prompt**, or the command line
- Works with Manning's current sign-in form (one-time tokens are read from the page)
- Choose formats: **PDF and EPUB** by default, Kindle and EPUB 3 on request
- `--list` shows your library (formats, MEAP versions) without downloading anything
- **Resumable**: files already downloaded are skipped; partial downloads are never kept
- `--update` re-downloads early-access (MEAP) books when Manning shows a newer version, without extra requests
- Clear errors for wrong password, changed site layout, expired session or disk problems; one failing file does not stop the run
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
./manning.py [-h] [-k SERVICE] [-u EMAIL] [-p PASSWORD] [-o OUTPUT] [-F LIST] [-l] [-f | -U] [--delay SECONDS] [--user-agent UA] [-v]
```

| Option | Description |
|---|---|
| `-k`, `--keychain SERVICE` | Read email and password from the macOS Keychain item with this service name |
| `-u`, `--username EMAIL` | Manning account email (optional with `--keychain`; prompted if omitted) |
| `-p`, `--password PASSWORD` | Password on the command line (**insecure**, see below) |
| `-o`, `--output DIR` | Output directory (default: `Manning_<YYYY-MM-DD>`) |
| `-F`, `--formats LIST` | Comma-separated formats: `pdf`, `epub`, `kindle`, `epub3`, or `all` (default: `pdf,epub`) |
| `-l`, `--list` | Only list your books with their formats and MEAP versions; download nothing |
| `-f`, `--force` | Re-download every file, even if it already exists |
| `-U`, `--update` | Re-download MEAP books whose version on the dashboard differs from the one you downloaded |
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
./manning.py -k manning --list                 # see what is in your library
./manning.py -k manning                        # PDF + EPUB of every book into Manning_<today>/
./manning.py -k manning -o ~/Books/Manning     # use a fixed library folder
./manning.py -k manning -o ~/Books/Manning -F pdf         # PDF only
./manning.py -k manning -o ~/Books/Manning -F all         # every format offered
./manning.py -k manning -o ~/Books/Manning -U  # later: new books + newer MEAP versions
./manning.py -k manning -o ~/Books/Manning -f  # re-download everything
```

Example output:

```text
[1/4] Reading your Manning login from the macOS Keychain (item "manning")...
[2/4] Signing in to Manning as you@example.com...
      Signed in.
[3/4] Loading your library from the Manning dashboard...
      Found 84 books with downloadable files (9 items without files, e.g. video courses, ignored).
[4/4] Downloading pdf, epub into /Users/you/Books/Manning (pausing 2s between downloads)...
(1/84) AI Model Evaluation [pdf]: downloading...
(1/84) AI Model Evaluation [pdf]: saved AI_Model_Evaluation.pdf (13.6 MB)
(1/84) AI Model Evaluation [epub]: downloading...
(1/84) AI Model Evaluation [epub]: saved AI_Model_Evaluation.epub (9.2 MB)
(2/84) Go in Action, Second Edition [pdf]: already downloaded, skipping
...

Done. Downloaded 120, skipped 46 (already present), failed 0.
Tip: run with --update to fetch newer versions of early-access (MEAP) books.
```

The exit code is `0` when everything succeeded and `1` if login failed or any file failed.

With `--list`, step 4 is replaced by the list of books:

```text
   1. AI Model Evaluation  [epub, kindle, pdf]  (version: 5, last updated: 2026-09-14)
   2. Go in Action, Second Edition  [epub, kindle, pdf]
```

## Result

One folder per book, one file per format:

```text
Manning_2026-09-16
├── .manning-downloads.json
├── AI_Model_Evaluation
│   ├── AI_Model_Evaluation.epub
│   └── AI_Model_Evaluation.pdf
├── Go_in_Action_Second_Edition
│   ├── Go_in_Action_Second_Edition.epub
│   └── Go_in_Action_Second_Edition.pdf
...
```

Kindle files keep the extension Manning sends (`.mobi`/`.azw3`); an EPUB 3 edition is saved as `<name>-epub3.epub`. Amazon no longer accepts MOBI, so EPUB is the better choice for current Kindle devices and apps.

Folder names keep letters, digits, `.`, `+` and `-`; everything else becomes `_`. If two titles end up with the same name (e.g. `C# in Depth` and `C in Depth`), the Manning product id is appended to both.

While a file is downloading it is written to a `.part` file and renamed when complete, so an interrupted run can simply be started again.

`.manning-downloads.json` records the MEAP version of each downloaded file. `--update` compares it with the version shown on the dashboard, so checking for updates costs no extra requests. Manning shows no version for finished books, so their files are only fetched again with `--force`.

## Troubleshooting

| Message | Meaning / fix |
|---|---|
| `No Keychain item found for service "manning"` | Create the item (see above) or check the service name with `security find-generic-password -s manning` |
| `Login failed: check your email/password.` | Wrong credentials, or the account needs a login step the script cannot do (e.g. social login only: set a Manning password first) |
| `Sign-in form not found on the login page` | Manning changed its sign-in page; the parser needs updating. Please open an issue |
| `No books found in the library response` | Manning changed its dashboard. The page is saved as `library-debug.html` in the output folder; attach it to an issue (it lists your library, but contains no password) |
| `Got a web page instead of a file` | Session expired or the download link changed; rerun, and open an issue if it persists |
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
