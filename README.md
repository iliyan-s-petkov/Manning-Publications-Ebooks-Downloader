# Manning Publications Ebooks Downloader

[![GitHub license](https://img.shields.io/github/license/luckylittle/Manning-Publications-Ebooks-Downloader.svg)](https://github.com/luckylittle/Manning-Publications-Ebooks-Downloader/blob/master/LICENSE)

If you are like me and you have bought a lot of (50+) IT ebooks from [Manning Publications](https://www.manning.com/), you might be looking for a tool that can programatically download them in a nice, organized way. You came to the right place!

Screenshot of the owned products dashboard:

![Dashboard](img/dashboard.png)

## Requirements

Python 3.9+.

```bash
# Install Python packages inside virtual environment:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
./manning.py -h
# usage: manning.py [-h] [-k SERVICE] [-u EMAIL] [-p PASSWORD] [-o OUTPUT] [-f] [-v]
```

### Recommended: credentials from the macOS Keychain

Store your Manning login once. `-w` as the last option makes `security` prompt for the password, so it never lands in your shell history:

```bash
security add-generic-password -s manning -a user@domain.com -w
```

Then run:

```bash
./manning.py --keychain manning
# Logged in as user@domain.com
# Found 57 downloadable books
# Downloading AWS Security ...
# ...
```

The account email is read from the Keychain item. If you have several `manning` items, pick one with `-u user@domain.com`. On first use macOS may ask whether `security` may access the item; choose **Allow** (or **Always Allow**).

### Other options

```bash
./manning.py -u user@domain.com -p secretpassword   # works, but exposes the password in history / `ps`
./manning.py -k manning -o ~/Books/Manning           # custom output directory
./manning.py -k manning -f                           # re-download books that already exist
```

Books that already exist in the output folder are skipped, so an interrupted run can simply be restarted. Downloads are written to a `.part` file first and renamed when complete.

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## Result

* As you can see in the example below, there is one `*.zip` per folder:

```bash
tree Manning_2020-09-13
# Manning_2020-09-13
# ├── AWS_Security
# │   └── AWS_Security.zip
# ├── Azure_Storage,_Streaming,_and_Batch_Analytics
# │   └── Azure_Storage,_Streaming,_and_Batch_Analytics.zip
# ├── Beyond_Spreadsheets_with_R
# │   └── Beyond_Spreadsheets_with_R.zip
# ├── Elastic_Leadership
# │   └── Elastic_Leadership.zip
# ├── Event_Streams_in_Action
# │   └── Event_Streams_in_Action.zip
# ├── Five_Lines_of_Code
# │   └── Five_Lines_of_Code.zip
# ...
```

* Each `*.zip` file contains `PDF`, `EPUB`, `MOBI`:

```bash
zipinfo Manning_2020-09-13/AWS_Security/AWS_Security.zip
# Archive:  AWS_Security.zip
# Zip file size: 14443760 bytes, number of entries: 3
# -rw----     2.0 fat  8008077 bl defN 20-Sep-13 06:36 AWS_Security_v3_MEAP.pdf
# -rw----     2.0 fat  4457182 bl defN 20-Sep-13 06:36 AWS_Security_v3_MEAP.epub
# -rw----     2.0 fat  3016348 bl defN 20-Sep-13 06:36 AWS_Security_v3_MEAP.mobi
#  files, 15481607 bytes uncompressed, 14443314 bytes compressed:  6.7%
```

* To unzip all of the files (and remove the original `*.zip`):

```bash
find Manning_2020-09-13/ -name '*.zip' -execdir unzip -o {} \; -delete
```

## Stars

[![Stargazers over time](https://starchart.cc/luckylittle/Manning-Publications-Ebooks-Downloader.svg)](https://starchart.cc/luckylittle/Manning-Publications-Ebooks-Downloader)

## Contributors

Lucian Maly <<lucian@redhat.com>>

---

_Last Update: 2026-09-16 (modernized: Keychain credentials, new CAS login, resumable downloads)_
