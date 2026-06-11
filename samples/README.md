# Sample APKs

Most APK files are not committed (see root `.gitignore`).

## Secret leak demo (API key scanner)

Build a test APK with **fake** hardcoded secrets (static hits only; no live verification):

```bash
cd ../test_apk
python build_secret_test_apk.py
```

Then scan:

```bash
python our_scanner.py -f samples/secret-leak-demo.apk -o ./reports/secret-leak-demo
```

Expected: many `api_key` warnings (~15), `confirmed: 0`. See `test_apk/README.md`.

## OVAA (recommended test app)

1. Clone [oversecured/ovaa](https://github.com/oversecured/ovaa) and build a debug APK, **or**
2. Download a release APK from the OVAA repo if available.

Place your APK here, e.g. `samples/app-debug.apk`, then run:

```bash
python our_scanner.py -f samples/app-debug.apk -o ./reports/
```

Expected package: `oversecured.ovaa`
