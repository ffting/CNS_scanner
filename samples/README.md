# Sample APKs

APK files are not committed (see root `.gitignore`).

## OVAA (recommended test app)

1. Clone [oversecured/ovaa](https://github.com/oversecured/ovaa) and build a debug APK, **or**
2. Download a release APK from the OVAA repo if available.

Place your APK here, e.g. `samples/app-debug.apk`, then run:

```bash
python our_scanner.py -f samples/app-debug.apk -o ./reports/
```

Expected package: `oversecured.ovaa`
