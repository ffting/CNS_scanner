"""Quick smoke test without a real APK file."""

import xml.etree.ElementTree as ET

from deep_link import extract_deep_links
from manifest_parser import _collect_permissions, extract_components
from models import AppMeta, ScanResult
from poc_generator import attach_poc_commands
from risk_rules import apply_risk_analysis
from vulnerability_patterns import detect_vulnerabilities

SAMPLE_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.bank">
  <permission android:name="com.example.bank.CUSTOM"
      android:protectionLevel="dangerous"/>
  <application android:debuggable="false" android:allowBackup="true">
    <activity android:name=".OAuthActivity" android:exported="true">
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="bank.com"
            android:pathPrefix="/oauth/callback"/>
      </intent-filter>
    </activity>
    <provider android:name=".UserProvider" android:exported="true"/>
    <service android:name=".SyncService" android:exported="true">
      <intent-filter>
        <action android:name="com.example.SYNC"/>
      </intent-filter>
    </service>
  </application>
</manifest>"""


def main() -> None:
    root = ET.fromstring(SAMPLE_MANIFEST)
    perms = _collect_permissions(root)
    comps = extract_components(root, "com.example.bank", perms, 33)
    links = extract_deep_links(comps)
    result = ScanResult(
        meta=AppMeta(package_name="com.example.bank", apk_path="test.apk", target_sdk=33),
        components=comps,
        deep_links=links,
        custom_permissions=perms,
    )
    apply_risk_analysis(result)
    attach_poc_commands(result)
    detect_vulnerabilities(result)

    assert len(comps) == 3
    assert len(result.vulnerabilities) >= 3
    assert any(v.pattern_id == "VULN_OAUTH_DEEP_LINK_OPEN" for v in result.vulnerabilities)
    assert any(v.pattern_id == "VULN_EXPORTED_PROVIDER_LEAK" for v in result.vulnerabilities)
    assert any(c.chain_id == "CHAIN_OAUTH_HIJACK" for c in result.attack_chains)
    assert len(links) >= 1
    oauth = next(c for c in comps if "OAuth" in c.name)
    assert oauth.priority in ("P0", "P1", "P2")
    print("OK: smoke test passed")
    print("Summary:", result.summary)
    print("Vulnerabilities:", [v.pattern_id for v in result.vulnerabilities])
    print("Chains:", [c.chain_id for c in result.attack_chains])
    for link in links:
        print(" deep link:", link.priority, link.risk_tags, link.adb_command)


if __name__ == "__main__":
    main()
