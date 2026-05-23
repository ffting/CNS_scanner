# Evaluation Report

## Summary

| Metric | Value |
|---|---:|
| Ground truth attack surfaces | 3 |
| Scanner findings | 12 |
| Matched findings | 0 |
| Missed ground truth items | 3 |
| Coverage | 0.00% |
| Approx. precision | 0.00% |
| Priority score | 0.00% |
| Actionability score | 2.00 / 5 (40.00%) |

## Matched Ground Truth Items

| GT ID | Type | Name | Expected Priority | Actual Priority | Priority Score |
|---|---|---|---|---|---:|

## Missed Ground Truth Items

| GT ID | Type | Name | Expected Priority |
|---|---|---|---|
| gt_001 | exported_activity | `com.example.app.LoginActivity` | P1 |
| gt_002 | deep_link | `myapp://oauth/callback` | P0 |
| gt_003 | exported_provider | `com.example.app.provider` | P0 |

## Unmatched Scanner Findings

These findings were reported by the scanner but not matched to the current ground truth. They may be false positives, or the ground truth may be incomplete.

| Finding ID | Type | Name | Priority | Reason |
|---|---|---|---|---|
| finding_001 | exported_activity | `oversecured.ovaa.activities.DeeplinkActivity` | P1 | - |
| finding_002 | exported_activity | `oversecured.ovaa.activities.WebViewActivity` | P3 | - |
| finding_003 | exported_activity | `oversecured.ovaa.activities.LoginActivity` | P1 | - |
| finding_004 | exported_activity | `oversecured.ovaa.activities.EntranceActivity` | P3 | - |
| finding_005 | exported_activity | `oversecured.ovaa.activities.MainActivity` | P1 | - |
| finding_006 | exported_receiver | `oversecured.ovaa.receivers.UselessReceiver` | P3 | - |
| finding_007 | exported_service | `oversecured.ovaa.services.InsecureLoggerService` | P1 | - |
| finding_008 | exported_provider | `oversecured.ovaa.providers.TheftOverwriteProvider` | P0 | - |
| finding_009 | exported_provider | `oversecured.ovaa.providers.CredentialsProvider` | P3 | - |
| finding_010 | exported_provider | `androidx.core.content.FileProvider` | P3 | - |
| finding_011 | exported_provider | `androidx.startup.InitializationProvider` | P3 | - |
| finding_012 | exported_receiver | `androidx.profileinstaller.ProfileInstallReceiver` | P1 | - |

## Actionability Details

| Finding ID | Type | Name | Score | Name | Reason | Priority | ADB | Chain |
|---|---|---|---:|---:|---:|---:|---:|---:|
| finding_001 | exported_activity | `oversecured.ovaa.activities.DeeplinkActivity` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_002 | exported_activity | `oversecured.ovaa.activities.WebViewActivity` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_003 | exported_activity | `oversecured.ovaa.activities.LoginActivity` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_004 | exported_activity | `oversecured.ovaa.activities.EntranceActivity` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_005 | exported_activity | `oversecured.ovaa.activities.MainActivity` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_006 | exported_receiver | `oversecured.ovaa.receivers.UselessReceiver` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_007 | exported_service | `oversecured.ovaa.services.InsecureLoggerService` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_008 | exported_provider | `oversecured.ovaa.providers.TheftOverwriteProvider` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_009 | exported_provider | `oversecured.ovaa.providers.CredentialsProvider` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_010 | exported_provider | `androidx.core.content.FileProvider` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_011 | exported_provider | `androidx.startup.InitializationProvider` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
| finding_012 | exported_receiver | `androidx.profileinstaller.ProfileInstallReceiver` | 2 / 5 | 1 | 0 | 1 | 0 | 0 |
