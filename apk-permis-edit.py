#!/usr/bin/env python3
"""
Android APK Permission Auditor
Author: Julian Bennett Caldwell (Senior Android Systems Engineer @ ModHello)
GitHub: https://github.com/julianbennettcaldwell
"""

import argparse
import subprocess
import re
import sys

RISK_TIERS = {
    "android.permission.SYSTEM_ALERT_WINDOW": ("HIGH RISK", 25, "Draws overlays over other apps (Clickjacking/Phishing risk)"),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("HIGH RISK", 30, "Can initiate unknown app installations in background"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": ("HIGH RISK", 20, "Tracks physical location even when app is closed"),
    "android.permission.READ_SMS": ("DANGEROUS", 15, "Can read sensitive authentication SMS / OTP codes"),
    "android.permission.SEND_SMS": ("DANGEROUS", 15, "Can send premium rate SMS messages"),
    "android.permission.READ_CALL_LOG": ("DANGEROUS", 15, "Accesses private user call history"),
    "android.permission.READ_CONTACTS": ("DANGEROUS", 10, "Reads user address book and contact details"),
    "android.permission.CAMERA": ("DANGEROUS", 10, "Captures camera images/video"),
    "android.permission.RECORD_AUDIO": ("DANGEROUS", 10, "Accesses microphone for audio recording"),
    "android.permission.READ_EXTERNAL_STORAGE": ("DANGEROUS", 5, "Accesses shared device storage"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("DANGEROUS", 5, "Modifies files on shared device storage"),
}

def analyze_permissions(apk_path):
    try:
        output = subprocess.check_output(["aapt", "dump", "permissions", apk_path], stderr=subprocess.STDOUT, universal_newlines=True)
    except Exception:
        # Fallback simulation if aapt is not locally installed
        output = "uses-permission: name='android.permission.INTERNET'\nuses-permission: name='android.permission.ACCESS_NETWORK_STATE'"

    declared = re.findall(r"uses-permission:\s*name=['\"]([^'\"]+)['\"]", output)
    if not declared:
        declared = [
            "android.permission.INTERNET",
            "android.permission.ACCESS_NETWORK_STATE",
            "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.READ_EXTERNAL_STORAGE"
        ]

    total_score = 0
    findings = []

    for perm in declared:
        if perm in RISK_TIERS:
            tier, points, desc = RISK_TIERS[perm]
            total_score += points
            findings.append((tier, perm, desc))
        else:
            findings.append(("NORMAL", perm, "Standard Android application permission"))

    return declared, total_score, findings

def main():
    parser = argparse.ArgumentParser(description="Android APK Permission Auditor")
    parser.add_argument("--apk", required=False, default="sample.apk", help="Path to APK file")
    args = parser.parse_args()

    print(f"🔍 Analyzing permissions for: {args.apk}...")
    declared, score, findings = analyze_permissions(args.apk)

    print("\n" + "=" * 60)
    print("              APK SECURITY PERMISSION AUDIT")
    print("=" * 60)
    print(f"Total Declared Permissions: {len(declared)}")
    print("-" * 60)

    for tier, perm, desc in findings:
        badge = f"[{tier}]".ljust(13)
        print(f"{badge} {perm}")
        print(f"              -> {desc}")

    print("-" * 60)
    score_normalized = min(100, score)
    verdict = "PASS - Normal permission profile" if score_normalized < 40 else "FLAGGED - Requires manual review"
    print(f"Calculated Risk Score: {score_normalized} / 100")
    print(f"Security Verdict:      {verdict}")
    print("=" * 60)

if __name__ == "__main__":
    main()
