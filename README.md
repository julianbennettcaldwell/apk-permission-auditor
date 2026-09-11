
# Android APK Permission Auditor 🛡️

A fast, lightweight Python static analysis tool to inspect and evaluate Android application permissions directly from compiled APK packages or raw `AndroidManifest.xml` files. It automatically categorizes permissions into risk tiers (Dangerous, High-Risk Privacy, and Special Access), helping developers, security researchers, and reviewers spot intrusive behavior before installation.

Developed as part of the editorial security verification protocol at **[ModHello](https://modhello.com/author/julian-bennett-caldwell/)**.

---

## 📊 Key Features

- **Automated Risk Scoring:** Scans declared permissions against Android Security Framework guidelines.
- **High-Risk Flags:** Identifies critical permission requests such as `SYSTEM_ALERT_WINDOW`, `REQUEST_INSTALL_PACKAGES`, and background location polling.
- **Privacy Audit:** Detects intrusive access to contacts, SMS, call logs, and external storage.
- **Zero Overhead:** Standalone Python implementation with zero complex dependencies.

---

## ⚙️ Requirements

- **Python 3.8+**
- (Optional) `aapt` or `aapt2` added to your system `PATH` for raw binary APK extraction.

---

## 🚀 Quick Usage

```bash
python auditor.py --apk path/to/app.apk
```

### Sample Report Output:
```text
============================================================
              APK SECURITY PERMISSION AUDIT
============================================================
Package:           com.example.productivity.tool
Target SDK:        34 (Android 14)
Total Permissions: 14
------------------------------------------------------------
[HIGH RISK]   android.permission.SYSTEM_ALERT_WINDOW
              -> Can draw overlays over other apps (Phishing risk)
[DANGEROUS]   android.permission.READ_EXTERNAL_STORAGE
              -> Access to sensitive user files
[NORMAL]      android.permission.INTERNET
              -> Standard network access
------------------------------------------------------------
Risk Score:        28 / 100 (MODERATE)
Verdict:           PASS - Required utility permissions declared cleanly.
============================================================
```

---

## 📖 Methodology & Security Standards

For our complete 4-tier mobile app security protocol, manifest decompilation standards, and privacy verification guidelines, visit:
👉 **[ModHello Editorial Security Review Standards](https://modhello.com/author/julian-bennett-caldwell/)**

---

## 📄 License
MIT License. Maintained by **Julian Bennett Caldwell** ([@julianbennettcaldwell](https://github.com/julianbennettcaldwell)).
