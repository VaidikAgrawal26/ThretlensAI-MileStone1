# Safe bundled test samples

These files are harmless text files. They are included so Milestone 1 can be demonstrated without downloading or executing malware.

- `clean_sample.txt`: should normally produce a low risk score and no YARA matches.
- `yara_test_sample.txt`: intentionally contains harmless indicator strings that exercise YARA, string, URL and local signature matching.

The second file's SHA-256 is included in `backend/yara_rules/signatures.json` as `DEMO_YARA_TEST_SIGNATURE`. This is **not** a malware signature.
