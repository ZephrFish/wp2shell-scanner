# wp2shell-scanner

Non-destructive detection for WordPress core exposure to wp2shell (CVE-2026-63030 / CVE-2026-60137). Fingerprints the core version and confirms the REST `/batch/v1` route is reachable; sends no exploit payload.

Deep dive blog post: https://blog.zsec.uk/wp2shell-code-trace-deep-dive/

## Nuclei template

```
nuclei -t wp2shell-exposure.yaml -u https://target
```

## Python scanner

Single host, multiple hosts, or a file. Standard library only.

```
python3 wp2shell.py https://target
python3 wp2shell.py host1 host2 host3
python3 wp2shell.py -f hosts.txt
```

Options: `-f/--file` hosts file (one per line), `-j/--json` JSON output, `-t/--threads` concurrency (default 10).
