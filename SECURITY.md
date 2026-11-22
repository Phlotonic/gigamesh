# Security Policy

**Copyright (C) 2026 Adam Dryden and Quanumis Systems.**

## Reporting Vulnerabilities or Genome Contamination

If you discover:
- A security vulnerability in GigaMesh's API, detection engines, REA bridge, or Red-Hat host controllers,
- A bypass in the **Mutual Genome Sync Firewall** (`GenomeSyncFirewall`) allowing forged benchmark scores, secret leaks, or unsafe modules to cross between local `genome_repo/` and `genome-sync`, or
- Suspected poisoning or contamination in the public `genome-sync` branch,

**Please do not open a public GitHub issue.** Report it privately via email to:

- **Security Contact**: Adam Dryden — Quanumis Systems
- **Email**: [adryden508@gmail.com](mailto:adryden508@gmail.com)

Include reproduction steps, affected commit SHA or fork ID, and any relevant Merkle ledger or firewall report digests. We aim to acknowledge reports within 48 hours and coordinate responsible disclosure.
