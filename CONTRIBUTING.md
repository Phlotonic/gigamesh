# Contributing to GigaMesh

We welcome mutual security research, defensive detector improvements, Reverse Engineer Anything (REA) adapter enhancements, Red Hat / OpenShift containment modules, and empirical evaluation benchmarks.

## Contributor License Agreement (CLA)

Because **GigaMesh** is dual-licensed under **GNU AGPL-3.0** and a **Commercial License** (see [`COMMERCIAL_LICENSE.md`](./COMMERCIAL_LICENSE.md)), every contribution submitted via Pull Request, patch, or genome sync must carry clear dual-licensing rights.

By submitting a contribution ("Contribution") to `Phlotonic/gigamesh`, you agree to the following terms:

1. **Originality & Authority**: You represent that your Contribution is your original work (or that you have the legal authority to submit it) and does not infringe any third-party intellectual property rights.
2. **Copyright & Dual-Licensing Grant**: You retain copyright in your Contribution, and you grant **Adam Dryden and Quanumis Systems** (and their successors and assigns) a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright and patent license to reproduce, prepare derivative works of, publicly display, publicly perform, sublicense, and distribute your Contribution and derivative works under **both** open-source licenses (including **AGPL-3.0** and **CC-BY-SA-4.0**) **and** commercial/proprietary licenses.
3. **Defensive Safety Invariant**: Contributions to detectors, snares, REA metabolism rules, or `genome-sync` payloads must remain strictly **in-perimeter defensive capabilities**. Offensive exploit payloads, hack-back tools, or unredacted credentials/PII will be rejected.

If your employer owns rights to your work, please ensure you have corporate authorization before submitting a PR. For corporate CLA paperwork, email **Adam Dryden / Quanumis Systems** at [adryden508@gmail.com](mailto:adryden508@gmail.com).

## Development & Verification Checklist

Before opening a pull request:

```bash
# Run the full backend & sync firewall test suite
PYTHONPATH=backend .venv/bin/pytest -v backend/tests

# Verify frontend TypeScript types and production bundle
npm --prefix frontend run build
```

All PRs introducing new defensive options or trade-off forks must pass GigaMesh's Darwinian benchmark evaluation without violating use-case false-positive ceilings.
