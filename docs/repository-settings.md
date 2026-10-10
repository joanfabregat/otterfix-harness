# Repository settings

The `main` ruleset is stored in [`.github/main-ruleset.json`](../.github/main-ruleset.json). It was applied on 2026-10-09 and verified through both the ruleset and effective branch-rules APIs: [Protect main](https://github.com/joanfabregat/otterfix-harness/rules/24815853). The active ruleset was retained when the repository was renamed to `otterfix-harness`. This file is an auditable API payload; committing it does not apply settings automatically. GitHub's live configuration is authoritative.

The ruleset requires pull requests, blocks branch deletion and force pushes, and requires review conversations to be resolved. It has no bypass actors. The initial recommended approval count is zero so a solo maintainer can merge their own pull requests; this does not enforce independent review. Set it to one when an independent reviewer is available or required by project policy.

Documentation CI is included in the initial commit. Add its successful check to required checks after observing the first run, then extend protections with Rust checks as implementation lands. Keeping an empty required-check list is not a validation guarantee. Automatic merging is outside the initial setup.
