# Release contract

Only public upstream Python, Node and Debian content may enter the images.
The build context is restricted to the generic recipe directory; no application
repository, source, configuration, history or dependency lockfile is an input.
Logs, artifacts, provenance and labels must contain only this repository's data.

Publication is disabled by default. Before enabling it, review the exact workflow
commit and configure `toolchain-publish` with an independent required reviewer,
self-review prevention, no administrator bypass and main-only deployments.
Keep main protected by pull-request review. Only then enable
`TOOLCHAIN_PUBLICATION_ENABLED`. Dispatch is main-only. The environment reviewer
must inspect the exact commit before authorizing package-write jobs.

Build both Linux architectures once, push unique staging tags, scan exact child
digests, verify package/runtime versions, attest and promote the same index.
Fixable Critical findings block promotion; High findings remain reported.
Staging tags are not releases. Both runtime jobs must pass before recommending
an image pair. Never use mutable tags as consumer pins.

Registry visibility is separate from repository visibility. New packages may
initially be private. Verify and explicitly set generic image packages public
before advertising anonymous consumption; do not claim anonymous access until
an unauthenticated digest pull succeeds. No private data is permitted even in
staging. Credentials are used only by pinned login-action, never build inputs.

Retain released indexes, child manifests and attestations. Do not enable untagged
manifest cleanup. Keep released tags and record immutable references with run
URLs. Fresh builds may differ because apt metadata and attestations change;
the guarantee is scan/promote digest equality, not bit-reproducible rebuilds.

Image publication and consumer integration are not yet verified. Recipe runtime
targets are Python 3.12.14 and Node 24.20.0 on amd64 and arm64. Each publication
must prove these on both platforms. Generic tooling maintainers own refreshes;
consumers independently review and test any new digest before adoption.
