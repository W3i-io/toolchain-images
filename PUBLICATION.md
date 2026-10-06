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
Staging tags are not releases and become publicly pullable, including unscanned
candidates, when packages are public. Never consume staging tags.
Individual runtime promotions are not atomic as a pair. A recommended pair is
valid ONLY when the final `pair` job succeeds in the same run and attempt. If one
runtime fails, any individually promoted image is not a recommended pair.
Use both immutable references from that run's evidence artifacts and retain its
run URL. Never use mutable tags as consumer pins.

Registry visibility is separate from repository visibility. New packages may
initially be private. Verify and explicitly set generic image packages public
before advertising anonymous consumption; do not claim anonymous access until
an unauthenticated digest pull succeeds. No private data is permitted even in
staging. The pinned login action configures the Docker client credential; pinned
BuildKit and Docker registry operations use it for authenticated publication.
The attestation action uses job identity to publish provenance. The Trivy
container receives only exported public image data, evidence and scanner cache,
not the Docker socket, credential files or job environment. Never add build
secrets or consumer-specific build arguments.

Retain released indexes, child manifests and attestations. Do not enable untagged
manifest cleanup. Keep released tags and record immutable references with run
URLs. Fresh builds may differ because apt metadata and attestations change;
the guarantee is scan/promote digest equality, not bit-reproducible rebuilds.

Image publication and consumer integration are not yet verified. Recipe runtime
targets are Python 3.12.14 and Node 24.20.0 on amd64 and arm64. Each publication
must prove these on both platforms. Generic tooling maintainers own refreshes;
consumers independently review and test any new digest before adoption.

## Maintenance and release controls

Refresh action commits, QEMU, BuildKit, SBOM generator, Trivy and base-image
digests together with review; no supporting container may use an unpinned tag.
The scanner records version/database metadata and reuses its cache across the
two architectures in a runtime job. Vulnerability data stays current, not frozen.
The exact perl-base update repairs known upstream package defects. A newer
Debian package can make the exact version unavailable; this intentionally fails
closed. Update the workflow, recipe and verifier together, or remove the repair
only after refreshed base images pass both architecture scans and runtime checks.
Runtime expectations also live in the verifier and must match reviewed bases.

Dispatch as a different account from the environment reviewer; self-approval is
not permitted. CODEOWNERS covers the release implementation. Concurrent runs are
serialized; GitHub may replace an older pending run with a newer pending run.
A queued run is not evidence of a release. Publication remains disabled pending
exact-commit review and verification of the protected environment.
