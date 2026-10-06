#!/usr/bin/env bash
# Called by the publication workflow after a single multi-platform staging push.
set -euo pipefail
: "${IMAGE:?}" "${INDEX:?}" "${BASE:?}" "${KIND:?}"
[[ "$INDEX" =~ ^sha256:[a-f0-9]{64}$ ]]
[[ "$KIND" == python || "$KIND" == node ]]
TRIVY='aquasec/trivy:0.69.1@sha256:1c78ed1ef824ab8bb05b04359d186e4c1229d0b3e67005faacb54a7d71974f73'
mkdir -p evidence
printf '%s\n' "$IMAGE@$INDEX" "$BASE" > evidence/sources.txt
docker buildx imagetools inspect "$IMAGE@$INDEX" --raw > evidence/index.json
# BuildKit includes unknown/unknown attestation manifests: preserve these in the
# released index, but require exactly one runnable manifest for each target.
python3 - <<'PY'
import json, re
index = json.load(open('evidence/index.json'))
items = index['manifests']
for arch in ['amd64', 'arm64']:
    found = [m for m in items if m.get('platform', {}).get('os') == 'linux'
             and m.get('platform', {}).get('architecture') == arch]
    assert len(found) == 1, (arch, found)
    digest = found[0]['digest']
    assert re.fullmatch(r'sha256:[a-f0-9]{64}', digest), digest
    open(f'evidence/{arch}.digest', 'w').write(digest)
PY
for arch in amd64 arm64; do
  digest=$(cat "evidence/$arch.digest")
  ref="$IMAGE@$digest"
  docker pull --platform "linux/$arch" "$ref"
  docker run --rm --platform "linux/$arch" "$ref" dpkg-query -W > "evidence/$arch-packages.tsv"
  installed=$(docker run --rm --platform "linux/$arch" "$ref" dpkg-query -W '-f=${Version}' perl-base)
  test "$installed" = '5.36.0-7+deb12u4'
  if [ "$KIND" = python ]; then
    docker run --rm --platform "linux/$arch" "$ref" python --version > "evidence/$arch-runtime.txt"
    test "$(cat "evidence/$arch-runtime.txt")" = 'Python 3.12.14'
  else
    docker run --rm --platform "linux/$arch" "$ref" node --version > "evidence/$arch-runtime.txt"
    test "$(cat "evidence/$arch-runtime.txt")" = 'v24.20.0'
  fi
  # Images have already been pulled by login-action's authenticated Docker client.
  # Trivy scans that exact local digest via the socket: no token/env/file injection.
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
    -v "$PWD/evidence:/evidence" "$TRIVY" image --image-src docker \
    --scanners vuln --ignore-unfixed --severity HIGH,CRITICAL --exit-code 0 \
    --format json --output "/evidence/$arch-scan.json" "$ref"
  # Enforce policy against the saved report, not a second scan/DB snapshot.
  python3 - "$arch" <<'PY'
import json, sys
arch = sys.argv[1]
report = json.load(open(f'evidence/{arch}-scan.json'))
assert report['SchemaVersion'] == 2
assert report['ArtifactType'] == 'container_image'
assert report['Metadata']['OS']['Family'] == 'debian'
assert report.get('Results'), 'Missing scan results'
findings = [v for r in report['Results'] for v in r.get('Vulnerabilities', [])]
critical = [v for v in findings if v['Severity'] == 'CRITICAL' and v.get('FixedVersion')]
print(f'{arch}: {len(critical)} fixable Critical; '
      f'{sum(v["Severity"] == "HIGH" for v in findings)} fixable High (reported)')
assert not critical, 'Fixable Critical finding blocks release'
PY
done
