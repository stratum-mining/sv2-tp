# Maintainer guide

This guide covers routine maintenance of `stratum-mining/sv2-tp`, especially
reviewing and merging pull requests. Versioning, tagging, and publishing are
covered separately in the [release process](release-process.md).

## Merge policy

Merge pull requests locally with
[`github-merge.py`](https://github.com/bitcoin-core/bitcoin-maintainer-tools#github-merge).
The maintainer signs the merge commit, which includes a `Tree-SHA512`
commitment to the source tree. Verification follows the first-parent history
back to the trusted root. Normal contributors are not required to sign
commits. Their commits on a merged branch may be unsigned.

Use a clean checkout dedicated to merging. Avoid GitHub's merge, squash, or
rebase buttons: their output does not establish this project's maintainer
signature and tree-hash chain. Keep the existing first-parent history intact;
do not force-push `master` or reverse the parents when constructing a merge.

## Local setup

Install Git 2.38 or newer, Python 3, GnuPG, and the project's
[build dependencies](dependencies.md). Keep a reviewed local copy of
[bitcoin-maintainer-tools](https://github.com/bitcoin-core/bitcoin-maintainer-tools),
for example at `~/bitcoin-maintainer-tools`.

From the `sv2-tp` checkout, configure the repository locally:

```sh
git config --local githubmerge.repository stratum-mining/sv2-tp
git config --local githubmerge.merge-author-name "$(git config user.name)"
git config --local user.signingkey YOUR_PRIMARY_GPG_FINGERPRINT
git config --local githubmerge.testcmd \
  'cmake --preset dev-mode -DCMAKE_BUILD_TYPE=Debug && cmake --build build --parallel 8 && ctest --test-dir build --output-on-failure'
```

Set `user.name` and `user.email` first if they are not already configured.
The merge script defaults to SSH for GitHub access. It does not use `origin`'s
push URL to select the repository. Do not copy Bitcoin Core's `pushmirrors`
settings into this repository.

The signing key's primary fingerprint must be in
[`trusted-keys`](../contrib/verify-commits/trusted-keys). Import maintainers'
public keys into GnuPG and confirm their full fingerprints independently; a
keyserver download alone does not establish their identity. See the
[verification tools](../contrib/verify-commits/README.md) for key import details.

Install the pre-push hook below in every clone used to push `master`.

## Review and merge a pull request

1. Review the latest PR head, its discussion, dependencies, and CI results.
   Check that ACKs apply to the commit being merged. For protocol or IPC
   changes, check the relevant specification and supported Bitcoin Core
   versions, including the
   [SRI integration tests](../.github/workflows/sri-integration-test.yml).
2. Check for local work before starting:

   ```sh
   git status --short
   git fetch origin
   git log --oneline origin/master..master
   ```

   Start with a clean working tree and no unpublished commits on `master`.
   Publish already reviewed and verified commits, or preserve local work on
   another branch first. The merge script starts from upstream `master` and
   replaces local `master` with its result; it does not preserve unpublished
   local commits in that result.
3. Run the script from the merge checkout, replacing `123` with the PR number:

   ```sh
   python3 ~/bitcoin-maintainer-tools/github-merge.py 123 master
   ```

   It fetches the PR head, constructs a local merge, runs the configured
   Debug build and CTest suite, and shows the result for review. CTest does
   not replace CI, integration tests, or relevant lint checks. Before signing,
   run the quick checks as well:

   ```sh
   python3 test/lint/check-doc.py
   python3 test/lint/lint-includes.py
   ```

   Investigate any difference from GitHub's merge tree. If the PR needs
   conflict resolution or further changes, prepare and review those changes
   before attempting the merge again.
4. Inspect the displayed commit list, diff, ACKs, and merge message before
   signing. Signing approves the exact fetched source tree. The script does
   not recheck the PR head after testing, so that head can become outdated
   while the script runs.
5. After signing, enter `x` at the push prompt to retain the local merge for
   final inspection. The script exits without pushing; this is intentional.
   Compare the merge's second parent with GitHub's current PR head:

   ```sh
   git rev-parse master^2
   git ls-remote https://github.com/stratum-mining/sv2-tp.git refs/pull/123/head
   ```

   If the hashes differ, review the update and recreate and retest the merge.
   This check detects intervening updates; it is not an atomic freshness
   guarantee. Keep the reviewed local result unchanged before pushing.
6. Run the saved verifier and inspect the final commit, then push:

   ```sh
   hooks_dir=$(git rev-parse --git-path hooks)
   python3 "$hooks_dir/sv2-verify-commits/verify-commits.py" "$(git rev-parse master)"
   git show --no-patch --format=fuller master
   git push origin master
   ```

   The installed pre-push hook runs verification again against the exact
   commit being sent. If upstream advanced, fetch and review it, then
   recreate and retest the merge; do not force-push. Confirm the resulting
   upstream commit and CI results after pushing.

## Recommended master pre-push hook

The hook rejects pushes to `refs/heads/master` on every remote in this clone
when signatures, tree hashes, or clean merges fail verification. It also
rejects deletions and requires both the trusted root and the existing remote
tip to remain on the first-parent history. Topic branches are unaffected.

Install a snapshot of the verifier, hook, and trust files from a clean,
already trusted checkout. Review that revision and the trusted fingerprints
before installation: untrusted code cannot establish its own trust. The
snapshot is stored inside the hooks directory, outside the working tree, so
checking out another branch cannot silently change the verification rules.

The following commands refuse to replace an existing hook or snapshot. Review
and combine any existing custom hook deliberately instead of overwriting it.

```sh
(
  set -eu
  hooks_dir=$(git rev-parse --git-path hooks)
  trusted_commit=$(git rev-parse HEAD)
  mkdir -p "$hooks_dir"
  if [ -e "$hooks_dir/pre-push" ] || [ -L "$hooks_dir/pre-push" ] ||
     [ -e "$hooks_dir/sv2-verify-commits" ] || [ -L "$hooks_dir/sv2-verify-commits" ]; then
    echo "Review the existing pre-push hook and verifier snapshot first." >&2
    exit 1
  fi
  temp_dir=$(mktemp -d)
  trap 'rm -rf "$temp_dir"' EXIT
  git archive "$trusted_commit" contrib/verify-commits > "$temp_dir/verifier.tar"
  tar -xf "$temp_dir/verifier.tar" -C "$temp_dir"
  cp -R "$temp_dir/contrib/verify-commits" "$hooks_dir/sv2-verify-commits"
  printf '%s\n' "$trusted_commit" > "$hooks_dir/sv2-verify-commits/SNAPSHOT_COMMIT"
  install -m 755 "$hooks_dir/sv2-verify-commits/pre-push-hook.sh" "$hooks_dir/pre-push"
)
```

The hook is local configuration and is not installed by cloning the repository.
Linked worktrees using the same hooks directory share it. Other clones,
machines, and GitHub's web interface need their own enforcement. Do not use
`--no-verify` to work around a failed push.

When updating the verifier or trust data, independently review the chosen
revision, then back up the existing hook and snapshot and repeat installation.
The saved copy intentionally does not update when the checkout changes.

## Standalone maintainer commits

Occasionally `master` needs a direct maintainer commit, such as release
preparation. It needs both a trusted GPG signature and `Tree-SHA512`, just
like a merge. After creating and reviewing the commit, run:

```sh
python3 ~/bitcoin-maintainer-tools/signoff.py
```

This amends the latest commit to add its tree hash and sign it. Run it only
on unpublished commits. Verify the resulting commit before pushing; rerun
tests when the source changes. A signature alone is insufficient, and later
amendments require a matching tree hash and a new signature.

## Trust changes and verification failures

Add or rotate a maintainer key through a reviewed change signed by an
already trusted maintainer. Confirm the new primary fingerprint independently,
import its public key, and update each maintainer's saved verifier snapshot.
Keep historical signing keys available while they are needed to verify the
chain. Removing a former maintainer's key also makes their historical commits
untrusted under this verifier; plan that change explicitly.

The signature and tree-hash roots are deliberate historical trust anchors.
The sv2-tp bootstrap anchors both at
`1bb2a1795933bb6792c8371f74488f5f74a24be8`, the commit before the signed trust
setup. The anchor is accepted without verification; subsequent first-parent
commits must verify. Using the existing parent avoids a commit needing to
contain its own hash. Do not move a root forward to silence a failure.

On failure, read the verifier's diagnostic and check the candidate commit,
signature, public key availability or expiry, tree-hash trailer, and parent
order. Missing keys should be imported after confirming their identity.
Repair unpublished commits and retest when necessary. The `allow-*` files
are reviewed exceptions for specific historical commits, not a routine way
to admit new failures. Do not rewrite published `master` to repair history.

GitHub's built-in signed-commit requirement does not implement this trust
policy or validate `Tree-SHA512`; it also checks contributor commits brought
in by a merge. Full server enforcement needs a required verification check
on the exact candidate commit before `master` advances, for example by
testing that commit on a staging branch first. A check triggered only after
a `master` push can report a failure but cannot prevent that push.
