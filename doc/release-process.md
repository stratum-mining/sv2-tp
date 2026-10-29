Release Process
====================

Releases are normally prepared on `master`, without release candidates or a
separate release branch.

Follow the [maintainer guide](maintainer-guide.md) for signing commits,
adding tree-hash commitments, and verifying pushes to `master`.

## Versioning and Bitcoin Core compatibility

Versions use `MAJOR.MINOR.PATCH`, with `CLIENT_VERSION_BUILD` holding the patch
number in [CMakeLists.txt](../CMakeLists.txt).

* When dropping support for an older Bitcoin Core major version, increment
  `CLIENT_VERSION_MINOR` and reset `CLIENT_VERSION_BUILD` to `0`. For example,
  `v1.1.0` required Core v31, while `v1.0.6` supported Core v30.2.
* For other releases, increment the patch version. Adding support for a newer
  Core version while retaining existing compatibility can be a patch release:
  `v1.1.2` supports both Core v31 and v32.
* State supported Core versions, including minimum patch versions and any
  required upgrade order, in the README and release notes. Do not assume that
  untested later Core versions will remain compatible.
* Keep `CLIENT_VERSION_RC` at `0`.

## Before every release

* Check every subtree for new upstream release tags before preparing the release.
  See the [subtree inventory](../test/lint/README.md#git-subtree-checksh) for the
  subtree paths and upstream repositories (currently `src/ipc/libmultiprocess`
  and `src/secp256k1`).
* Query each upstream repository's tags, for example with
  `git ls-remote --tags <upstream-url>`, and compare its latest release tag with
  the upstream revision recorded in the latest subtree update's
  `git-subtree-split` metadata. If the tagged release is already included, no
  update is needed. New commits on an upstream branch alone do not require an
  update; only new release tags qualify.
* If a newer release tag is available, update the subtree to that tag in a
  separate pull request, following the [subtree update
  instructions](developer-notes.md#subtrees). Use the release tag as the ref in
  `git subtree pull`, rather than the upstream branch tip, and run
  `test/lint/git-subtree-check.sh -r <prefix>` after fetching the upstream ref.
* Merge the subtree update pull requests into `master` before proceeding with
  release preparation. Keep subtree updates separate from release preparation
  changes. If an upstream has no release tags, leave that subtree unchanged.
* Check CI results for the intended release commit, including SRI integration
  tests against the supported Core versions. Keep the compatibility claims and
  [integration test matrix](../.github/workflows/sri-integration-test.yml) aligned.

## Prepare and tag

1. Start from a clean `master` and choose the release version using the rules
   above. The patch number is normally already set by the previous release's
   development-version bump.
2. Update [doc/release-notes.md](release-notes.md) for this release, using the
   changes since the previous release tag. Summarize notable changes, link the
   relevant PRs, credit contributors, and explain Core compatibility and upgrade
   requirements. Update the README if compatibility or usage has changed.
   Previous notes remain available through release tags and GitHub releases;
   no wiki or separate archive copies are needed.
3. Set the chosen version in `CMakeLists.txt` and set
   `CLIENT_VERSION_IS_RELEASE` to `true`. Configure and rebuild locally:

   ```sh
   cmake --preset dev-mode -DCMAKE_BUILD_TYPE=Debug
   cmake --build build -j16
   ```

4. Regenerate the manpage and example configuration, then review the output:

   ```sh
   contrib/devtools/gen-manpages.py
   contrib/devtools/gen-conf.sh
   build/bin/sv2-tp --version
   test/lint/check-doc.py
   test/lint/lint-includes.py
   git diff --check
   ```

   Confirm the binary and manpage show the intended release version. Commit
   the version, documentation, and generated changes together with subject
   `build: prepare vX.Y.Z release`. Verify CI for the final preparation commit
   before tagging it.
5. Create a signed annotated tag on the preparation commit. For example, with
   `VERSION=1.1.3` and that commit checked out:

   ```sh
   git tag -s "v${VERSION}" -m "v${VERSION}"
   ```

   Publish the release tag for builders to fetch. Build from this tag throughout
   the remaining steps.
6. On `master`, increment `CLIENT_VERSION_BUILD` and set
   `CLIENT_VERSION_IS_RELEASE` back to `false`. Commit with subject
   `build: unset release flag and bump patch version`. This development commit
   is not part of the tagged release.

## Building

For first-time setup, see the [Guix installation instructions](../contrib/guix/INSTALL.md)
and [macOS SDK setup](../contrib/guix/README.md#making-the-xcode-sdk-available-for-macos-cross-compilation).
Builders also need local clones of
[sv2-tp-guix.sigs](https://github.com/stratum-mining/sv2-tp-guix.sigs) and, to
assemble signed macOS binaries,
[sv2-tp-detached-sigs](https://github.com/stratum-mining/sv2-tp-detached-sigs).

1. In a clean builder checkout, fetch and check out the release tag. `VERSION`
   is the release version without the `v` prefix, for example `1.1.3`:

   ```sh
   git fetch origin "v${VERSION}"
   git checkout --detach "v${VERSION}"
   ./contrib/guix/guix-build
   ```

   See [Guix build options](../contrib/guix/README.md#building) for selecting
   platforms, caches, and SDK paths.
2. Run [guix-attest](../contrib/guix/README.md#attesting-to-build-outputs) with
   `GUIX_SIGS_REPO_SV2_TP` set to the absolute path of the attestations clone
   and `SIGNER` set to your signing identity. Commit and publish
   `noncodesigned.SHA256SUMS` and its `.asc` signature under
   `${VERSION}/${SIGNER}/` in that repository.
3. Complete the codesigning steps below, then run `guix-attest` again. Commit
   and publish the resulting `all.SHA256SUMS` and `.asc` signature.
4. Run [guix-verify](../contrib/guix/README.md#verifying-build-output-attestations)
   against the final manifests. One builder's signed attestations are sufficient
   to release; additional independent matching builds are welcome. Compare
   other builders' manifests when available, and investigate any discrepancies
   before publishing.

## Codesigning

The normal release artifacts are Linux binaries and signed, notarized macOS
binaries. Windows is currently disabled in the Guix build and codesign scripts.

1. The macOS signer uses the `sv2-tp-${VERSION}-${HOST}-codesigning.tar.gz`
   outputs for `x86_64-apple-darwin` and `arm64-apple-darwin` to create detached
   signatures with signapple and complete notarization. In the maintainer's
   local setup, switch to user `sjors` and run `~/dev/sign-apples.sh`.
2. Publish the detached signatures in `sv2-tp-detached-sigs`. Record the exact
   signature commit used for the release so builders can reproduce the signed
   outputs.
3. Builders check out that signature commit and run
   [guix-codesign](../contrib/guix/README.md#codesigning-build-outputs), setting
   `DETACHED_SIGS_REPO_SV2_TP` to the absolute path of the detached-signatures
   clone. Use the final committed signatures for the outputs being attested.
4. Extract the final macOS tarballs and check the code signatures and
   notarization. Run `sv2-tp --version` from the extracted artifact on a
   supported machine and confirm it reports the intended release version.
   Also smoke-test a final Linux artifact on a supported machine.

If Windows release builds are enabled in the future, add their zip artifacts
and any applicable signing steps to this checklist at that time.

## Publish

1. Create a draft [GitHub release](https://github.com/stratum-mining/sv2-tp/releases/new)
   for the existing release tag. Use the release notes from that tag, including
   supported Core versions, upgrade instructions, PR credits, and a link to the
   release's attestations in `sv2-tp-guix.sigs`.
2. Upload the intended final binaries from
   `guix-build-${VERSION}/output/`, using the codesigned macOS outputs. Keep
   artifact basenames unchanged and upload them without platform subdirectories.
   Do not publish intermediate codesigning bundles as installable binaries.
3. Publish a verified `all.SHA256SUMS` manifest as `SHA256SUMS`, together with
   its detached signature as `SHA256SUMS.asc`. If combining signatures from
   multiple builders, use only signatures over the identical manifest. Confirm
   the uploaded binaries match its checksums and all intended assets are present.
4. Publish the GitHub release. Announce it in SRI Discord and other relevant
   channels as appropriate; a mailing-list announcement is not required for
   every patch release.

## Optional maintenance releases

Older release series may receive selected fixes when needed. There is no
automatic commitment to maintain every series; state support and end-of-life
decisions explicitly when relevant.

1. Reuse the series' maintenance branch, or create it from the latest release
   tag in that series when the first backport is needed. For example, create
   branch `1.0` from `v1.0.6` to maintain compatibility with Core v30.2.
2. Backport selected fixes through separate PRs targeting that branch,
   preferably from fixes already merged into `master`. Preserve the series'
   Core compatibility and keep changes scoped to those fixes and their
   dependencies. Test against the Core versions supported by that series;
   the current `master` integration matrix may not apply.
3. Check upstream subtree release tags on the maintenance branch too. Handle
   subtree updates in separate PRs targeting that branch, and verify that
   they preserve the series' compatibility before merging.
4. Follow [Prepare and tag](#prepare-and-tag) on the maintenance branch in
   place of `master`. Use the next unused patch version in that series, such
   as `v1.0.7`, and write notes covering changes since its previous release.
   Then follow the same building, codesigning, and publication steps above.
5. Keep the development-version bump on the maintenance branch. Do not merge
   its release preparation or version changes into `master`.
