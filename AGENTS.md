# Guidance for Automated Agents

To keep the repository tidy and easy to maintain, automated agents should follow these principles:

- **Follow established style.** Consult the developer guidelines in [`doc/developer-notes.md`](doc/developer-notes.md) before writing or editing code. Adhere to the documented formatting, naming, and documentation conventions unless the project maintainers request otherwise.
- **Delete obsolete source files.** When retiring code, prefer removing the corresponding files outright instead of leaving stub implementations (for example, those containing only `#error` guards).
- **Confirm large refactors.** When a deletion task appears to require non-trivial refactoring elsewhere, pause and ask for confirmation first—consider whether removing the code you're about to refactor is a better alternative.
- **Update build metadata.** After deleting files, ensure any build scripts, project files, or documentation lists referencing them are updated accordingly.
- **Validate the build.** Always rebuild and run the relevant tests after removing files to confirm that no hidden dependencies remain.
- **Consult the linters.** Review the CI lint entry point at [`ci/lint/06_script.sh`](ci/lint/06_script.sh) to understand which linters the project runs. When feasible, execute the relevant linters locally or follow their documented rules before submitting changes. As the first line of defense, run the quick checks `test/lint/check-doc.py` (argument documentation) and `test/lint/lint-includes.py` (include hygiene) before proposing changes; both scripts execute in seconds and catch common regressions.

Following these steps keeps dead code from lingering and helps future contributors understand the current surface area of the project.

## Commit attribution

Include the following trailers on commits generated with automated assistance:

```
Assisted-by: GitHub Copilot
Assisted-by: OpenAI GPT-5-Codex
```

If different tools or models were involved, replace the names above with the correct attributions before committing.
