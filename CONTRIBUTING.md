# Contributing

Everyone is welcome to contribute to GoDaddy's Open Source Software. You can
report or triage bugs, improve documentation, review changes and contribute code.
Please read our [Code of Conduct](CODE_OF_CONDUCT.md) before participating.

## Reporting issues

Search the [issue tracker][issues] before opening a report. Include the affected
version or commit, Envoy/control-plane version, relevant sanitized configuration,
expected behavior and a reproducible example. Never include credentials,
private keys or complete authenticated request proofs.

Report potential vulnerabilities privately using [SECURITY.md](SECURITY.md),
not in a public issue or pull request.

For a substantial behavior or architecture change, open an issue first so the
proposal can be discussed. Link related issues in the PR and use `Fixes #123`
when the change resolves an issue.

## Development workflow

1. Fork and clone the repository.
2. Create a branch from `main` for the change.
3. Make the smallest change that addresses the problem and update documentation.
4. Add or update tests when behavior changes; reproduce reported defects first.
5. Run the relevant checks in [the development guide](docs/development.md).
6. Review the diff, sign off your commits and open a PR against `main`.

For a fork, keep the upstream branch available:

```sh
git remote add upstream https://github.com/agentnameservice/ans-envoy.git
git fetch upstream
git switch -c your-change upstream/main
```

Use Conventional Commit titles such as `fix: reject ambiguous authorization`
or `docs: clarify replay-store recovery`. Explain the problem, resulting behavior,
validation and any remaining limitations in the PR. Preserve attribution and
existing copyright notices when modifying or incorporating others' work.

## Code review

Significant changes require review before merge. Keep changes focused, respond
to findings with code or evidence, and distinguish local tests from deployed
behavior. A green smoke test does not establish complete ANS conformance.

When comparing implementations, pin both source revisions and use the same
configuration and test conditions. See [comparison criteria](docs/comparison.md).

## Developer Certificate of Origin

This project follows the Linux Foundation contribution model used by the other
ANS repositories. Every contribution commit must carry a `Signed-off-by:` trailer
certifying the [Developer Certificate of Origin 1.1](DCO): the human contributor
has the right to submit the contribution under the project's license.

Read the certificate before signing off:

```sh
git commit -s
```

Git adds a trailer using your configured name and email:

```text
Signed-off-by: Your Name <your.email@example.com>
```

Use your own identity and email. A DCO sign-off is a rights attestation, not a
cryptographic GPG/SSH signature; neither replaces the other.

For an unpublished commit, use `git commit --amend -s`. To correct a series on
your own branch, review the affected commits before rebasing:

```sh
git fetch upstream
git rebase --signoff upstream/main
git push --force-with-lease origin your-change
```

Coordinate before rewriting a shared branch. Only sign off contributions you
can certify; do not add another person's attestation.

The [DCO GitHub App][dco-app] provides the required `DCO` pull-request check in
ANS repositories. Maintainers configure that app and the required check when
setting up a repository. The merge-group workflow preserves the check name for
the merge queue; it relies on the app having validated the PR and is not a
replacement for that validation. Bot and merge-commit handling follows the app's
configuration. Do not bypass a failed DCO check.

## AI-assisted contributions

AI-assisted contributions are welcome with disclosure, following the
[Linux kernel convention][ai-guidance]:

- Identify the tool and model in the PR's **AI assistance** section, for example
  `Assisted-by: <tool> (<model>)`.
- Human contributors remain responsible for correctness, testing, licensing and
  the DCO attestation. An AI tool is not a contributor who can certify the DCO.
- Do not list AI assistants as authors or add AI `Co-Authored-By:` trailers.
- An assistant must not invent or independently provide a human sign-off. The
  human must explicitly authorize any tooling that applies their attestation.

## Licensing and security

Contributions use the [MIT License](LICENSE). New dependencies and copied
material must have compatible terms and retain required notices. See
[licensing and notices](docs/licensing.md) and run `cargo deny check` when the
resolved dependency graph changes.

Committed keys under `testdata/demo-agents` are public test fixtures. Never use
those keys for a real registration or service, and do not commit generated test
bundles, live agent private keys, kubeconfigs, credentials or local configuration.

[issues]: https://github.com/agentnameservice/ans-envoy/issues
[dco-app]: https://github.com/apps/dco
[ai-guidance]: https://docs.kernel.org/process/coding-assistants.html
