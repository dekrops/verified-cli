# Automated code review

The `Claude PR Review` workflow runs two review passes on pull requests that
target `main`, drafts included: on open, update, reopen and draft status
changes. A newer run cancels the previous run for the same pull request. It
uses the same mechanics as the review workflow of the Verified platform's
repository, with prompts written for this project.

- **review:** Claude Opus reviews verification correctness, check order and
  refusal codes, trust handling, what the output claims, input safety,
  workspace storage, licensing hygiene and design quality. It posts at most 15
  actionable inline findings and one summary. A complete review with no
  findings and no material gaps submits a formal approval. Findings or an
  incomplete review leave the decision to a person; the workflow never
  requests changes and never merges.
- **ponytail-review:** Claude Sonnet reviews complexity when a pull request
  adds at least 400 lines or changes at least 12 files. It posts one comment
  and never submits or dismisses a formal review, so it cannot interfere with
  the main reviewer's approval.

Models and budgets: `claude-opus-4-7` with 150 turns and a 30-minute timeout;
`claude-sonnet-4-6` with 80 turns and a 20-minute timeout. Reviews consume
paid Claude usage.

The reviewers read code. They do not run repository scripts, build, test or
change anything, and they do not replace the quality gate, human judgment or a
required-approval policy.

## What the approval means

The `review` job can approve a pull request. If branch protection on `main`
requires one approving review, that approval satisfies it. Decide deliberately
whether an automated approval should count: either require more than one
approval, or require review from a code owner, if a person must always sign
off. This repository has no branch protection and no `CODEOWNERS` yet.

## One-time repository setup

1. Install or enable the [Claude GitHub app](https://github.com/apps/claude)
   for `dekrops/verified-cli`.
2. Configure `CLAUDE_CODE_OAUTH_TOKEN` under
   [repository Actions secrets](https://github.com/dekrops/verified-cli/settings/secrets/actions),
   or grant this repository access to an organization secret with that name. A
   secret scoped to another repository does not carry over. A Claude account
   owner can generate a token with `claude setup-token`. Never paste it into a
   pull request, an issue or a chat.
3. After the credential is set, rerun the workflow or push a new commit to a
   pull request to trigger a review. If the Claude app rejects the first run
   because the workflow is new, retry on a later pull request once the
   workflow has landed on `main`.

See the [action's setup guide](https://github.com/anthropics/claude-code-action/blob/main/docs/setup.md)
for authentication and app requirements. A missing credential fails the
`configuration` job with an explicit message and skips both review jobs. It
never reports a successful review.

## Trust and maintenance

- Pull requests from forks and from Dependabot are skipped. The workflow uses
  `pull_request`, never `pull_request_target`, so code from a fork never runs
  with this repository's secrets. When the repository is public, outside
  contributions get no automated review until a maintainer decides how to
  provide one.
- Review jobs have read-only repository contents, permission to comment on and
  review pull requests, and OIDC. Checkout keeps its read-only token because
  the action fetches the pull request branch itself.
- The tool policy denies file editing and agent delegation, and limits shell
  use to inspecting the pull request and history and publishing review output.
  The diff is untrusted: it must not be able to redirect the reviewer.
- Actions are pinned to commits, and the actionlint image to a digest, as
  everywhere in this repository's workflows.
- `.github/ponytail-review.md` is third-party text under the MIT license,
  copied unchanged from the public project named in its header; its license is
  in `.github/ponytail-review.LICENSE`. To update it, replace the body from a
  newer upstream release and update the recorded commit and version. Project
  rules belong in `.github/ponytail-review.ci.md` and the workflow, not in the
  vendored file.

The separate `Workflow Validation` check runs actionlint on workflow changes
and needs no Claude credential. Locally: `actionlint -shellcheck=`.
