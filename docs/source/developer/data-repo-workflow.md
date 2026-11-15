# The data repository workflow

The data files are not produced by hand. A GitHub Actions
{term}`workflow` in the {term}`data repository` runs the scraper and
commits the result. This page describes that workflow.

## Which version this page describes

The workflow file is
`.github/workflows/scrape_format_ciphersuites.yaml` in the data
repository <https://github.com/Spacecow99/ciphersuites>. This page
describes the file as it is at data commit
`df9a10cf6772262033878fe6241beaf973685f47` (short form `df9a10c`). That
is the commit that this package's data {term}`submodule` pins. The
workflow file is the same as at `a75b39c`. You can
read the file in a clone at
`ciphersuites/_ciphersuites/.github/workflows/scrape_format_ciphersuites.yaml`.

That commit is on the branch `feature/technologies-schema-v2`, which is
not merged into `main` yet. The workflow file on the default branch
`main` is the same, so the weekly schedule is active. [Releasing](releasing.md) describes how the file got
there.

## Why the workflow has two jobs

The scraper runs third-party code (its dependencies) on untrusted input
(upstream HTML, CSV and source files). A token is the key that GitHub
gives a job to access the repository. A compromised dependency in a job
with a write token can push any change to the data repository. So
the workflow separates the work:

- the job `scrape` runs the scraper with a token that can only read;
- the job `commit` has the write permission, but runs no third-party
  code. It only copies known files and pushes them.

## Triggers

```yaml
on:
  workflow_dispatch:
    inputs:
      accept:
        description: "Accept gate failures for LIB:VER pairs (comma-separated)"
        required: false
        default: ""
      reason:
        description: "Evidence for the acceptance (required with accept)"
        required: false
        default: ""
      baseline_ref:
        description: "Baseline git ref (default: HEAD)"
        required: false
        default: ""
  schedule:
    - cron: "0 0 * * 0"
```

This is the `on:` section of the file, without its comments.

- **Schedule.** The cron expression `0 0 * * 0` means every Sunday at
  00:00 UTC. GitHub runs scheduled workflows only from the default
  branch. This workflow file is on the data repository's default branch,
  so the weekly run is active.
- **Manual start** (`workflow_dispatch`). A person with write access
  starts the workflow in the GitHub web interface (tab "Actions") and
  chooses a branch. The three inputs:

| Input | Meaning |
|---|---|
| `accept` | Comma-separated `LIB:VER` pairs, for example `mbedtls:4.2,schannel:Windows Server 2025`. The workflow splits the value only at commas, so a label may contain spaces. Each pair becomes one `--accept` option. |
| `reason` | The reason for the acceptance. It becomes `--reason`. The scraper requires it when `accept` is set. |
| `baseline_ref` | A git ref of the data repository. It becomes `--baseline-ref`. Empty means the checked-out files. |

All three default to empty. See
[Runner and command line](runner-and-cli.md#accept-a-gate-failure) for
what `--accept` does.

## Settings for the whole workflow

- `permissions: {}`: no job gets any token permission unless it asks for
  one.
- `concurrency: group: scrape-ciphersuites` with
  `cancel-in-progress: false`: two runs never overlap. A new run waits
  until the running one ends.
- Every action is pinned to a full commit SHA, with the version in a
  comment, for example
  `actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0`.

## The job `scrape`

Permissions: `contents: read`. Steps:

1. **Check out** the data repository with its full history
   (`fetch-depth: 0`), so that `--baseline-ref` can name any commit. The
   token is not stored in the checkout (`persist-credentials: false`).
2. **Set up Python 3.12.**
3. **Restore the fetch cache** `~/.cache/python-ciphersuites` with
   `actions/cache`. The key is `scrape-cache-<os>-<run id>`, and any key
   that starts with `scrape-cache-<os>-` can be restored. So each run
   starts from the newest cache and saves a new one.
4. **Install the package**:
   `python -m pip install "python-ciphersuites @ git+https://github.com/Spacecow99/python-ciphersuites@05ae7183cda1c3896040d26e75a61b8e8322f317"`.
   The text after `@` is the full SHA of the commit that the tag
   `v0.1.0` marks. A SHA cannot move; a tag can. See
   [Releasing](releasing.md).
5. **Scrape and validate.**
   - It runs `ciphersuites-scrape --out . --report validation-report.json`.
   - It adds one `--accept` per pair and `--reason` when `accept` is set.
     It adds `--baseline-ref` when `baseline_ref` is set.
   - The inputs reach the script only through environment variables
     (`ACCEPT`, `REASON`, `BASELINE_REF`) and are always quoted. This
     prevents script injection.
   - The step does not stop on a failure. It stores the exit code as the
     job output `rc`.
   - The Markdown summary goes to the job summary page, because GitHub
     sets `GITHUB_STEP_SUMMARY`.
6. **Upload the data**: every top-level `*.yaml` file, as the artifact
   `data` (a file bundle that GitHub keeps for the run and that a later
   job can download). The step fails when there is no such file.
7. **Upload the report**: `validation-report.json`, as the artifact
   `validation-report`. This step runs even when an earlier step failed.

The scraper writes complete files even when some versions fail; failed
versions are {term}`stale`. So the job gives the data to the job
`commit` even when the scraper's exit code is 1.

## The job `commit`

It runs after `scrape` succeeded. Permissions: `contents: write`. Steps:

1. **Check out** the data repository.
2. **Download** the artifact `data` into a temporary directory.
3. **Copy only the known files.** It copies only these 14 files from the
   artifact, and only when each is a regular file and not a symbolic
   link: `ciphersuites.yaml`, `iana.yaml`, `testssl.yaml`,
   `scanigma.yaml`, `boringssl.yaml`, `gnutls.yaml`, `go.yaml`,
   `jsse.yaml`, `libressl.yaml`, `mbedtls.yaml`, `nss.yaml`,
   `openssl.yaml`, `s2n.yaml` and `schannel.yaml`. Any other file in the
   artifact is ignored. The files `technologies.yaml` and
   `vulnerabilities.yaml` are not in the list, so the workflow never
   overwrites them. A person edits them in the data repository.
4. **Commit and push.** It stages the top-level `*.yaml` files only
   (`git add -- ':(glob)*.yaml'`). When something changed, it commits as
   `github-actions[bot]` with the message
   `Updated data from job @ <date>` and pushes to the branch of the run.
5. **Fail on validation failures.** When the scraper's exit code `rc`
   was not 0, the step prints a message and fails. So the run shows red
   after the data and the report are saved.

## What a maintainer does after a run

1. Open the run in the "Actions" tab and read the job summary of
   `scrape`, or download the artifact `validation-report`.
2. For each `fail` finding, find the cause. See
   [Validation gates](validation-gates.md).
3. When a gate failure is a real upstream change, start the workflow by
   hand with `accept` and `reason`, with the evidence in the reason.
4. When a parser is wrong, fix the adapter in this package and release
   it. The workflow installs the package from a fixed reference, so a
   fix reaches the workflow only when that reference changes. See
   [Releasing](releasing.md).

The package uses new data only after a maintainer moves the
{term}`gitlink` of `ciphersuites/_ciphersuites` to the new data commit.
