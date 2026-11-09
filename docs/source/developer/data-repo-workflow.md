# The data repository workflow

The data files are not produced by hand. A GitHub Actions
{term}`workflow` in the {term}`data repository` runs the scraper and
commits the result. This page describes that workflow.

## Which version this page describes

The workflow file is
`.github/workflows/scrape_format_ciphersuites.yaml` in the data
repository <https://github.com/Spacecow99/ciphersuites>. This page
describes the file as it is at data commit
`c24a21eb2cf4253bcdaf15b09d5d13da6fe21773` (short form `c24a21e`). That
is the commit that this package's data {term}`submodule` pins. You can
read the file in a clone at
`ciphersuites/_ciphersuites/.github/workflows/scrape_format_ciphersuites.yaml`.

That commit is on the data repository's branch
`claude/modest-tesla-n4t2ke`. The data repository's default branch
`main` still has an older workflow, which calls commands that the
current package no longer has. This page does not describe it.
[Releasing](releasing.md) describes how the branch reaches `main`.

## Why the workflow has two jobs

The scraper runs third-party code (its dependencies) on untrusted input
(upstream HTML, CSV and source files). If that code were compromised, a
job with a write token could push anything to the data repository. So
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
  branch. So the weekly run starts only when this workflow file is on
  the data repository's default branch. Until then, it runs only when a
  person starts it.
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
   `python -m pip install "python-ciphersuites @ git+https://github.com/Spacecow99/python-ciphersuites@v0.1.0"`.
   The tag `v0.1.0` does not exist yet, so this step fails until it is
   created. See [Releasing](releasing.md).
5. **Scrape and validate.** It runs
   `ciphersuites-scrape --out . --report validation-report.json`, with
   one `--accept` per pair and `--reason` when `accept` is set, and
   `--baseline-ref` when `baseline_ref` is set. The inputs reach the
   script only through environment variables (`ACCEPT`, `REASON`,
   `BASELINE_REF`) and are always quoted. This prevents script
   injection. The step does not stop on a failure: it stores the exit
   code as the job output `rc`. The Markdown summary goes to the job
   summary page, because GitHub sets `GITHUB_STEP_SUMMARY`.
6. **Upload the data**: every top-level `*.yaml` file, as the artifact
   `data`. The step fails when there is no such file.
7. **Upload the report**: `validation-report.json`, as the artifact
   `validation-report`. This step runs even when an earlier step failed.

The scraper writes complete files even when some versions fail; failed
versions are {term}`stale`. So the data is passed on even when the
scraper's exit code is 1.

## The job `commit`

It runs after `scrape` succeeded. Permissions: `contents: write`. Steps:

1. **Check out** the data repository.
2. **Download** the artifact `data` into a temporary directory.
3. **Copy only the known files.** For each of the 14 names
   `ciphersuites`, `iana`, `testssl`, `scanigma`, `boringssl`, `gnutls`,
   `go`, `jsse`, `libressl`, `mbedtls`, `nss`, `openssl`, `s2n` and
   `schannel`, it copies `<name>.yaml` from the artifact when that is a
   regular file and not a symbolic link. Any other file in the artifact
   is ignored. The legacy files `technologies.yaml` and
   `vulnerabilities.yaml` are not in the list.
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
