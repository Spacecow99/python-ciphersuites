# Releasing

This page describes how a release of the package and its data comes
together, and how to move the data {term}`gitlink`.

**State at the commit that this documentation describes.** No release
has been made. The package repository has no tags at all; in particular,
the tag `v0.1.0` does not exist (checked with `git ls-remote --tags` on
2026-11-09). The procedure below is the plan from the project's review
records. No step of it is done yet.

## What a release is

The package is not published on PyPI: `pyproject.toml` has the
classifier `Private :: Do Not Upload`. A release is a git tag in the
package repository. People and the data workflow install from that
reference with pip.

The package version is the string `__version__` in
`ciphersuites/__init__.py`, now `"0.1.0"`. The build tool flit reads the
version from there (`dynamic = ["version", "description"]` in
`pyproject.toml`). A tag does not change it.

## Why the order matters

The package and the data live in two repositories that point at each
other:

- The package pins one data commit through the gitlink
  `ciphersuites/_ciphersuites`. A clone with `--recurse-submodules`
  fails when that commit is not reachable from a branch or tag of the
  data repository. A commit is reachable when a branch or a tag
  contains it.
- The data repository's workflow installs the package from a fixed
  reference (see [The data repository workflow](data-repo-workflow.md)).
  The install fails when that reference does not exist.

Today, both sides point at work that is only on feature branches:

- The gitlink pins data commit `c24a21e`, which is on the data branch
  `claude/modest-tesla-n4t2ke`. The data repository's `main` is still at
  `07d09ab`.
- The data workflow on that branch installs
  `python-ciphersuites @ git+https://github.com/Spacecow99/python-ciphersuites@v0.1.0`,
  and that tag does not exist.
- The package code is on the branch `claude/modest-tesla-n4t2ke`; the
  package `main` has older code.

A squash merge or a deleted branch would make the pinned data commit
unreachable. Git can move a tag to a different commit. So the workflow
must install the package from a full commit SHA, not from a tag.

## The release procedure

Do these steps in this order.

### 1. Merge the data branch with a merge commit

Merge the data repository's branch `claude/modest-tesla-n4t2ke` into
its `main`. Use a merge commit. Do not squash or rebase: the merge commit
keeps `c24a21e` reachable from `main`, so the gitlink stays valid.

From this moment, the workflow file is on the default branch, so its
weekly schedule is active (Sundays 00:00 UTC). Until step 4 is done, a
scheduled run fails at the install step, because `v0.1.0` does not
exist. Such a run fails before it scrapes, so it does not change the
data. Do steps 1 to 4 one after the other, in one session.

### 2. Merge the package branch

Merge the package repository's branch `claude/modest-tesla-n4t2ke` into
its `main`. The CI must pass on the merge.

### 3. Tag the release

Create the tag `v0.1.0` on the merge commit of step 2, and push it:

% notest: creates and pushes a tag in the package repository
```console
$ git tag v0.1.0 <merge-commit-sha>
$ git push origin v0.1.0
```

Write down the full 40-character SHA of the tagged commit:

% notest: needs the tag of step 3
```console
$ git rev-parse v0.1.0^{commit}
```

### 4. Pin the workflow install to the commit SHA

In the data repository, change the install line of the workflow from the
tag to the full commit SHA of step 3:

```text
python -m pip install "python-ciphersuites @ git+https://github.com/Spacecow99/python-ciphersuites@<40-hex-sha>"
```

A commit SHA cannot move; a tag can. Commit this change to the data
repository's `main`.

### 5. Move the gitlink to the tip of data `main`

After step 4, the newest commit of the data repository's `main` is the
commit that pins the workflow install to the SHA. Move the gitlink to
that commit, so that the packaged data includes the final workflow
file. Use the procedure in [Move the data gitlink](#move-the-data-gitlink),
in a follow-up commit of the package. Data `main` (`07d09ab`) is an
ancestor of `c24a21e`. So, when `main` gets no other commits, the data
files at that commit are the same as at `c24a21e`, and the tests must
still pass.

## Move the data gitlink

Use this procedure for step 5, and whenever new data should reach the
package (for example after weekly runs of the data workflow).

1. Make sure that the data commit is pushed to a branch of the data
   repository. A gitlink must never point to a commit that exists only
   on your computer.
2. Check out that commit in the submodule:

   % notest: needs network access and changes the submodule checkout
   ```console
   $ git -C ciphersuites/_ciphersuites fetch origin
   $ git -C ciphersuites/_ciphersuites checkout <data-commit-sha>
   $ git add ciphersuites/_ciphersuites
   ```

3. Update the expected commit in `test_data_dir_is_gitlink` in
   `tests/test_data_packaging.py`. The test checks that the gitlink
   points to exactly this commit.
4. Update the pages of this documentation that name the old data
   commit. Search `docs/source` for its short SHA.
5. Run the whole test suite. The documentation examples that use the
   packaged data show only facts that a data update cannot change, so
   they must still pass. A failure means that the data changed in a way
   that needs review.
6. Commit the gitlink, the test change and the documentation change
   together, with the data commit in the message.

Check the result:

```console
$ git ls-files -s ciphersuites/_ciphersuites | cut -d ' ' -f 1
160000
```

`git ls-files -s` prints the mode, the pinned data commit, a stage
number and the path. The mode `160000` marks a gitlink. Without the
`cut` command you also see the commit.

## The build

The CI job `build` builds the wheel with `flit build` and checks that it
contains `ciphersuites/_ciphersuites/ciphersuites.yaml`. So a release
without the data fails in CI. To build locally:

% notest: writes dist/ in the clone
```console
$ flit build
```
