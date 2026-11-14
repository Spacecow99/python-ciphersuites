# Releasing

This page describes how a release of the package and its data comes
together, and how to move the data {term}`gitlink`.

**State.** Release `v0.1.0` is done. This page records the procedure as
it was performed.

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

Before the release, both sides pointed at work that was only on
feature branches. The gitlink pinned a data commit that was only on a
data branch. The data workflow installed the package from a tag that did
not exist. The package `main` had older code.

A squash merge or a deleted branch would make the pinned data commit
unreachable. Git can move a tag to a different commit. So the workflow
installs the package from a full commit SHA, not from a tag.

## The release procedure

These steps were done in this order.

### 1. Merge the data branch with a merge commit

The data repository's feature branch went into its `main` with pull
request Spacecow99/ciphersuites#19. It used a merge commit, not a squash
or a rebase. The merge commit `52037e5` keeps the pinned data commit
`c24a21e` reachable from `main`, so the gitlink stays valid.

From this moment, the workflow file was on the default branch, so its
weekly schedule (Sundays 00:00 UTC) was active. Until step 4 was done, a
scheduled run would fail at the install step. Such a run fails before it
scrapes, so it does not change the data. Steps 1 to 4 were done one
after the other, in one session.

### 2. Merge the package branch

The package repository's feature branch went into its `main` with pull
request Spacecow99/python-ciphersuites#9, also with a merge commit. The
CI passed on the merge. The merge commit is
`05ae7183cda1c3896040d26e75a61b8e8322f317`.

### 3. Tag the release

The tag `v0.1.0` is a lightweight tag on that merge commit. It was
created and pushed like this:

% notest: creates and pushes a tag in the package repository
```console
$ git tag v0.1.0 05ae7183cda1c3896040d26e75a61b8e8322f317
$ git push origin v0.1.0
```

The full SHA of a tagged commit is:

% notest: needs the tag of step 3
```console
$ git rev-parse v0.1.0^{commit}
```

### 4. Pin the workflow install to the commit SHA

In the data repository, the install line of the workflow changed from
the tag to the full commit SHA of step 3 (data commits `bf796e5` and
`a75b39c`). It reads:

```text
python -m pip install "python-ciphersuites @ git+https://github.com/Spacecow99/python-ciphersuites@05ae7183cda1c3896040d26e75a61b8e8322f317"
```

A commit SHA cannot move; a tag can. Write the bare SHA after a single
`@`. The text `...@v0.1.0@<sha>` fails: pip clones a repository named
`python-ciphersuites@v0.1.0`, which does not exist.

### 5. Move the gitlink to the tip of data `main`

After step 4, the newest commit of the data repository's `main` was
`a75b39c`. The gitlink moved to that commit, so that the packaged data
includes the final workflow file. It used the procedure in
[Move the data gitlink](#move-the-data-gitlink). The data files at
`a75b39c` are identical to the files at `c24a21e`, and the tests still
pass.

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
