# Harness fixture: examples that pass

Used only by tests/test_docs_examples.py to test the harness itself.

```pycon
>>> from pathlib import Path
>>> from ciphersuites.catalog import Catalog
>>> cat = Catalog.load(Path("tests/fixtures/catalog_v2"))
>>> cat.get("RC4-MD5", library="openssl", version="3.0").code_point
('0x00', '0x04')
>>> cat.versions("openssl")
['1.0.2', ...]
```

```console
$ python -c "print('alpha'); print('beta'); print('gamma')"
alpha
...
gamma
$ python -c "import os; print(os.path.isdir('tests/fixtures/catalog_v2'))"
True
$ python -c "import sys; sys.exit(3)"; echo "exit=$?"
exit=3
```

```python
from ciphersuites.scrape.core import normalize_code_point

assert normalize_code_point([0xC0, 0x2F]) == ("0xC0", "0x2F")
```

- An indented block inside a list item:

  ```yaml
  code_point: ['0xC0', '0x2F']
  names:
    - name: ECDHE-RSA-AES128-GCM-SHA256
      versions: ['1.0.2']
  ```

% notest: shows output that depends on the network
```console
$ ciphersuites-scrape --out ../ciphersuites
this would fail if it ran
```

````markdown
A four-backtick fence is not an example, and neither is this inner block:

```python
raise RuntimeError("never run")
```
````

```text
Plain text blocks are not examples.
```
