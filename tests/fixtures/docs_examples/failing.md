# Harness fixture: examples that fail

Every fenced example below must be reported as a failure.

```pycon
>>> 1 + 1
3
```

```pycon
There is no prompt in this block.
```

```console
$ python -c "print('one')"
two
```

```console
$ python -c "import sys; sys.exit(1)"
```

```console
output before any command
$ python -c "print('x')"
x
```

```python
raise ValueError("this example raises")
```

```yaml
key: [unclosed
```

% notest:
```python
print("a notest marker without a reason is an error")
```

```bash
echo "use a console block, not bash"
```

```console
$ python -c "import sys; print('x'); sys.exit(1)" | cat
x
```

```pycon3
>>> 1 + 1
2
```
