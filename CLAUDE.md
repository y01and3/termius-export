# termius-export

Decrypts Termius's local data offline and converts hosts, SSH keys, port forwards and proxy
settings into configuration for other SSH clients.

**Termius does not need to be running.** This tool never launches it and never opens a debug
port — it reads the IndexedDB straight off disk, so it also works on a cold backup directory.

---

## Quick start

```bash
nix develop                       # or: pip install -e .
python -m termius_export --out out
```

Default behaviour: auto-detect the Termius data directory, read the decryption key from the OS
keyring, emit every format, then self-verify.

```bash
python -m termius_export --format openssh,tabby --no-secrets
python -m termius_export --data-dir ~/termius-backup/Termius --out out
```

---

## Architecture

Four stages. Writers **never** touch Termius's table layout:

```
source.py     LevelDB          ──►  raw tables (list of dicts)
crypto.py     per-field secretbox decryption
normalize.py  Termius schema   ──►  client-agnostic model
writers/      model            ──►  per-client config
verify.py     read outputs back, compare against the model
```

| File | Responsibility |
|---|---|
| `source.py` | Read Chromium IndexedDB, deduplicate records |
| `envelope.py` | The encrypted-field wire format: header detection, no dependencies |
| `crypto.py` | XSalsa20-Poly1305 decryption, version-header validation |
| `localkey.py` | Fetch `localKey` from the platform keyring |
| `datadir.py` | Locate Termius's data directory, per platform and install type |
| `fsperm.py` | Platform-dependent filesystem writes and permission hardening |
| `normalize.py` | Resolve Termius entity references, produce a `Model` |
| `model.py` | Dataclasses for the intermediate model |
| `keyfiles.py` | Name and place the exported private keys on disk |
| `writers/` | One writer per target client |
| `verify.py` | Self-verification of generated output |

Adding a client means adding one writer file. You should never need to re-read Termius's
internals again.

---

## Cipher format

Field-level encryption:

```
base64( 0x04 0x01 | nonce[24] | XSalsa20-Poly1305(ciphertext + MAC) )
```

Standard NaCl secretbox with a two-byte version header prepended. The key is the base64-decoded
`localKey` from the OS keyring — 32 bytes.

**This was reverse-engineered, not documented.** See *Reverse-engineering method* below.

The format itself lives in `envelope.py`, which imports nothing, and the decryption in
`crypto.py`, which needs PyNaCl. That split is not tidiness: header detection is the rule this
project is least willing to get wrong, and keeping it out of the module that pulls PyNaCl is
what lets the test suite check it at all.

Two rules enforced in `crypto.py`:

1. **Detect encrypted fields by the version header**, never by a "looks like base64" heuristic.
2. **Raise on an unknown header** instead of silently skipping. Only `0401` has been observed;
   anything else means Termius changed schemes, and no output from that run should be trusted.

---

## Seven traps

All seven were hit during development — the fifth only once a Mac was involved, the sixth only
once `_dump_keys` was moved somewhere a test could reach it, the seventh only on a profile that
had been used for years with groups and without sync. Don't rediscover them.

### 1. LevelDB holds multiple generations of the same record

Reading LevelDB directly returns historical versions. On one real machine the `hosts` table held
52 raw records for 13 actual hosts.

`ccl_chromium_reader`'s `live_only=True` **does not help** — it filters LevelDB-level tombstones,
and all of these records are "live" at that level.

The fix: **deduplicate by the business primary key `id`, keeping the row with the greatest
`updated_at`** (`source.py::_dedup_latest`). Validate by comparing post-dedup counts against what
the application UI shows, table by table — all six should match exactly.

Skip this and you emit four times as many host entries as the user has.

### 2. An empty string is a valid decryption result, not a failure

When a host has no name, `label` holds an **encrypted empty string**.

A reference implementation wrote `if (!decrypted || ...) return ciphertext;`. An empty string is
falsy, so successfully decrypted empty labels were treated as failures and the raw ciphertext was
returned. Symptom: a few host names show up as base64 gibberish, and no amount of tuning the
heuristic fixes it.

The same bug inflates the "hosts with a password" count, because an empty password's ciphertext
string is truthy.

**Test with `is None`, never for truthiness.**

### 3. The keyring service name depends on how Termius was installed

Termius uses the **executable name** as the keyring service name:

| Install | service |
|---|---|
| Linux snap | `termius-app` |
| macOS | `Termius` |

Looking up `Termius` on a snap install finds nothing. `localkey.py` tries a list of candidates.

Check by hand:

```bash
secret-tool lookup service termius-app account localKey        # Linux
security find-generic-password -s Termius -a localKey -w       # macOS
```

Two things measured on a real Mac, both absent on Linux:

- **macOS prompts for authorization.** Reading an item created by another application raises a
  GUI Allow / Always Allow / Deny dialog, and the export blocks until it is answered. A miss
  returns in 0.04 s; a hit took 5–9 s, which is the dialog waiting. `secret-tool` has no such
  step, so this is the one place where "reads the key from the OS keyring" needs a caveat.
  Note that *Always Allow* grants trust to `/usr/bin/security` — that is, to anything that
  shells out to it, not to this tool. It is also an argument for keeping the subprocess
  design: ACL trust is per-binary, so a ctypes/Security.framework port would be granted as
  whichever `python3` ran it and would re-prompt whenever that changed.
- **A machine can hold several entries, with different keys.** Moving between the DMG and App
  Store builds leaves the old one behind. One real Mac held `Termius` *and* `Termius (MAS)`,
  both `account=localKey`, both valid 32-byte keys, and the two **differed** — later confirmed
  on a live dual install, not just reconstructed from leftovers.

  No fixed `CANDIDATE_SERVICES` order can be right for both profiles on such a machine, so the
  order is not asked to be. **Poly1305 decides.** `find_local_key` takes a validator and
  returns the first entry that actually decrypts the data, rather than the first that exists;
  `cli` reads the tables before choosing a key (it never needed one to read them) and tests
  each candidate against one real ciphertext field. Guessing from install layout would have
  worked here too, but it would have been a heuristic where a decisive test was available —
  the same reasoning that produced the cipher format in the first place.

  Two consequences worth knowing. Each extra candidate costs another keychain prompt on macOS,
  which is why the loop stops at the first that works. And the field it tests against must
  genuinely be ciphertext: a plaintext field "decrypts" under any key, so every candidate would
  validate and selection would silently revert to first-one-wins. That is why `first_ciphertext`
  lives in `envelope.py`, where the test suite can reach it.

---

### 4. Windows needs four separate things, and none of them show up on Linux

Measured on a real install, not assumed:

- **The keyring service name is `Termius`**, and Credential Manager's target is
  `Termius/localKey` — keytar's `{service}/{account}` form. `CANDIDATE_SERVICES` already
  contained `Termius`, so only a backend was needed, not a new service name.
- **`os.chmod` is a no-op on Windows.** It can only toggle the read-only attribute, so `0600`
  on a private key silently protects nothing. `fsperm.py` uses `icacls` with the user's
  **SID** — well-known principal names are localized, so an English literal fails on a
  non-English Windows.
- **`Path.write_text` translates newlines.** The default `newline=None` turns every `\n` into
  `os.linesep`, producing CRLF private keys and, because `csv.writer` already emits `\r\n`, a
  `hosts.csv` full of `\r\r\n`. `fsperm.write_private` passes `newline="\n"`.
- **`subprocess(text=True)` decodes with the locale ANSI codepage, not UTF-8.** On a Chinese
  Windows that is GBK. `slug()` keeps CJK characters — Python's `\w` is Unicode-aware — so a
  Chinese Termius label becomes a Chinese ssh alias, `ssh -G` echoes it back as the UTF-8
  bytes we wrote, and GBK cannot decode them. The failure is nasty: `UnicodeDecodeError` is
  raised *inside subprocess's reader thread*, so `stdout` is silently left as `None` and the
  real traceback is `'NoneType' object has no attribute 'splitlines'` somewhere unrelated.

  `verify.py::_run` decodes as UTF-8 with `errors="replace"`, matching what we wrote.
  `fsperm`'s calls deliberately do **not**: `whoami` and `icacls` are Windows console programs
  that emit the console codepage, so they keep the locale default and only add
  `errors="replace"`.

  **Caveat added after the first macOS run:** that `ssh -G` echoed the CJK alias back at all
  was a *locale artifact*, not a property of ssh. Do not read this bullet as evidence that
  non-ASCII aliases work — see trap 5.

The last three are invisible on Linux, where `chmod` works, `os.linesep` is already `\n`, and
the locale is UTF-8. Testing on the development platform cannot surface them.

One more, measured with the real parser: an **unquoted `IdentityFile` path containing a space
makes `ssh` reject the entire config file** (`keyword identityfile extra arguments at end of
line`), not merely that one host. `_quote_path` in `writers/openssh.py` quotes exactly those
paths, and leaves every space-free path byte-identical.

### 5. Whether `ssh` accepts an alias depends on the **C library**, not on OpenSSH

Measured on macOS 26.2 with OpenSSH 10.0p2 against a real 213-host profile: **55 hosts had a
non-ASCII alias, and not one of them could be reached through the generated `sshconfig`.**

```
$ ssh -G -F out/sshconfig -- '<CJK alias>'
hostname contains invalid characters          # exit 255, stdout empty
```

**The check is applied to the destination argument, before any config lookup.** `ssh -G -F
/dev/null -- '<CJK alias>'` fails identically, and a matching `Host` block with an ASCII
`HostName` does not rescue it. So no `ssh_config` content can fix this — only the alias can.

The first read of this was "locale-dependent". That was too narrow. Same OpenSSH version, two
libcs:

| | `C` | `en_US.UTF-8` | `zh_CN.UTF-8` |
|---|---|---|---|
| macOS 26.2, OpenSSH 10.0p2 | accepted | **rejected** | **rejected** |
| Fedora 43, glibc 2.42, OpenSSH 10.0p2 | accepted | accepted | accepted |

Consistent with `valid_domain()` testing bytes with `isalnum()` against the locale's
single-byte ctype table — the tables differ between libcs. Latin-1 accented characters such as
`café` pass everywhere; CJK depends on both axes.

**This is why the fix belongs in the output, not in a runtime check.** A generated `sshconfig`
is portable data: written on one machine, used on another, which is most of the point of this
tool. "Works where it was generated" is not the bar.

So each host gets a second `Host` pattern when its alias is one ssh may refuse:

```
Host A01<CJK> A01
    HostName 192.0.2.11
```

Four decisions worth keeping:

- **The ASCII form comes second.** If the original ever becomes valid everywhere, the file must
  not have quietly trained people onto the derived name.
- **Nothing is demoted to a comment.** `Host` takes several patterns, so the original alias is
  still a real alias on every platform that accepts it.
- **Both aliases come from the same `AliasAllocator`**, in two passes — every primary alias is
  allocated before any ASCII fallback. A single pass would let a derived name take a name
  another host wanted for itself and push that host to `-2`.
- **A label that strips to nothing falls back to the address**, which is what `label_was_empty`
  already does for a host the user never named. On the real profile that was 26 of the 55.

`is_ssh_safe` is deliberately stricter than any one platform: ASCII only, and no leading `-`.
The leading dash is its own small trap — ssh rejects it *and* would read it as an option first,
so `verify.py` passes `--` before the destination. Without that, `ssh -G -F cfg -orig` parses
as `-o rig` and fails with `no argument after keyword "rig"`: an error about the config file,
for a problem that is entirely in the alias.

**The first report of this named the wrong cause**, which cost a detour. `verify_openssh` read
`.stdout` only, so an empty stdout became `<alias>: hostname` — a value mismatch that never
happened. It now tests `returncode` first and reports ssh's own message under its own check,
`openssh: alias accepted by ssh`. The parse probe had the same flaw in a nastier form: it used
`model.hosts[0].alias`, so a profile whose alphabetically first alias is one ssh rejects would
report a perfectly good file as "ssh rejected the config" **and suppress every later check**.
It now probes with a fixed valid destination.

Verification tries **every** pattern rather than stopping at the first that works. Checking only
the original would leave the ASCII alias unverified on a libc that accepts the original — which
is exactly the platform where it is never exercised in anger, and so exactly where it would rot
unnoticed.

A related trap in the same family, latent rather than active: `slug()` used to permit `@`, and
ssh reads `@` in a destination as the user separator. `Host root@gateway` plus `ssh
root@gateway` resolves to user `root` on a host named `gateway` — a different machine, no
error. `@` is now replaced like any other unsafe character.

### 6. A `slug` is a destination, not a filename, and `file_base` is a filename

`slug()` answers "what may appear in something someone types at `ssh`". `Key.file_base` used
its answer as **one path component** under `keys/`, which is a different question. Three shapes
`slug` happily produces are not names at that position, and all three fail without an error:

| `file_base` | What actually happened |
|---|---|
| `.` | `keys/.` *is* `keys/` — the key directory was replaced by a file holding a private key |
| `..` | `keys/..` is the output root — `IsADirectoryError`, mid-export, after files were written |
| `NUL`, `nul.pem` | On Windows the OS opens the null device rather than creating a file: the write succeeds and the key is discarded. Reserved **by stem**, so an extension does not help |

`model.file_slug` is the filename-safe form and `normalize` builds `file_base` with it. It also
drops a trailing dot, which Windows strips silently — `backup.` and `backup` are one file there,
so leaving it would let the filesystem merge two keys behind the allocator's back.

**The worse half was collision handling.** `_dump_keys` registered only the private-key path;
the `.pub` path was derived and never reserved. Dots survive `slug`, so a key labelled
`id_rsa.pub` is an ordinary key — and next to one labelled `id_rsa` the two fought over one
filename:

```
keys/id_rsa       PRIVATE-A          # written for "id_rsa"
keys/id_rsa.pub   PUBLIC-A           # ...on top of "id_rsa.pub"'s private key
```

Either ordering loses a file. The costly one destroys a private key outright and leaves
`IdentityFile` pointing at a public key.

**And the self-check could not see it.** `verify_key_files` decides what to fingerprint by
suffix, skipping `*.pub` and `*.txt` — so the one file the collision corrupts is the one it
never looks at, and a key merely *named* `notes.txt` was never checked either. The export was
wrong, a private key was gone, and every check reported green. That is precisely the
"quietly wrong" outcome this project rates as worse than no output at all.

`keyfiles._allocate` now reserves the private path and its `.pub` sibling **as a pair**, and
treats a name ending in a verifier-reserved suffix as taken, so the counter moves it aside
(`id_rsa.pub` → `id_rsa.pub_2`). That also removes a third latent case: an orphan key labelled
`README.txt` used to be overwritten by the `keys-unlinked/README.txt` written after it.

The general lesson is the one the tests section already makes: this lived in `cli.py`, so
**nothing could test it**. Moving it to `keyfiles.py` is what surfaced all of it. When a
function cannot be reached from a test, that is a fact about the design, not about the test.

### 7. A host's credentials are not always on the host's own row

Measured on a real macOS (DMG) profile with 146 raw host rows. The export ran clean and every
self-check passed, yet many hosts came out with no username or password, and nested groups lost
their parents. Three separate causes:

- **Group inheritance.** Termius shows an empty host field as inheriting from the host's group,
  and that group from its `parent_group`. `normalize` used to read only the host's own
  `ssh_config`, and kept only the innermost group's label, so `Clients/Acme` became `Acme`.
  It now walks host → group → parents for the identity, key, port and proxy, field by field,
  and writes the full `/`-separated path. An empty string here means "unset", deliberately
  unlike the empty `label` of trap 2: that is what Termius itself shows.
- **Rows created while sync is off.** 35 hosts, 34 configs and 3 groups had `id: undefined`,
  not a missing `id`. Every such row shares that one value, so indexing on it can resolve a
  reference to an unrelated row. Some of these rows also hold `local_id` only as the IndexedDB
  record key (`145.0`, a float). `normalize.adopt_record_key` drops the meaningless `id` and
  takes `local_id` from the key, before deduplication, so these rows dedup and dereference by
  `local_id` like any other.
- **`ssh_config_identities`.** Newer Termius links a config to its identity through this join
  table rather than `ssh_configs.identity`. It is now read as a fallback.

With only the first cause fixed, the profile exported 105 passwords and 106 usernames for 145
hosts. With all three, 135 and 138, and the deduped host count dropped to the true 144 — the 145th had been a second generation of one never-synced
host that only became recognisable once its `local_id` was.

The lesson repeats trap 1's: **compare counts against what the application shows.** All checks
passing said only that the output matched the model, not that the model matched Termius.

---

**`Local State`'s `os_crypt.encrypted_key` is not the localKey.** It base64-decodes to a
`DPAPI` prefix and is Chromium's own cookie / Local-Storage key, present in every Electron
app. Do not investigate it again.

---

## Tests

`tests/` uses the standard library's `unittest`, deliberately — not pytest.

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Two reasons. The suite needs no install, and `localkey`, `model`, `fsperm` and every writer
import with stdlib alone, so it runs on a bare Python without `pynacl` or
`ccl_chromium_reader`. More importantly it runs unmodified **on Windows**, so the pure Windows
logic is exercised natively rather than only simulated from Linux.

Tests requiring a real Windows API call are guarded with
`@unittest.skipUnless(sys.platform == "win32", ...)`.

**Never import `cli`, `crypto` or `source` from a test** — they pull `pynacl` /
`ccl_chromium_reader` and will fail to import on a bare checkout. This is why
`write_private` lives in `fsperm` rather than `cli`, why data-directory resolution lives in
`datadir`, and why the "wrong key" message lives in `localkey`. When something in `cli` needs
a test, move it out rather than importing `cli`.

`keyfiles` is the case that proves the rule was worth enforcing rather than merely stated.
`_dump_keys` sat in `cli` and was therefore untested, and it was silently destroying private
keys — see trap 6. The move came first and the defects fell out of the first tests written
against it. Anything still in `cli` should be read as untested, because it is.

`envelope` was split out of `crypto` for the same reason, and it is the sharper case: the
function that picks which field a candidate key is tested against has a silent failure mode.
Return a plaintext field and it "decrypts" under every key, so every candidate validates and
key selection quietly stops selecting. A behaviour that fails without any error is exactly the
kind that has to be tested, so it cannot live behind a PyNaCl import.

`normalize` **is** importable, and deliberately so: its two references to `Decryptor` and
`RawTables` are annotations only, so they sit under `if TYPE_CHECKING` and the heavy modules
never load. `build_model` takes both objects as arguments and constructs neither, so a test can
pass a stub whose whole contract is `walk()` and `stats`. That module holds the trickiest logic
in the project; leaving it untestable to save two import lines was a bad trade.

`ruff`'s findings in `tests/` are silenced per-file rather than worked around. `E402` is
unavoidable — `sys.path.insert(0, "src")` has to run before the package is imported, which is
the property that lets the suite run from a bare checkout. `UP012` is redundant to Python but
load-bearing to the reader: those tests assert *which* encoding was produced, so spelling out
`.encode("utf-8")` is the assertion.

## Writer plugin interface

```python
class MyWriter:
    name = "myclient"
    title = "MyClient config"
    verified = "roundtrip"          # see below

    def write(self, model: Model, ctx: WriteContext) -> list[OutputFile]:
        ...
```

`ctx.key_path(host.key)` yields the absolute path of the private key on disk;
`ctx.include_secrets` decides whether plaintext passwords are written.

### The `verified` field — the most important convention here

| Value | Meaning |
|---|---|
| `roundtrip` | Output has been **read back and validated** by the target client or its official parser |
| `upstream-source` | Fields follow the target client's **type definitions in its own source code**, but no import round-trip was performed |
| `unverified` | Guessed from documentation or experience |

**This repository does not ship `unverified` writers.** A config file that is quietly wrong is
worse than no config file at all — someone will point it at a production host.

Labelling this honestly is non-negotiable. `verify.py` reports Tabby's round-trip check as
`skipped` rather than `pass` for exactly this reason.

**`roundtrip` means the round-trip that ran, not a guarantee for every environment.** OpenSSH is
labelled `roundtrip` and has earned it — the round-trip is what caught trap 5 — but it validates
the aliases *the local `ssh` accepts*, and which aliases those are depends on the C library. A
writer whose correctness varies by platform should say so here rather than let the label imply
more than was measured. A check that only ever confirms what you already believe is not doing
anything.

### Adding a writer

1. **Get a source of truth first.** Either:
   - export a real config file from the target client (best), or
   - read the target client's own type definitions (acceptable — label `upstream-source`).

   If you have neither, don't write the writer.

2. Create a module under `writers/`. In the module docstring, **cite the source of truth
   precisely** (repository path, file, type name). See `tabby.py` for the pattern.

3. Register it in `WRITERS` in `writers/__init__.py`.

4. Add an offline check to `verify.py`. Even a structural check is worth having; if a round-trip
   is impossible offline, return `passed=None` explicitly.

---

## Verification strategy

**Anything that can be falsified locally must actually be run**, not eyeballed.

| Format | How it is verified |
|---|---|
| OpenSSH | `ssh -G -F <file> <alias>` — let ssh itself parse it, then compare its resolved hostname/port/user per host. Reported as two checks: whether ssh *accepted* the alias, and whether the values it resolved match |
| JSON | `json.load` round-trip, compare host and key counts |
| CSV | `csv.DictReader` round-trip, compare addresses row by row |
| Tabby | Structural check (entry count, quote balance); round-trip import reported as `skipped` |
| Termix | Schema check against `normalizeImportedHost`'s contract (required `ip`, `authType` and `tunnelType` domains); round-trip reported as `skipped` |
| known_hosts | `ssh-keygen -F <host> -f <file>` per entry — OpenSSH's own known_hosts parser |
| Private keys | `ssh-keygen -l -f` on every emitted key, confirming they are real, parseable keys |

Three traps in that table, all found by a 213-host real-world export rather than by reading:

- **`ssh -G` lower-cases the hostname.** Comparing it case-sensitively against the model
  reports every host with an uppercase address as a mismatch. DNS is case-insensitive.
- **A non-zero exit is not a value mismatch.** Reading `.stdout` alone silently turns "ssh
  refused to run" into "the hostname disagreed", which is a true failure reported under a false
  cause. Check `returncode` before comparing anything. See trap 5.
- **`ssh-keygen -l -f <private>` silently falls back to `<private>.pub`.** Any test of the
  private-key path must delete the `.pub` first, or it proves nothing. This is how the
  passphrase-protected PKCS#1 PEM case stayed hidden: those keys encrypt the public modulus
  too, so without the `.pub` ssh-keygen reports `is not a key file` — the same message as for
  genuine corruption. `_is_encrypted_pem` separates them, and such keys are reported as
  **skipped**, never as passed.

A check that reports a false failure is worse than no check: it teaches people to ignore the
whole verification pass.

**Not every mismatch is a false alarm, though.** The same export reported two hosts whose
address was `3221226008` rather than `192.0.2.24` — Termius stores some addresses as a packed
32-bit integer. ssh coped, because `inet_aton` accepts a bare 32-bit number, so the sshconfig
worked and only the readback disagreed. But the packed form would have reached Tabby, Termix,
CSV and JSON, whose consumers do *not* cope: Node's `net.connect` treats `"3221226008"` as a
name to resolve and the lookup fails. `model.py::expand_packed_ipv4` normalises it. The
lesson is that a readback mismatch is a symptom, not a diagnosis — chase it to the cause
before deciding which side is wrong.

The CLI exits non-zero if any check fails.

---

## Security posture

- Output directory `0700`, private keys `0600`, process `umask 077` — **on POSIX**. Windows
  gets an equivalent via `icacls`; see trap 4. Everything goes through `fsperm`, so the
  platform difference lives in one file rather than being scattered through `cli.py`
- **No extra plaintext intermediate files.** Decrypted data only ever exists in memory
- `--no-secrets` exports structure without passwords or passphrases
- **Orphaned keys are still written out** to `keys-unlinked/`, never silently dropped. Its
  `README.txt` states plainly that "not referenced" ≠ "not in use"
- The tool is **read-only**; it never modifies or deletes Termius data

`.gitignore` covers every output path. Note that its patterns are anchored — an unanchored
`localkey*` would also match `src/termius_export/localkey.py`, which is source code.

---

## Reverse-engineering method

The method matters more than the result. The cipher format was worked out like this:

**1. Find the key before attacking the ciphertext.**
The application has to store a decryption key somewhere. Desktop Electron apps almost always use
the OS keyring. Enumerate every entry and search on variations of the application name. Once you
have the key you have a way to verify hypotheses.

**2. Use known plaintext to measure the overhead.**
You don't know the algorithm, but you do know **what some plaintexts must be** — a host the user
never named has an empty-string label. The ciphertext length for empty plaintext *is* the
format's fixed overhead. Here: 42 bytes.

Cross-check with a variant: take the shortest address field and compute
`len(ciphertext) - len(plaintext)`. A constant result means a fixed-overhead AEAD rather than
block padding.

**3. Use the overhead number to guess the algorithm.**
42 = 2 + 24 + 16. A 24-byte nonce plus a 16-byte MAC is the signature of NaCl secretbox
(AES-GCM and ChaCha20-Poly1305-IETF are both 12 + 16). So what are the extra two bytes?

**4. Check whether the prefix is fixed or random.**
Collect the first N bytes of every ciphertext and deduplicate. All identical → a fixed header
(a version marker). All different → a random nonce. Here the first two bytes were always `0401`,
so: version header.

**5. Decrypt under the hypothesis, then validate across the whole corpus.**
Take the nonce from offset 2 and run secretbox. All 26 sampled fields decrypted, and all 9 private
keys came out containing `BEGIN ... PRIVATE KEY`. Hypothesis confirmed.

**Only a full-corpus pass counts as verification.** One or two successful fields can be luck.

A cautionary note: the first attempt read the nonce from offset 0, all 26 samples failed, and the
conclusion was nearly "this is a proprietary scheme, we must depend on the app's own native
module." **One failure is not enough to give up** — quantify the length relationships first, then
decide.

### Why Python, in the end

The original implementation was Node, because decryption had to call the application's bundled
native module via `ELECTRON_RUN_AS_NODE`. Once the cipher format was understood, that constraint
disappeared and the language was free again.

The single decisive reason for Python: **Chromium stores IndexedDB values in V8 structured-clone
format inside LevelDB, and `ccl_chromium_reader` already implements that.** Any other language
would require writing a V8 deserializer from scratch — the largest and most fragile part of the
whole project, and one that would keep breaking as Chromium evolves.

---

## Known limitations

- Verified on Linux (snap install) and on Windows. The Windows evidence is a real 213-host /
  22-key / 264-known_hosts profile on a Chinese-localized Windows with Python 3.12: `localKey`
  read from Credential Manager (blob encoding measured as UTF-8), all six formats emitted, and
  every self-check passing with no hardening warnings. The resulting ACL was inspected rather
  than assumed: `icacls out\keys` showed a single ACE, `<HOST>\<user>:(OI)(CI)(F)` — inherited
  entries stripped, no `Authenticated Users` or `BUILTIN\Users`
- The localization matters to that evidence: it is what exposed the `icacls`-principal and
  GBK-decoding traps. A run on an English Windows would not have caught either
- **macOS: the DMG build is verified; the App Store build is not.** The DMG evidence is a real
  213-host / 22-key / 264-known_hosts profile on macOS 26.2 (arm64) with Python 3.12 and
  OpenSSH 10.0p2: data directory auto-detected at `~/Library/Application Support/Termius`,
  `localKey` read from the login keychain, the whole corpus decrypted, all six formats emitted,
  and POSIX modes measured rather than assumed (`out` 0700, `keys/` 0700, private keys 0600,
  `sshconfig` and `hosts.csv` 0600) with no hardening warnings. One caveat belongs with it: a
  keychain authorization dialog appears on first run (trap 3). All 213 hosts are reachable
  through the generated `sshconfig`, 55 of them via the ASCII alias that this platform's ssh
  requires (trap 5)
- **macOS App Store: measured too.** Bundle id `com.termius.mac` (read from the bundle, with
  `Contents/_MASReceipt` present), data at
  `~/Library/Containers/com.termius.mac/Data/Library/Application Support/Termius`, matched by
  the container glob with nothing left to guess, and its `Termius (MAS)` keychain entry
  decrypts that profile. `datadir.py` still globs rather than hard-coding the id, since the id
  is Termius's to change
- Do **not** identify the build with `osascript -e 'id of app "Termius"'`. With both builds
  installed the App Store copy lands as `Termius 2.app`, so the name `Termius` still resolves
  to the DMG bundle and the answer is silently wrong. Read `CFBundleIdentifier` from the
  specific bundle
- A freshly synced profile shows **no** LevelDB duplication: the App Store install reported 213
  raw host rows for 213 hosts, against the DMG profile's 426 for the same data. Historical
  generations accumulate with use rather than appearing at sync, so validating the dedup step
  (trap 1) against a new install would suggest it does nothing
- Hardware-backed keys (Apple Secure Enclave, Windows TPM) **cannot be exported** — the private
  key never leaves the hardware. Those must be regenerated
- The Tabby writer has not been round-trip verified; see the `verified` table above
- Only cipher version header `0401` has been observed. If upstream changes schemes the tool fails
  loudly rather than producing wrong output
