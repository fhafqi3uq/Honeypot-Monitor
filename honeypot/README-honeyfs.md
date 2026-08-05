# honeyfs-overlay/ + fs.pickle

Cowrie's fake filesystem needs **two** things to make a decoy file show up
under `ls`/`cat`, not one:

1. **`src/cowrie/data/fs.pickle`** — the directory tree itself (names,
   sizes, permissions). This is what `ls -la` reads. A file that only
   exists on disk under `honeyfs/` but has no matching entry here is
   invisible — `ls` won't list it at all.
2. **`honeyfs/<path>`** — the actual bytes `cat` returns. Cowrie's
   `Filesystem.init_honeyfs()` (`src/cowrie/shell/fs.py`) walks this
   directory at every startup and wires each file to the matching
   `fs.pickle` entry (via `A_REALFILE`) *if and only if* that entry
   already exists in the pickle. It never creates new pickle entries on
   its own.

So `honeyfs-overlay/` (this repo, tracked) + `fs.pickle` (this repo,
tracked) ship together — `SETUP.md`'s Cowrie install step copies both onto
a freshly cloned `cowrie-src` (`cp -r ../honeyfs-overlay/. honeyfs/` +
`cp ../fs.pickle src/cowrie/data/fs.pickle`). Copying only one half is a
common mistake and silently does nothing: dropping files into `honeyfs/`
without registering them in `fs.pickle` leaves `ls` showing nothing, and
replacing `fs.pickle` without the matching `honeyfs/` files leaves `cat`
printing "No content in pickle file for X".

## What's actually in here

A believable "small company's compromised web/payment server" persona,
consistent across every file (same Debian 12 / kernel 6.1 version in
`cowrie.cfg`'s `kernel_version`/`kernel_build_string`, `etc/os-release`,
and `proc/version` — a mismatch there is a classic honeypot tell):

- `root/` — `.bash_history` with a plausible admin session, a fake
  `wallet.dat`, SSH keys/`authorized_keys` (all fake, non-functional).
- `home/admin/backup/` — a fake MySQL dump and DB credentials file.
- `var/www/html/` — a small fake PHP app (`admin/login.php`,
  `api/users.php`, `upload.php`, a leaked `.env`, a `config.php.bak`).
- `opt/payment/` — fake payment-processing scripts.
- `var/log/` — pre-seeded `auth.log`/`syslog`/`apache2`/`mysql` logs so a
  freshly-started honeypot doesn't look suspiciously log-free.
- `etc/` — `passwd`/`shadow`/`group`/`hostname`/`os-release`/`issue`
  consistent with the Debian 12 persona above.

## Regenerating fs.pickle after editing honeyfs-overlay/

Editing a file already wired into the pickle (same path, same size or
smaller) needs nothing further — `init_honeyfs()` re-reads real file
content live at every Cowrie start. **Adding a new file** or **changing a
file's size** needs a matching pickle entry, via `fsctl` (`cowrie-env/bin/fsctl`
after activating the venv in a real `cowrie-src` checkout):

```bash
cowrie-env/bin/fsctl src/cowrie/data/fs.pickle <<'EOF'
mkdir /path/to/new/dir
touch /path/to/new/dir/newfile.txt <size-in-bytes>
exit
EOF
```

`fsctl`'s own `ls`/`cat` subcommands are unreliable in this Cowrie version
(errors on paths that do exist) — verify with a one-off Python script
reading the pickle directly instead of trusting `fsctl ls`:

```python
import pickle
with open("src/cowrie/data/fs.pickle", "rb") as f:
    fs = pickle.load(f, encoding="utf-8")
# fs is [name, type, uid, gid, size, mode, ctime, contents, target, realfile]
# contents (index 7) is the child-entry list for a directory.
```

After editing, re-copy both `honeyfs/` and `src/cowrie/data/fs.pickle`
back into this repo's `honeypot/honeyfs-overlay/` and `honeypot/fs.pickle`
so the next deploy picks up the change.
