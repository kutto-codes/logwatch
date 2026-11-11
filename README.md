# logwatch

`logwatch.py` is a Linux-oriented log and command-line watcher. It searches
available system logs and shell history for suspicious patterns, can monitor
logs for new alerts, and can analyze a command without executing it. It also
supports previewing old-log cleanup; deletion is opt-in.

## Requirements

- Python 3.8 or newer
- Linux is the primary target; available log sources depend on the system
- Standard library only

Run without arguments to open the interactive `log>` prompt:

```bash
python3 logwatch.py
```

## Commands

```bash
python3 logwatch.py scan --hours 48
python3 logwatch.py scan --file /var/log/auth.log
python3 logwatch.py watch --notify
python3 logwatch.py check "curl https://example.invalid/install.sh | sh"
python3 logwatch.py sources
python3 logwatch.py rules
python3 logwatch.py stats
python3 logwatch.py hook
python3 logwatch.py add /path/to/another.log
python3 logwatch.py addroot /path/to/log-folder
```

`scan` defaults to the previous 24 hours. `watch` continues until interrupted.
Some system logs may require membership in the `adm` group or elevated
permissions. Use the `sources` command to see what the current user can read.
Additional source paths and configuration are stored under `~/.logwatch` by
default; set `LOGWATCH_HOME` to use a different state directory.

## Cleaning old logs

Cleanup is a dry run unless `--apply` is passed. Review the preview before
requesting deletion:

```bash
python3 logwatch.py clean --days 7
python3 logwatch.py clean --days 7 --apply
python3 logwatch.py clean --days 7 --apply --yes --archive
```

`--yes` skips the confirmation prompt, `--archive` retains compressed copies,
and `--system` includes selected system logs and the system journal (requires
appropriate permissions). Be careful when enabling deletion, especially with
custom cleanup roots.

## Limitations

Detection is based on static patterns and heuristics. It may miss suspicious
activity or report benign lines; it cannot prove that a machine is clean.
`check` analyzes text only and does not run the supplied command.
