"""Local web app for CleanGuard: scan, manage scanned files, quarantine, and chat.

Runs on 127.0.0.1 only, standard library only, no external assets. The model never moves a
file: chat can only read results and propose a selection, and moves go through the same typed
confirmation and approval token as the CLI (cli.quarantine_selection).
"""
