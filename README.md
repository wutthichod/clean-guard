# CleanGuard · Agentic AI (Group 8)

A local storage-cleaning agent. It marks files `keep`, `deletable` or `review`, flags private
documents, and moves only what you approve into a quarantine you can restore from. It never
deletes anything, and nothing leaves your computer: the model runs on your machine through Ollama.

## Set up

Needs Python 3.10+ and [Ollama](https://ollama.com). Run every command from this folder.

macOS or Linux:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
ollama pull qwen3:8b-q4_K_M
```

Windows (PowerShell or cmd):

```powershell
python -m venv .venv
.venv\Scripts\activate.bat
pip install -r requirements.txt
ollama pull qwen3:8b-q4_K_M
```

## Use it

```bash
python -m cleanguard ui                  # web app: scan, manage files, quarantine, chat
python -m cleanguard clean ~/Downloads   # guided, in the terminal: scan, report, approve, undo
```

The web app runs at `http://127.0.0.1:8765/`, on this computer only.

Windows: keep the repo out of OneDrive, because CleanGuard refuses cloud-synced folders.
macOS: allow Files and Folders access when your terminal asks.

## Test it

```bash
python -m unittest discover -s tests     # offline, with a fake model; no Ollama needed
```

More detail: [docs/GUIDE.md](docs/GUIDE.md) has the commands, design notes, evaluation
and the UAT kit. The design document is [CleanGuard_Implementation.md](CleanGuard_Implementation.md).
