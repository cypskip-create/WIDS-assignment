# Installation

Use Python 3.11 or newer with venv and pip. All commands run from the project root. No cloud/API key is needed.

```powershell
python -m venv .venv
.venv\Scripts\python.exe -m pip install -e ".[dev]"
.venv\Scripts\python.exe -m wids.cli fixture
.venv\Scripts\python.exe -m streamlit run app.py
```

Linux/macOS: use `.venv/bin/python` instead. Installation of Scapy does not itself provide monitor-mode hardware. Offline reading requires no administrator privileges. Optional live capture needs a Linux monitor-mode interface and authorized capture permissions configured outside the application.

This workspace was built with the desktop bundled Python 3.12.14. If Python is not on PATH on this same machine, the existing environment is runnable directly as `.venv\Scripts\python.exe`. The runtime location is machine-specific and should not be used as a portable installation command. `requirements-lock.txt` records tested package versions; `pyproject.toml` is the supported dependency declaration.

No network is needed for demo replay once dependencies are installed. Genuine public-data training requires the downloader. See DATASET.md. Raw data and model binaries are gitignored and reproducible. To stop the server press Ctrl+C in its terminal; monitoring cleanup runs on exit. A killed process has no surviving child capture process, and next startup marks unfinished sessions interrupted.
