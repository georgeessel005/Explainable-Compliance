# Deployment — Streamlit Community Cloud

The repo is deploy-ready: `streamlit_app.py` at the root is the entry point,
`requirements.txt` is minimal and pinned (all pure-Python / manylinux wheels — no
`packages.txt` needed), no secrets, state is `st.session_state` only, and every file path
uses `pathlib`/`tempfile` (no Windows-only assumptions). The synthetic dataset is committed,
so the app has data on first load; it also regenerates deterministically if absent.

## Step 1 — Push to GitHub

`gh` is **not installed** on this machine, so create the remote repo manually.

1. Create an empty repo on GitHub named `compliance-tool` (no README/licence/.gitignore —
   the repo already has them). Copy its URL.
2. From `c:\xampp\htdocs\george`:

   ```bash
   git remote add origin https://github.com/<your-username>/compliance-tool.git
   git branch -M main
   git push -u origin main
   ```

   (If you later install the GitHub CLI, `gh repo create compliance-tool --public --source . --push`
   does steps 1–2 in one command.)

## Step 2 — Link on Streamlit Community Cloud (one-time, ~2 min, manual)

This is the single step that cannot be automated — the first link is a web action.

1. Go to **share.streamlit.io** and sign in with GitHub.
2. Click **New app** → **Deploy a public app from GitHub**.
3. Repository: `<your-username>/compliance-tool`. Branch: `main`.
   Main file path: `streamlit_app.py`.
4. **Advanced settings** → Python version **3.11**, 3.12, or 3.13 (all work; the code needs
   3.10+).
5. Click **Deploy**.

After this first link, **every `git push` to `main` auto-redeploys** — no further manual
steps ever.

## If the Cloud build fails

Almost always a dependency issue. Open the build logs on the app page. The pinned set here
(streamlit, pydantic, PyYAML, reportlab, pandas, altair) installs cleanly on Community Cloud
with no system libraries. The PDF is written to `tempfile.gettempdir()` (`/tmp` on Cloud,
writable and ephemeral) and served to the user from in-memory bytes — correct for Cloud's
read-only app directory.

## Verifying report integrity after download

Each compiled PDF carries a SHA-256. To re-verify:

```bash
sha256sum compliance_report.pdf          # Linux / macOS / Cloud
certutil -hashfile compliance_report.pdf SHA256   # Windows
```
