# AIKYA — clean deployment setup

AIKYA is a peer-to-peer student skill exchange platform. This repository preserves the existing `index.html` interface and uses FastAPI with PostgreSQL for deployment.

## Fresh database policy

- The app does not import or migrate the old SQLite database.
- The browser no longer seeds fictional demo users, posts, messages, reviews, or credits.
- Existing browser-side AIKYA cache keys are cleared on startup; server data is loaded from the configured database.
- Do not upload `aikya_local.db`, `.env`, real credentials, or student records.

## Deploy on Render + Neon

1. Create a **new, empty PostgreSQL database** in Neon.
2. Push this repository to GitHub.
3. In Render, create a new Web Service from the repository. Render can use `render.yaml`.
4. Set `DATABASE_URL` to the Neon connection string. Keep it private.
5. Set `ALLOWED_ORIGINS` to the exact public service origin, for example `https://your-service.onrender.com` (no trailing slash). If you add a custom domain, add it as a comma-separated origin.
6. Deploy, then open `/api/health`. A healthy response should show `status: ok` and `database: PostgreSQL`.

## Important limitations before inviting real students

This is a first production-preparation pass, not a claim that every feature has passed end-to-end testing. The legacy UI uses whole-array local-storage writes. The API now rejects writes to records that are not owned by the signed-in user and scopes private collections, but certain UI actions that mutate another user's record (for example likes or profile reputation updates) need dedicated API endpoints to work reliably and safely. Complete the feature/API refactor and run two-account authorization tests before public launch.

## Local syntax check

```bash
python -m pip install -r requirements.txt
python -m py_compile main.py
```

For local testing with PostgreSQL, set `DATABASE_URL`, `APP_ENV=development`, and `ALLOWED_ORIGINS=http://localhost:8000`, then run:

```bash
uvicorn main:app --reload --host 127.0.0.1 --port 8000
```

## Secrets and data

Never commit real `.env` files, database URLs, session secrets, student exports, or database backups. Rotate any credential that was accidentally committed.
