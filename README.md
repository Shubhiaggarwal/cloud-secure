# CSPM SaaS - AWS Cloud Security Scanner + Always-On AI Assistant

A multi-tenant web app: a company signs up, adds an AWS account (or uses
demo mode), clicks **Scan Now**, gets a findings dashboard with a security
score, and has an AI assistant sitting alongside the results at all times
to help fix what's wrong.

Built on top of the original CLI CSPM scanner - the scan logic
(`checks/`, `engine/`), knowledge base (`knowledge/`), and AI assistant
(`ai/`) are reused almost unchanged, just wrapped in a web API + database
instead of a single-run terminal script.

## Architecture

```
frontend/   React (Vite) - login/signup, dashboard, findings, chat sidebar
backend/    FastAPI - multi-tenant API, Postgres/SQLite, JWT auth
  app/checks/    unchanged CSPM rule logic (IAM, S3, EC2, CloudTrail)
  app/engine/    scoring + severity grouping
  app/ai/        Gemini RAG + system prompt (unchanged)
  app/services/  NEW: AssumeRole scanning, per-scan chat sessions
  app/routers/   NEW: /auth, /accounts, /scans, /chat
```

Each company's AWS account is scanned via `sts:AssumeRole` using a role
ARN they configure (the standard, secure cross-account pattern every real
CSPM tool uses - you never store or see their AWS keys). A **demo mode**
toggle lets you test the whole flow against a seeded mock account with no
real AWS access required.

## Backend setup

```bash
cd backend
python -m venv venv
venv\Scripts\activate      # Windows
# source venv/bin/activate  # Mac/Linux
pip install -r requirements.txt

cp .env.example .env
# edit .env: set GEMINI_API_KEY (https://aistudio.google.com/apikey)
# and a real JWT_SECRET_KEY

python ingest.py           # builds the RAG knowledge base (one-time)
uvicorn app.main:app --reload --port 8000
```

Backend runs at `http://localhost:8000`. Interactive API docs (auto-generated
by FastAPI) are at `http://localhost:8000/docs` - useful for testing
endpoints directly before the frontend is wired up.

## Frontend setup

```bash
cd frontend
npm install
cp .env.example .env       # defaults already point at localhost:8000
npm run dev
```

Frontend runs at `http://localhost:5173`.

## Using it

1. Go to `http://localhost:5173/signup`, create a company account.
2. Click **+ Add account**. Leave "Demo mode" checked to try it instantly
   with a seeded mock AWS account (no real credentials needed).
3. Click **Scan Now**. Findings + security score appear once the scan
   completes (polls automatically).
4. Use the chat sidebar (always visible on the right) to ask about any
   finding, or click "Ask the assistant how to fix this" on a specific
   finding to jump straight into a relevant question.

## Connecting a REAL AWS account (production path)

Instead of demo mode, the company creates an IAM role in their AWS account:

1. Trust policy: allow your backend's AWS account (`SCANNER_AWS_ACCOUNT_ID`
   in `.env`) to assume the role, with a unique `ExternalId` condition.
2. Attach a read-only policy covering what the checks need, e.g.:
   `IAMReadOnlyAccess`, `AmazonS3ReadOnlyAccess`,
   `AmazonEC2ReadOnlyAccess` (security groups), `AWSCloudTrailReadOnlyAccess`.
3. In the app, add the account with "Demo mode" unchecked, pasting in the
   Role ARN and External ID.

## Known limitations / next steps for real production use

- **Scan execution** uses FastAPI `BackgroundTasks` (fine for one process).
  For real concurrent scan volume, swap in Celery + Redis or RQ -
  `run_scan_job()` in `app/routers/scans.py` is already isolated so this is
  a drop-in change, not a rewrite.
- **Chat session storage** is an in-memory dict (`app/services/chat_service.py`).
  Fine for a single-process dev server; move to Redis if you run multiple
  backend workers, so any worker can serve any session.
- **Database** defaults to SQLite for zero-setup local dev. Switch
  `DATABASE_URL` to Postgres for production, and use Alembic migrations
  instead of `Base.metadata.create_all()`.
- **Scheduled/recurring scans** aren't included - this is on-demand only,
  per your requirement. Adding a cron-triggered scan (e.g. via
  APScheduler or a cloud scheduler) is a natural next step if you want
  continuous monitoring later.
- **Password reset, email verification, rate limiting** aren't included -
  add before any real signup traffic.
