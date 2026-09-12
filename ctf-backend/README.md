# CTF Solver Backend

A dockerized FastAPI backend that accepts a text prompt + optional files, figures out
what *kind* of CTF challenge it is (crypto / stego / forensics / archive / misc / web),
runs the relevant tools against the input, collects everything it found ("evidence"),
then hands that evidence + the original prompt to Gemini to reason out a flag.

## How it works

```
POST /api/solve  (multipart: text + files[])
        │
        ▼
 1. save_uploads()        -> temp workspace per request (uuid dir)
 2. categorize()           -> looks at file magic bytes, extensions, and the text
                              prompt to guess one or more categories
 3. run_pipeline()         -> runs the tool belt for each matched category
                              (exiftool, binwalk, strings, steghide, zsteg,
                              foremost, file, unzip, base64/hex/rot13 tries,
                              basic RSA/XOR helpers, hidden-file/metadata scan)
 4. build_evidence_bundle()-> collapses all tool stdout/stderr/found-strings
                              into a size-capped evidence document
 5. ask_gemini()           -> sends prompt + evidence + a CTF-solver system
                              prompt to Gemini, asks for JSON: {flag, reasoning}
 6. extract_flag()         -> regex safety net (flag{...}, CTF{...}, etc.) in
                              case Gemini's structured output misses it
        │
        ▼
   { flag, reasoning, category, evidence_summary, job_id }
```

Because tool execution (especially binwalk/foremost on big files) can take a
few seconds to a couple minutes, `/api/solve` is asynchronous:

- it returns a `job_id` immediately (`202 Accepted`)
- poll `GET /api/jobs/{job_id}` for status (`pending` / `running` / `done` / `error`)
- results are kept in memory with a TTL (see `app/job_store.py`) — swap in Redis
  if you need multi-instance/horizontal scaling later, the interface is a single
  small class so that's a drop-in change.

## Running locally

```bash
cp .env.example .env      # fill in GEMINI_API_KEY
docker build -t ctf-backend .
docker run --env-file .env -p 8000:8000 ctf-backend
```

Docs at `http://localhost:8000/docs`.

## Deploying to Railway

1. Push this folder to a git repo.
2. Railway -> New Project -> Deploy from GitHub repo.
3. Railway auto-detects the `Dockerfile` and builds it (no Nixpacks needed).
4. Set environment variables in the Railway dashboard (see `.env.example`):
   - `GEMINI_API_KEY` (required)
   - `MAX_UPLOAD_MB` (optional, default 50)
   - `TOOL_TIMEOUT_SECONDS` (optional, default 25 per tool)
   - `ALLOWED_ORIGINS` (comma separated, for your frontend's CORS)
5. Railway sets `$PORT` automatically — the container's CMD already reads it.
6. Done. Railway gives you a public URL; point your frontend at
   `https://<your-app>.up.railway.app/api/solve`.

No external services (no Redis/Postgres) are required for a first deploy —
everything runs in a single container, which fits Railway's simplest tier.
If you outgrow one instance, see "Scaling notes" below.

## Deploying to Vercel instead

Vercel now runs Dockerfiles as Vercel Functions. This repo already has what
you need:

1. Push this folder to a git repo, import it as a Vercel project.
2. Vercel auto-detects `Dockerfile.vercel` and builds/runs it as a function.
3. Add a KV/Redis database from the Vercel Marketplace (Upstash, or Vercel KV)
   and set its connection string as `REDIS_URL` in your project's env vars.
   **This is required, not optional** — Vercel Functions autoscale across
   instances, so job status has to live somewhere shared instead of in one
   process's memory.
4. Set `GEMINI_API_KEY` (and any other vars from `.env.example`) in the
   Vercel dashboard.
5. No `vercel.json` is needed for this. Under Fluid compute, Vercel Functions
   already default to a 300-second duration on every plan, which is enough
   room for a slower analysis (binwalk extraction, foremost carving) to
   finish inline before the request times out. If you genuinely need longer
   than that, check Vercel's current docs for how duration is configured for
   container-image functions specifically — the `functions` key in
   `vercel.json` only matches conventional function file paths (e.g. under
   `api/`), not an auto-detected `Dockerfile.vercel`, so it can't be set that
   way (that's the `"doesn't match any Serverless Functions"` error if you
   try).

Everything else (routes, pipeline, Gemini call) is identical between the two
hosts — only the job-status storage and the Dockerfile name differ.

## Security notes (read before exposing this publicly)

- Uploaded files are processed in an isolated temp dir per request and deleted
  afterward (`app/workspace.py`), including on error.
- Every external tool call goes through `run_tool()` which enforces a timeout,
  disables shell interpolation (`shell=False`, argv lists only), and caps
  captured output size — a hostile file can't hang the worker or fill memory.
- Filenames from the client are never used to build paths directly — they're
  sanitized/rewritten to random names on disk (`app/workspace.py::save_upload`).
- `MAX_UPLOAD_MB` and a max-files-per-request cap are enforced before anything
  touches disk.
- This service executes fairly heavyweight binary-analysis tools on
  attacker-controlled files. That's the point (CTF forensics), but don't run it
  with elevated privileges, and consider Railway's resource limits / a
  dedicated low-privilege container if you open it to the public internet.

## Scaling notes

- Swap `app/job_store.py`'s in-memory dict for Redis and move tool execution
  into a Celery/RQ worker if you need more than one instance or very long jobs.
- The tool wrappers in `app/tools/` are plain functions with no shared state,
  so moving them into a worker process is a copy-paste job, not a rewrite.
