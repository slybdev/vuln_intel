# Tactical Ops local setup

Start PostgreSQL and the scan worker from the project root:

```powershell
docker compose up -d --build postgres scan-worker
```

Install the Python dependencies and start the API in a separate terminal:

```powershell
python -m pip install -e .
python -m vuln_intel.dashboard --host 127.0.0.1 --port 8081
```

Start the Tactical Ops UI from the project root in another terminal:

```powershell
npx --yes bun install
npx --yes bun run dev
```

Open <http://127.0.0.1:3000>. Vite proxies `/api` requests to the Python API on port `8081`.
Keep both services bound to localhost for local use. Copy `.env.example` to `.env` and set
credentials only when needed; never commit `.env` or provider tokens.

The production Docker image builds the frontend and serves it with the API on port `8000`.
Configure a database host reachable from the container; `127.0.0.1` inside a container refers
to the container itself.
