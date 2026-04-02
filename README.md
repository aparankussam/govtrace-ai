# GovTrace AI

Production-ready split deployment:

- `govtrace-web/`: static frontend for Vercel
- `govtrace-api/`: FastAPI backend for Vercel

Each project can be deployed as a separate Vercel app by setting that folder as the project's Root Directory.

Frontend build command:

```bash
node build.mjs
```

Backend install command:

```bash
pip install -r requirements.txt
```

See `.env.example` in each project folder for the required environment variables.
