# LinkerAI

> A Monolithic LinkedIn Automation & Content Engine powered by Hono.js, Postgres, and Gemini AI.

Deployed at: `https://linkerai.iotwise.au`

## Features
- **Monolith Architecture**: Single Hono.js app for API, Dashboard, and Logic.
- **Gemini AI Integration**: Uses `google-genai` headers for text research and image generation.
- **Dual Mode**:
  - **Direct Mode**: Posts directly to LinkedIn.
  - **Webhook Mode (n8n)**: Returns JSON for use in automation workflows.
- **Zero-Maintenance**: Designed for Dokploy with minimal state.

## Setup & Deployment (Dokploy)

### 1. Database Setup
1. Go to your Dokploy Dashboard -> **Databases**.
2. Click **Create** -> Select **PostgreSQL**.
3. Name it `linkerai-db`.
4. Once created, copy the **Internal Connection URL** (e.g., `postgresql://user:password@input:5432/db`).

### 2. Application Deployment
1. Go to **Applications** -> **Create**.
2. Select **GitHub** (or your source provider) and point to this repository.
3. Select the `Dockerfile` build type.

### 3. Environment Variables
Add the following variables in the Dokploy "Environment" tab:

| Variable | Description |
| :--- | :--- |
| `DATABASE_URL` | The Internal Postgres Connection URL from Step 1. |
| `GEMINI_API_KEY` | Your Google Gemini API Key. |
| `API_SECRET` | Secret key for securing the `/api/v1/generate` webhook. |
| `SUPER_ADMIN_PASSWORD` | Password for the root `admin` user on the dashboard. |
| `PORT` | `3000` (Default). |

### 4. Database Initialization
This app does not include a complex migration system to keep things lightweight. 
To initialize the tables:
1. Open the Dokploy Console (or use a tool like pgAdmin/DBeaver connected to the DB).
2. Run the contents of `schema.sql`.

Alternatively, you can add a simple startup script to run the DDL on boot, but manual run is safer for this scope.

## API Usage (n8n / Webhook)

**Endpoint:** `POST https://linkerai.iotwise.au/api/v1/generate`

**Headers:**
- `Content-Type`: `application/json`
- `x-api-secret`: `<YOUR_API_SECRET>`

**Body:**
```json
{
  "mode": "webhook",
  "topic": "The Future of AI Agents in 2026",
  "tone": "Professional and Optimistic"
}
```

**Response:**
```json
{
  "status": "success",
  "text": "Here is the generated LinkedIn post...",
  "image_b64": "<base64_string>",
  "research_summary": "..."
}
```

## Local Development

```bash
# 1. Install Dependencies
npm install

# 2. Setup .env
echo "DATABASE_URL=postgresql://..." > .env
echo "GEMINI_API_KEY=..." >> .env

# 3. run
npm run dev
```

## Tech Stack
- **Framework**: Hono.js
- **Runtime**: Node.js 20+
- **DB**: PostgreSQL
- **AI**: Google Gemini Pro Check
- **Frontend**: Tailwind CSS + HTMX
