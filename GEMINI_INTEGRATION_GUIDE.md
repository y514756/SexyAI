# Gemini API Integration Guide

> How SexyAI (Planner App) connects to Google Gemini for chat and nightlife radar scanning.
> Use this as a reference to replicate the system on LOKKR.APP.

---

## Architecture Overview

```
Browser → Your Server (Express) → Gemini REST API
                ↓
          Supabase (stores results)
```

The Gemini API key is **never exposed to the frontend**. All Gemini calls go through your server as a proxy. The frontend sends a request to your API, your server calls Gemini, and returns the result.

---

## Environment Variables

```env
GEMINI_API_KEY=your_google_ai_studio_key_here
```

Get a key from [Google AI Studio](https://aistudio.google.com/apikey). Set it in your `.env` locally and in Railway (or whatever hosting) for production.

---

## Gemini API Basics

**Base URL:**
```
https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${GEMINI_API_KEY}
```

**Model:** `gemini-2.5-flash` (stable, fast, supports grounding with Google Search)

**Request format:**
```json
{
  "systemInstruction": {
    "parts": [{ "text": "Your system prompt here" }]
  },
  "contents": [
    { "role": "user", "parts": [{ "text": "User message" }] },
    { "role": "model", "parts": [{ "text": "Assistant reply" }] }
  ],
  "tools": [{ "googleSearch": {} }],
  "generationConfig": {
    "temperature": 0.85,
    "topP": 0.95,
    "topK": 40,
    "maxOutputTokens": 300,
    "responseMimeType": "text/plain"
  }
}
```

**Response format:**
```json
{
  "candidates": [
    {
      "content": {
        "parts": [
          { "text": "The generated response text" }
        ]
      }
    }
  ]
}
```

> **Important:** When using `googleSearch` tool, the response may have multiple `parts`. Filter for text parts and join them:
> ```js
> const text = candidate.content.parts.filter(p => p.text).map(p => p.text).join('\n');
> ```

---

## Endpoint 1: Chat Proxy

This is a general-purpose Gemini proxy — the frontend sends messages and a system prompt, the server forwards to Gemini and returns the text.

### Server (Express)

```js
app.post('/api/chat/gemini', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY not configured on server' });

  const { messages, systemPrompt } = req.body;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: systemPrompt }] },
          contents: messages.map(m => ({
            role: m.role === 'user' ? 'user' : 'model',
            parts: [{ text: m.content }]
          })),
          tools: [{ googleSearch: {} }],
          generationConfig: {
            temperature: 0.85,
            topP: 0.95,
            topK: 40,
            maxOutputTokens: 300,
            responseMimeType: 'text/plain'
          }
        })
      }
    );

    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ error: errText.substring(0, 500) });
    }

    const data = await response.json();
    const text = data.candidates[0].content.parts[0].text;
    res.json({ text });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

### Frontend Call

```js
const res = await api.post('/api/chat/gemini', { messages, systemPrompt });
const reply = res.text;
```

### Config Notes
- `maxOutputTokens: 300` — keep this low for chat to stay snappy
- `googleSearch` is enabled so Gemini can ground responses in real web data
- Role mapping: frontend uses `user`/`model`, Gemini expects the same

---

## Endpoint 2: Radar Scan (Nightlife Intel)

This is the "Live" scanner — calls Gemini with a nightlife-specific system prompt, saves the result to the database, and returns it.

### Server (Express)

```js
app.post('/api/radar/scan', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY not configured on server' });

  const { city = 'Toronto', prompt } = req.body;
  const defaultPrompt = `Radar Check: What's happening in ${city} queer nightlife right now? Cover: new parties/events this week, venue buzz, scene shifts, any promoter or creator activity worth noting. Be specific — names, dates, venues. Skip anything you're not confident about.`;
  const userPrompt = prompt || defaultPrompt;

  try {
    const response = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: {
            parts: [{
              text: 'You are a nightlife radar intelligence agent. Your job is to scan the web for the latest queer nightlife activity in a given city. Be punchy, specific, and useful. Include names, dates, venues, and links when possible. Use google_search to ground your responses in real, current information. Skip anything you cannot verify.'
            }]
          },
          contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
          tools: [{ googleSearch: {} }],
          generationConfig: {
            temperature: 0.85,
            topP: 0.95,
            topK: 40,
            responseMimeType: 'text/plain'
          }
        })
      }
    );

    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ error: errText.substring(0, 500) });
    }

    const geminiData = await response.json();
    const candidate = geminiData.candidates[0];
    const text = candidate.content.parts.filter(p => p.text).map(p => p.text).join('\n');

    // Save to database
    const { data, error } = await supabase
      .from('radar_updates')
      .insert({ content: text, city })
      .select()
      .single();
    if (error) return res.status(500).json({ error: error.message });

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});
```

### Frontend Call

```js
const newUpdate = await api.post('/api/radar/scan', { city, prompt: prompt || undefined });
```

### Config Notes
- **No `maxOutputTokens`** — radar responses are long and detailed, let Gemini finish naturally
- System instruction is hardcoded on the server (not sent from frontend) for security
- Response parts are joined with `\n` because `googleSearch` can split output across multiple parts
- Result is saved to `radar_updates` table before returning

---

## Endpoint 3: Radar Prompts (Prompt Library)

CRUD endpoints for saving reusable scan prompts.

### Server (Express)

```js
// List all saved prompts
app.get('/api/radar/prompts', async (req, res) => {
  const { data, error } = await supabase
    .from('radar_prompts')
    .select('*')
    .order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Save or update a prompt (upsert by name)
app.post('/api/radar/prompts', async (req, res) => {
  const { name, text } = req.body;
  if (!name || !text) return res.status(400).json({ error: 'Name and text are required' });
  const { data, error } = await supabase
    .from('radar_prompts')
    .upsert({ name, text }, { onConflict: 'name' })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// Delete a prompt
app.delete('/api/radar/prompts/:id', async (req, res) => {
  const { error } = await supabase.from('radar_prompts').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});
```

---

## Database Schema (Supabase)

Run these in Supabase SQL Editor:

```sql
-- Stores scan results
create table if not exists radar_updates (
  id uuid primary key default gen_random_uuid(),
  city text not null default 'General',
  content text not null,
  created_at timestamptz default now()
);

-- Stores saved prompts
create table if not exists radar_prompts (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  text text not null,
  created_at timestamptz default now()
);

-- Disable RLS (single-operator app, server-side only)
alter table radar_updates disable row level security;
alter table radar_prompts disable row level security;
```

---

## Auth Pattern

All `/api/*` routes are protected by auth middleware. The frontend stores a JWT token and sends it with every request.

### Middleware (Express)

```js
app.use('/api', async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = authHeader.replace('Bearer ', '');
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
  req.user = user;
  next();
});
```

### Frontend API Helper

```js
const apiCall = async (path, opts = {}, _retried) => {
  const token = localStorage.getItem('cc_auth_token');
  const headers = { ...opts.headers };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const r = await fetch(path, { ...opts, headers });
  if (r.status === 401 && !_retried) {
    const refreshed = await tryRefreshToken();
    if (refreshed) return apiCall(path, opts, true);
    logout();
    throw new Error('Session expired');
  }
  if (!r.ok) {
    const data = await r.json();
    throw new Error(data.error || 'API error');
  }
  return r.json();
};

const api = {
  get: (path) => apiCall(path),
  post: (path, body) => apiCall(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body)
  }),
  del: (path) => apiCall(path, { method: 'DELETE' }),
};
```

---

## Key Differences: Chat vs Radar

| Setting | Chat Proxy | Radar Scan |
|---------|-----------|------------|
| `maxOutputTokens` | 300 | None (unlimited) |
| System prompt | Sent from frontend | Hardcoded on server |
| Saves to DB | No | Yes (`radar_updates`) |
| Multi-turn | Yes (full message history) | No (single prompt) |
| Response parsing | Single `parts[0].text` | All text parts joined |

---

## Replicating on LOKKR.APP

To bring this to LOKKR, you need:

1. **Set `GEMINI_API_KEY`** in your LOKKR server environment
2. **Add the proxy endpoint** (`POST /api/chat/gemini` or `/api/radar/scan` or both) to your LOKKR Express server
3. **Create the Supabase tables** (`radar_updates`, `radar_prompts`) in LOKKR's Supabase project
4. **Add frontend UI** — city picker, prompt textarea, scan button
5. **Customize the system instruction** to match LOKKR's voice and use case

The pattern is always the same:
```
Frontend → Your Server (with API key) → Gemini API
                    ↓
              Save result to Supabase
```

No external services needed. No Make.com. No webhooks. Just your server and the Gemini REST API.
