require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const cron = require('node-cron');

const app = express();
app.set('trust proxy', 1);
const PORT = process.env.PORT || 3000;

// --- Supabase ---
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// --- Security Middleware ---
// [H4] Restrict CORS to allowed origins
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || `http://localhost:${PORT},https://sexyai-production.up.railway.app`).split(',');
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) cb(null, true);
    else cb(new Error('CORS blocked'));
  },
  credentials: true
}));

// [M1] Security headers
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'"],
      scriptSrcAttr: ["'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com", "https://cdnjs.cloudflare.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com", "https://cdnjs.cloudflare.com"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://api.openai.com", "https://api.anthropic.com", "https://api.x.ai", "https://generativelanguage.googleapis.com"],
      frameAncestors: ["'none'"],
    }
  },
  crossOriginEmbedderPolicy: false,
}));

// [H5] Rate limiting
app.use('/auth/login', rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { error: 'Too many login attempts, try again in 15 minutes' } }));
app.use('/api/chat/gemini', rateLimit({ windowMs: 60 * 1000, max: 10, message: { error: 'Rate limit exceeded' } }));
app.use('/api/radar/scan', rateLimit({ windowMs: 60 * 1000, max: 5, message: { error: 'Rate limit exceeded' } }));
app.use('/api/radar/report', rateLimit({ windowMs: 60 * 1000, max: 5, message: { error: 'Rate limit exceeded' } }));
app.use('/api/radar/industry', rateLimit({ windowMs: 60 * 1000, max: 5, message: { error: 'Rate limit exceeded' } }));
app.post('/api/radar/sandbox', rateLimit({ windowMs: 60 * 1000, max: 5, message: { error: 'Rate limit exceeded' } }));

app.use('/api', rateLimit({ windowMs: 60 * 1000, max: 200, message: { error: 'Rate limit exceeded' } }));

app.use(express.json({ limit: '10mb' }));

// [M2] Serve only public directory, not project root
app.use(express.static(path.join(__dirname, 'public')));

// ─────────────────────────────────────────
// AUTH ENDPOINTS
// ─────────────────────────────────────────
app.post('/auth/signup', (req, res) => {
  res.status(403).json({ error: 'Signup is disabled.' });
});

app.post('/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
  const { data, error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ token: data.session.access_token, refresh_token: data.session.refresh_token, user: data.user });
});

app.post('/auth/refresh', async (req, res) => {
  const { refresh_token } = req.body;
  if (!refresh_token) return res.status(400).json({ error: 'Refresh token required' });
  try {
    // Use the main supabase client to refresh directly
    const { data, error } = await supabase.auth.refreshSession({ refresh_token });
    if (error || !data.session) {
      console.warn('[Auth] Refresh failed:', error?.message || 'no session returned');
      return res.status(401).json({ error: 'Refresh failed' });
    }
    res.json({ token: data.session.access_token, refresh_token: data.session.refresh_token });
  } catch (err) {
    console.warn('[Auth] Refresh error:', err.message);
    res.status(401).json({ error: 'Refresh failed' });
  }
});

app.post('/auth/logout', async (req, res) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.replace('Bearer ', '');
    await supabase.auth.admin.signOut(token).catch(() => {});
  }
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// ICAL FEED (before auth — accessed by Apple Calendar)
// ─────────────────────────────────────────
app.get('/calendar/feed.ics', async (req, res) => {
  const token = req.query.token;
  if (!token || token !== process.env.CALENDAR_FEED_TOKEN) {
    return res.status(403).send('Invalid token');
  }
  const { data: events, error } = await supabase
    .from('calendar_events')
    .select('*')
    .order('date');
  if (error) return res.status(500).send('Error fetching events');

  const icsEvents = (events || []).map(e => {
    const dtStart = e.time
      ? `DTSTART:${e.date.replace(/-/g, '')}T${e.time.replace(/:/g, '')}00`
      : `DTSTART;VALUE=DATE:${e.date.replace(/-/g, '')}`;
    const dtEnd = e.end_time
      ? `DTEND:${e.date.replace(/-/g, '')}T${e.end_time.replace(/:/g, '')}00`
      : e.time
        ? `DTEND:${e.date.replace(/-/g, '')}T${String(parseInt(e.time.split(':')[0]) + 1).padStart(2, '0')}${e.time.split(':')[1]}00`
        : '';
    const desc = (e.description || '').replace(/\n/g, '\\n').replace(/,/g, '\\,').replace(/;/g, '\\;');
    return [
      'BEGIN:VEVENT',
      `UID:${e.id}@sexyai`,
      dtStart,
      dtEnd,
      `SUMMARY:${(e.title || '').replace(/,/g, '\\,').replace(/;/g, '\\;')}`,
      desc ? `DESCRIPTION:${desc}` : '',
      `DTSTAMP:${new Date(e.created_at).toISOString().replace(/[-:]/g, '').split('.')[0]}Z`,
      'END:VEVENT'
    ].filter(Boolean).join('\r\n');
  }).join('\r\n');

  const ical = [
    'BEGIN:VCALENDAR',
    'VERSION:2.0',
    'PRODID:-//SexyAI//Command Center//EN',
    'CALSCALE:GREGORIAN',
    'METHOD:PUBLISH',
    'X-WR-CALNAME:SexyAI Calendar',
    'REFRESH-INTERVAL;VALUE=DURATION:PT15M',
    icsEvents,
    'END:VCALENDAR'
  ].join('\r\n');

  res.setHeader('Content-Type', 'text/calendar; charset=utf-8');
  res.setHeader('Content-Disposition', 'inline; filename="feed.ics"');
  res.send(ical);
});

// ─────────────────────────────────────────
// AUTH MIDDLEWARE (protects all /api/* routes)
// ─────────────────────────────────────────
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

// ─────────────────────────────────────────
// COMPANIES
// ─────────────────────────────────────────
app.get('/api/companies', async (req, res) => {
  const { data, error } = await supabase.from('companies').select('*').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/companies', async (req, res) => {
  const { name, color, description, industry, tone, audience, context } = req.body;
  const { data, error } = await supabase.from('companies').insert({ name, color, description, industry, tone, audience, context }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/companies/:id', async (req, res) => {
  const { name, color, description, industry, tone, audience, context } = req.body;
  const updates = Object.fromEntries(Object.entries({ name, color, description, industry, tone, audience, context }).filter(([, v]) => v !== undefined));
  const { data, error } = await supabase
    .from('companies')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/companies/:name', async (req, res) => {
  const { error } = await supabase.from('companies').delete().eq('name', req.params.name);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// PLAYBOOKS
// ─────────────────────────────────────────
app.get('/api/playbooks', async (req, res) => {
  const { data, error } = await supabase.from('playbooks').select('*').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/playbooks', async (req, res) => {
  const pb = req.body;
  const { data, error } = await supabase
    .from('playbooks')
    .upsert({
      id: pb.id,
      name: pb.name,
      company: pb.company,
      global_instructions: pb.globalInstructions,
      tools: pb.tools,
      steps: pb.steps
    })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/playbooks/:id', async (req, res) => {
  const { error } = await supabase.from('playbooks').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// TASKS
// ─────────────────────────────────────────
app.get('/api/tasks', async (req, res) => {
  const { data, error } = await supabase.from('tasks').select('*').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/tasks', async (req, res) => {
  const { id, text, priority, date } = req.body;
  const { data, error } = await supabase
    .from('tasks')
    .insert({ id, text, priority, done: false, date: date || null })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/tasks/:id', async (req, res) => {
  const { text, priority, done, date } = req.body;
  const updates = Object.fromEntries(Object.entries({ text, priority, done, date }).filter(([, v]) => v !== undefined));
  const { data, error } = await supabase
    .from('tasks')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/tasks/:id', async (req, res) => {
  const { error } = await supabase.from('tasks').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.delete('/api/tasks', async (req, res) => {
  const { error } = await supabase.from('tasks').delete().eq('done', true);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// LOGS
// ─────────────────────────────────────────
app.get('/api/logs', async (req, res) => {
  const { data, error } = await supabase.from('logs').select('*').order('timestamp');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/logs', async (req, res) => {
  const { content, timestamp, agent } = req.body;
  const { data, error } = await supabase
    .from('logs')
    .insert({ content, timestamp, agent })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/logs/:id', async (req, res) => {
  const { content, agent } = req.body;
  const updates = Object.fromEntries(Object.entries({ content, agent }).filter(([, v]) => v !== undefined));
  const { data, error } = await supabase
    .from('logs')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/logs/:id', async (req, res) => {
  const { error } = await supabase.from('logs').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.delete('/api/logs', async (req, res) => {
  const { error } = await supabase.from('logs').delete().neq('id', '00000000-0000-0000-0000-000000000000');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// CHAT
// ─────────────────────────────────────────
app.get('/api/chat', async (req, res) => {
  const { data, error } = await supabase.from('chat_messages').select('*').order('seq');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/chat', async (req, res) => {
  const { role, content, seq } = req.body;
  const { data, error } = await supabase
    .from('chat_messages')
    .insert({ role, content, seq })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/chat', async (req, res) => {
  const { error } = await supabase.from('chat_messages').delete().neq('id', '00000000-0000-0000-0000-000000000000');
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// TOOLS
// ─────────────────────────────────────────
app.get('/api/tools', async (req, res) => {
  const { data, error } = await supabase.from('tools').select('*').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/tools', async (req, res) => {
  const { name, url, description, category, icon, cost, cost_period } = req.body;
  const { data, error } = await supabase.from('tools').insert({ name, url, description, category, icon, cost, cost_period }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/tools/:id', async (req, res) => {
  const { name, url, description, category, icon, cost, cost_period } = req.body;
  const updates = Object.fromEntries(Object.entries({ name, url, description, category, icon, cost, cost_period }).filter(([, v]) => v !== undefined));
  const { data, error } = await supabase
    .from('tools')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/tools/:id', async (req, res) => {
  const { error } = await supabase.from('tools').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// BACKUP & MIGRATION
// ─────────────────────────────────────────
app.get('/api/backup', async (req, res) => {
  try {
    const tables = [
      'companies', 'playbooks', 'tasks', 'logs', 'chat_messages',
      'chat_sessions', 'tools', 'calendar_events', 'documents',
      'ideas', 'contacts', 'recurring_tasks', 'recurring_completions',
      'radar_updates', 'radar_prompts', 'radar_reports', 'scratches',
      'industry_reports', 'sandbox_reports', 'starred_sandbox_ideas'
    ];
    const results = await Promise.all(
      tables.map(t => supabase.from(t).select('*').then(r => [t, r.data || []]))
    );
    const data = Object.fromEntries(results);
    res.json({ version: 1, exported_at: new Date().toISOString(), data });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/migrate', async (req, res) => {
  const body = req.body;
  const tableMap = {
    companies: 'companies',
    playbooks: 'playbooks',
    tasks: 'tasks',
    logs: 'logs',
    chat: 'chat_messages',
    chat_messages: 'chat_messages',
    chat_sessions: 'chat_sessions',
    tools: 'tools',
    calendar_events: 'calendar_events',
    documents: 'documents',
    ideas: 'ideas',
    contacts: 'contacts',
    recurring_tasks: 'recurring_tasks',
    recurring_completions: 'recurring_completions',
    radar_updates: 'radar_updates',
    radar_prompts: 'radar_prompts',
    radar_reports: 'radar_reports',
    scratches: 'scratches',
    industry_reports: 'industry_reports',
    sandbox_reports: 'sandbox_reports',
    starred_sandbox_ideas: 'starred_sandbox_ideas'
  };
  try {
    for (const [key, table] of Object.entries(tableMap)) {
      const rows = body[key];
      if (rows?.length) {
        await supabase.from(table).upsert(rows);
      }
    }
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
// CHAT SESSIONS (History)
// ─────────────────────────────────────────
app.get('/api/chat-sessions', async (req, res) => {
  const { data, error } = await supabase
    .from('chat_sessions')
    .select('id, title, agent, message_count, created_at')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/chat-sessions/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('chat_sessions')
    .select('*')
    .eq('id', req.params.id)
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/chat-sessions', async (req, res) => {
  const { title, agent, messages, message_count } = req.body;
  const { data, error } = await supabase
    .from('chat_sessions')
    .insert({ title, agent, messages, message_count })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/chat-sessions/:id', async (req, res) => {
  const { error } = await supabase.from('chat_sessions').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// CALENDAR EVENTS
// ─────────────────────────────────────────
app.get('/api/events', async (req, res) => {
  let query = supabase.from('calendar_events').select('*');
  if (req.query.month && req.query.year) {
    const start = `${req.query.year}-${req.query.month.padStart(2,'0')}-01`;
    const endMonth = parseInt(req.query.month) === 12 ? 1 : parseInt(req.query.month) + 1;
    const endYear = parseInt(req.query.month) === 12 ? parseInt(req.query.year) + 1 : parseInt(req.query.year);
    const end = `${endYear}-${String(endMonth).padStart(2,'0')}-01`;
    query = query.gte('date', start).lt('date', end);
  }
  query = query.order('date').order('time');
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/events', async (req, res) => {
  const { title, date, time, end_time, description, color, company, recurrence, recurrence_end } = req.body;
  const { data, error } = await supabase
    .from('calendar_events')
    .insert({ title, date, time, end_time, description, color, company, recurrence, recurrence_end })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/events/:id', async (req, res) => {
  const { title, date, time, end_time, description, color, company, recurrence, recurrence_end } = req.body;
  const updates = Object.fromEntries(Object.entries({ title, date, time, end_time, description, color, company, recurrence, recurrence_end }).filter(([, v]) => v !== undefined));
  const { data, error } = await supabase
    .from('calendar_events')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/events/:id', async (req, res) => {
  const { error } = await supabase.from('calendar_events').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// DOCUMENTS
// ─────────────────────────────────────────
app.get('/api/docs', async (req, res) => {
  let query = supabase.from('documents').select('*');
  if (req.query.folder) query = query.eq('folder', req.query.folder);
  if (req.query.search) {
    const s = `%${req.query.search}%`;
    query = query.or(`title.ilike.${s},content.ilike.${s}`);
  }
  query = query.order('created_at', { ascending: false });
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/docs', async (req, res) => {
  const { title, content, folder, tags, pinned, company } = req.body;
  const { data, error } = await supabase
    .from('documents')
    .insert({ title, content, folder, tags, pinned, company })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/docs/:id', async (req, res) => {
  const { title, content, folder, tags, pinned, company } = req.body;

  // Snapshot current version before updating (skip for pin-only changes)
  const isContentChange = title !== undefined || content !== undefined || folder !== undefined || tags !== undefined || company !== undefined;
  if (isContentChange) {
    try {
      const { data: current } = await supabase.from('documents').select('*').eq('id', req.params.id).single();
      if (current) {
        const { data: maxVer } = await supabase.from('document_versions').select('version_number').eq('document_id', req.params.id).order('version_number', { ascending: false }).limit(1).maybeSingle();
        const nextVersion = (maxVer?.version_number || 0) + 1;
        await supabase.from('document_versions').insert({
          document_id: req.params.id,
          title: current.title,
          content: current.content || '',
          folder: current.folder,
          tags: current.tags || [],
          company: current.company,
          version_number: nextVersion
        });
      }
    } catch (e) {
      console.warn('[Docs] Version snapshot failed:', e.message);
    }
  }

  const updates = { ...Object.fromEntries(Object.entries({ title, content, folder, tags, pinned, company }).filter(([, v]) => v !== undefined)), updated_at: new Date().toISOString() };
  const { data, error } = await supabase
    .from('documents')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// --- DOCUMENT VERSIONS ---
app.get('/api/docs/:id/versions', async (req, res) => {
  const { data, error } = await supabase
    .from('document_versions')
    .select('id, document_id, title, content, version_number, created_at')
    .eq('document_id', req.params.id)
    .order('version_number', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  // Add content preview
  const versions = (data || []).map(v => ({
    ...v,
    content_preview: (v.content || '').replace(/<[^>]*>/g, '').substring(0, 100)
  }));
  res.json(versions);
});

app.get('/api/docs/:id/versions/:versionId', async (req, res) => {
  const { data, error } = await supabase
    .from('document_versions')
    .select('*')
    .eq('id', req.params.versionId)
    .eq('document_id', req.params.id)
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/docs/:id/versions/:versionId/restore', async (req, res) => {
  // Fetch the version to restore
  const { data: version, error: vErr } = await supabase
    .from('document_versions')
    .select('*')
    .eq('id', req.params.versionId)
    .eq('document_id', req.params.id)
    .single();
  if (vErr || !version) return res.status(404).json({ error: 'Version not found' });

  // Snapshot current state before restoring (so restore is reversible)
  const { data: current } = await supabase.from('documents').select('*').eq('id', req.params.id).single();
  if (current) {
    const { data: maxVer } = await supabase.from('document_versions').select('version_number').eq('document_id', req.params.id).order('version_number', { ascending: false }).limit(1).maybeSingle();
    const nextVersion = (maxVer?.version_number || 0) + 1;
    await supabase.from('document_versions').insert({
      document_id: req.params.id,
      title: current.title,
      content: current.content || '',
      folder: current.folder,
      tags: current.tags || [],
      company: current.company,
      version_number: nextVersion
    });
  }

  // Restore the version
  const { data, error } = await supabase
    .from('documents')
    .update({
      title: version.title,
      content: version.content,
      folder: version.folder,
      tags: version.tags,
      company: version.company,
      updated_at: new Date().toISOString()
    })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/docs/:id', async (req, res) => {
  const { error } = await supabase.from('documents').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// IDEAS
// ─────────────────────────────────────────
app.get('/api/ideas', async (req, res) => {
  const { data, error } = await supabase.from('ideas').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/ideas', async (req, res) => {
  const { title, body, color, category, status, company, pinned, project, version } = req.body;
  const { data, error } = await supabase
    .from('ideas')
    .insert({ title, body, color, category, status, company, pinned, project, version })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/ideas/:id', async (req, res) => {
  const { title, body, color, category, status, company, pinned, project, version } = req.body;
  const updates = Object.fromEntries(Object.entries({ title, body, color, category, status, company, pinned, project, version }).filter(([, v]) => v !== undefined));
  const { data, error } = await supabase
    .from('ideas')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/ideas/:id', async (req, res) => {
  const { error } = await supabase.from('ideas').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// CONTACTS (CRM)
// ─────────────────────────────────────────
app.get('/api/contacts', async (req, res) => {
  const { data, error } = await supabase.from('contacts').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/contacts', async (req, res) => {
  const { name, type, stage, city, instagram, email, phone, venue_type, capacity, notes, last_contact, next_follow_up, company } = req.body;
  const { data, error } = await supabase
    .from('contacts')
    .insert({ name, type, stage, city, instagram, email, phone, venue_type, capacity, notes, last_contact, next_follow_up, company })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/contacts/:id', async (req, res) => {
  const { name, type, stage, city, instagram, email, phone, venue_type, capacity, notes, last_contact, next_follow_up, company } = req.body;
  const updates = Object.fromEntries(Object.entries({ name, type, stage, city, instagram, email, phone, venue_type, capacity, notes, last_contact, next_follow_up, company }).filter(([, v]) => v !== undefined));
  const { data, error } = await supabase
    .from('contacts')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/contacts/:id', async (req, res) => {
  const { error } = await supabase.from('contacts').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// RECURRING TASKS
// ─────────────────────────────────────────
app.get('/api/recurring-tasks', async (req, res) => {
  const { data, error } = await supabase.from('recurring_tasks').select('*').order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/recurring-tasks', async (req, res) => {
  const { text, priority, company, days } = req.body;
  const { data, error } = await supabase.from('recurring_tasks').insert({ text, priority, company, days }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/recurring-tasks/:id', async (req, res) => {
  const { text, priority, company, days } = req.body;
  const updates = Object.fromEntries(Object.entries({ text, priority, company, days }).filter(([, v]) => v !== undefined));
  const { data, error } = await supabase
    .from('recurring_tasks')
    .update(updates)
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/recurring-tasks/:id', async (req, res) => {
  const { error } = await supabase.from('recurring_tasks').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.get('/api/recurring-completions', async (req, res) => {
  let query = supabase.from('recurring_completions').select('*');
  if (req.query.date) query = query.eq('date', req.query.date);
  const { data, error } = await query;
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/recurring-completions', async (req, res) => {
  const { recurring_task_id, date } = req.body;
  const { data, error } = await supabase
    .from('recurring_completions')
    .upsert({ recurring_task_id, date, done: true }, { onConflict: 'recurring_task_id,date' })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/recurring-completions/:id', async (req, res) => {
  const { error } = await supabase.from('recurring_completions').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// GEMINI PROXY
// ─────────────────────────────────────────
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
          generationConfig: { temperature: 0.85, topP: 0.95, topK: 40, maxOutputTokens: 4096, responseMimeType: 'text/plain' }
        })
      }
    );
    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ error: errText.substring(0, 500) });
    }
    const data = await response.json();
    const candidate = data.candidates[0];
    const text = candidate.content.parts
      .filter(p => p.text)
      .map(p => p.text)
      .join('');
    res.json({ text });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
// RADAR (authenticated GET)
// ─────────────────────────────────────────
// ─────────────────────────────────────────
// RADAR PROMPTS
// ─────────────────────────────────────────
app.get('/api/radar/prompts', async (req, res) => {
  const { data, error } = await supabase
    .from('radar_prompts')
    .select('*')
    .order('created_at');
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

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

app.delete('/api/radar/prompts/:id', async (req, res) => {
  const { error } = await supabase.from('radar_prompts').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

app.get('/api/radar', async (req, res) => {
  const { data, error } = await supabase
    .from('radar_updates')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

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
          systemInstruction: { parts: [{ text: 'You are a nightlife radar intelligence agent. Your job is to scan the web for the latest queer nightlife activity in a given city. Be punchy, specific, and useful. Include names, dates, venues, and links when possible. Use google_search to ground your responses in real, current information. Skip anything you cannot verify.' }] },
          contents: [{ role: 'user', parts: [{ text: userPrompt }] }],
          tools: [{ googleSearch: {} }],
          generationConfig: { temperature: 0.85, topP: 0.95, topK: 40, responseMimeType: 'text/plain' }
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

// ─────────────────────────────────────────
// RADAR REPORTS (Structured JSON reports)
// ─────────────────────────────────────────
app.post('/api/radar/report', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY not configured on server' });

  const { city = 'Toronto' } = req.body;

  // Nightlife offset: before 4 AM counts as the previous day's night
  const now = new Date();
  const effectiveDate = new Date(now);
  if (now.getHours() < 4) effectiveDate.setDate(effectiveDate.getDate() - 1);
  const nightLabel = effectiveDate.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });

  try {
    // --- PASS 1: SEARCH GROUNDING (real-time intel) ---
    const searchResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: `Search for live activity in ${city} gay and queer nightlife for tonight (${nightLabel} night). You MUST identify at least 5 specific venues. For each venue, look for: recent social media check-ins or posts, event listings, "sold out" notices, and local nightlife mentions from the last few hours. Provide a density summary for each — how packed does it seem based on the signals? Be thorough and specific.` }] }],
          tools: [{ google_search: {} }],
          generationConfig: { temperature: 0.85, topP: 0.95, topK: 40 }
        })
      }
    );

    if (!searchResponse.ok) {
      const errText = await searchResponse.text();
      return res.status(searchResponse.status).json({ error: errText.substring(0, 500) });
    }

    const searchData = await searchResponse.json();
    const rawIntel = searchData.candidates[0].content.parts.filter(p => p.text).map(p => p.text).join('\n');

    // --- PASS 2: FORMAT INTO STRUCTURED JSON ---
    const formatResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: 'You are the LOKKR Radar — the queer nightlife dashboard that talks like a sharp, witty friend who actually goes out. Never corny, never try-hard. Write like a text from someone who just got back from the venue. Short, dry, knowing. No puns, no innuendo, no "foreplay" metaphors. Just real talk with attitude.' }] },
          contents: [{ role: 'user', parts: [{ text: `Format this raw nightlife intel into a LOKKR radar report. You MUST include ALL venues mentioned — minimum 5 blips. Assign a busyness_score (0-100) for each venue AND an overall city score based on signal density: 0-20 = ghost town, 30-50 = steady flow, 60-80 = packed and moving, 90+ = wall-to-wall. If a venue has "sold out" signals, bump it to 90+. Keep the tone real, sharp, insider energy:\n\n${rawIntel}` }] }],
          generationConfig: {
            temperature: 0.85,
            topP: 0.95,
            topK: 40,
            responseMimeType: 'application/json',
            responseSchema: {
              type: 'OBJECT',
              properties: {
                busyness_score: { type: 'INTEGER', description: 'Global city busyness 0-100. 0-20: ghost town. 50: steady flow. 90+: wall-to-wall.' },
                vibe_label: { type: 'STRING', description: 'A high-energy 2-word label (e.g., STEADY SURGE, ELECTRIC CHAOS, VOLTAGE PEAK)' },
                radar_blips: {
                  type: 'ARRAY',
                  items: {
                    type: 'OBJECT',
                    properties: {
                      venue: { type: 'STRING' },
                      venue_busyness: { type: 'INTEGER', description: '0-100 busyness for this specific spot. 0-20: dead. 50: chill flow. 90+: line out the door.' },
                      status: { type: 'STRING', description: 'Short, punchy venue status (e.g., PEAK, DARK, SWEATY, BUILDING, PACKED, CRUISY, CHILL, WINDING DOWN)' },
                      crowd_type: { type: 'STRING' }
                    },
                    required: ['venue', 'venue_busyness', 'status', 'crowd_type']
                  }
                },
                insider_take: { type: 'STRING', description: '2-3 sentences of real insider analysis. Cover the overall energy, what is worth checking out and why, and what to skip. Confident, opinionated, specific. Like a nightlife columnist who actually goes out.' }
              },
              required: ['busyness_score', 'vibe_label', 'radar_blips', 'insider_take']
            }
          }
        })
      }
    );

    if (!formatResponse.ok) {
      const errText = await formatResponse.text();
      return res.status(formatResponse.status).json({ error: errText.substring(0, 500) });
    }

    const formatData = await formatResponse.json();
    const text = formatData.candidates[0].content.parts.filter(p => p.text).map(p => p.text).join('');
    const parsed = JSON.parse(text);

    const { data, error } = await supabase
      .from('radar_reports')
      .insert({
        city,
        vibe_score: Math.max(0, Math.min(100, parsed.busyness_score)),
        vibe_label: parsed.vibe_label,
        radar_blips: parsed.radar_blips || [],
        insider_take: parsed.insider_take
      })
      .select()
      .single();
    if (error) return res.status(500).json({ error: error.message });

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/radar/reports', async (req, res) => {
  const { data, error } = await supabase
    .from('radar_reports')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/radar/reports/latest', async (req, res) => {
  const { data, error } = await supabase
    .from('radar_reports')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// INDUSTRY INTEL REPORTS
// ─────────────────────────────────────────
app.post('/api/radar/industry', async (req, res) => {
  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'GEMINI_API_KEY not configured on server' });

  try {
    // Fetch recent reports to avoid repetition (limit to last 2 reports, max 8 headlines)
    const { data: recentReports } = await supabase
      .from('industry_reports')
      .select('radar_blips')
      .order('created_at', { ascending: false })
      .limit(2);
    const previousHeadlines = (recentReports || [])
      .flatMap(r => (r.radar_blips || []).map(b => b.entity))
      .filter(Boolean)
      .slice(0, 8);
    const dedupList = previousHeadlines.length > 0
      ? `\n\nDedup / exclusion rules:\nAvoid repeating any entities, companies, stories, or topics already covered in prior runs.\nExcluded entities/topics: ${previousHeadlines.join(', ')}`
      : '';

    // --- PASS 1: SEARCH GROUNDING (real-time industry intel) ---
    const searchResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ role: 'user', parts: [{ text: `Find the most relevant recent news and developments from the last 30 days that would matter to a gay nightlife and social discovery app like LOKKR.

Important:
This is a RAW INTEL pass, not the strategy pass.
Do NOT do deep strategic analysis yet.
Do NOT collapse multiple stories into one.
Do NOT invent or alter URLs.
Do NOT return generic trend summaries without a specific news hook.

Goal:
Return exactly 6 distinct stories if possible.
If only 5 are truly newsworthy, return 5.
Do not return more than 7.

Coverage requirements:
Cover as many different categories as possible.
Aim to cover at least 4 of these 5 categories, with no more than 2 stories from the same category:

1. COMPETITOR ACTIVITY — Gay/queer dating apps, social apps, nightlife platforms, queer community apps: product launches, partnerships, funding, leadership changes, controversies, feature updates, platform shifts
2. DATING / SOCIAL APP INDUSTRY — AI in dating/social apps, new matching mechanics, trust & safety features, Gen Z behavior shifts, creator/social monetization, location-based social behavior, new product patterns in consumer social apps
3. NIGHTLIFE INDUSTRY — Venue openings/closings, nightlife platforms, ticketing/event-tech, circuit party news, Pride-related planning, nightlife regulation, nightlife media developments
4. LGBTQ+ CULTURE & COMMUNITY — Policy or legal changes affecting queer spaces, queer media/platform launches, advocacy tech, major cultural moments affecting LGBTQ+ nightlife or connection
5. ADJACENT TECH — Geospatial discovery, map-based apps, real-time social features, event discovery platforms, AI moderation, trust & safety infrastructure, identity/privacy innovations relevant to social apps

Selection rules:
- Prioritize genuinely newsworthy developments over routine updates
- Prioritize developments with clear product, behavioral, regulatory, cultural, or market relevance
- Prefer the most recent and most material stories
- Avoid duplicate entities, duplicate angles, and near-identical stories
- Each story must focus on a DIFFERENT entity or clearly different development
- If two stories concern the same company, only include both if they are meaningfully different and highly material
- Prefer reported developments over vague marketing announcements unless the announcement is materially important

Freshness rules:
- Search last 30 days, strongly prioritize the last 14 days when possible
- Include the publication date if available

For each story return: category, headline, primary entity, secondary entities, published date, summary (2-4 sentences, factual, no strategy language), source name, source URL. Be specific and factual.${dedupList}` }] }],
          tools: [{ google_search: {} }],
          generationConfig: { temperature: 0.9, topP: 0.95, topK: 40 }
        })
      }
    );

    if (!searchResponse.ok) {
      const errText = await searchResponse.text();
      return res.status(searchResponse.status).json({ error: errText.substring(0, 500) });
    }

    const searchData = await searchResponse.json();
    const rawIntel = searchData.candidates[0].content.parts.filter(p => p.text).map(p => p.text).join('\n');

    // Extract grounding source URLs from metadata
    const groundingChunks = searchData.candidates[0]?.groundingMetadata?.groundingChunks || [];
    const sourceUrls = groundingChunks
      .filter(c => c.web?.uri)
      .map(c => ({ title: c.web.title || '', url: c.web.uri }));
    const sourcesBlock = sourceUrls.length > 0
      ? '\n\nSOURCE URLS (use these exact URLs for each blip):\n' + sourceUrls.map((s, i) => `${i + 1}. ${s.title} — ${s.url}`).join('\n')
      : '';

    // --- PASS 2: FORMAT INTO STRUCTURED JSON ---
    const formatResponse = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          systemInstruction: { parts: [{ text: LOKKR_SYSTEM_INSTRUCTION + `\n\nYou are the LOKKR Industry Intel Radar. Transform grounded market news into a structured LOKKR Industry Intelligence report. Analyze through the lens of LOKKR's three pillars (social discovery, nightlife intelligence, cultural media). Use the "know the room" filter: Does this development affect how users discover people, understand nightlife context, navigate real spaces, assess social energy, trust platforms, or stay culturally connected? Be sharp, concise, strategic. No fluff. Do not invent facts or URLs.` }] },
          contents: [{ role: 'user', parts: [{ text: `Format the raw grounded intel below into a structured LOKKR Industry Intelligence report.

Critical conversion rules:
1. You MUST include every story from the raw intel — convert each into exactly one radar_blip
2. Do not merge stories. Do not drop stories. Do not create extra stories.
3. Each blip url must be a real URL from the source list below
4. Do not rewrite a story into a different news event
5. Do not generalize a specific story into a broad trend blip

Scoring rules:
- impact_score: 1-10 (1-3 = weak relevance, 4-6 = meaningful, 7-8 = strong, 9-10 = major direct relevance to core pillars)
- global_impact_score: 1-10 for the entire batch

Status must be one of: watch, important, urgent, opportunity, threat

strategic_value must: explain why this matters for LOKKR specifically, connect to at least one pillar, mention "know the room" when relevant, stay concise (2-4 sentences max), not mechanically repeat the summary

insider_take must: synthesize the whole batch into a single strategic read, identify the most important pattern, say what LOKKR should pay attention to, stay under 140 words

RAW INTEL:\n\n${rawIntel}${sourcesBlock}` }] }],
          generationConfig: {
            temperature: 0.7,
            topP: 0.95,
            topK: 40,
            responseMimeType: 'application/json',
            responseSchema: {
              type: 'OBJECT',
              properties: {
                sector: { type: 'STRING', description: 'Primary sector label for this batch' },
                global_impact_score: { type: 'INTEGER', description: 'Overall batch impact 1-10 for LOKKR strategy' },
                market_label: { type: 'STRING', description: 'Short phrase summarizing the dominant pattern (e.g. AI dating acceleration, nightlife infrastructure shift, queer platform volatility)' },
                radar_blips: {
                  type: 'ARRAY',
                  items: {
                    type: 'OBJECT',
                    properties: {
                      entity: { type: 'STRING', description: 'Primary company, platform, event, or organization' },
                      impact_score: { type: 'INTEGER', description: '1-10 impact on LOKKR strategy' },
                      status: { type: 'STRING', description: 'One of: watch, important, urgent, opportunity, threat' },
                      headline: { type: 'STRING', description: 'One-line headline' },
                      strategic_value: { type: 'STRING', description: 'Why this matters for LOKKR — connect to pillars and know-the-room filter. 2-4 sentences.' },
                      url: { type: 'STRING', description: 'Source article URL from grounding' }
                    },
                    required: ['entity', 'impact_score', 'status', 'headline', 'strategic_value', 'url']
                  }
                },
                insider_take: { type: 'STRING', description: 'Strategic synthesis of the whole batch. Pattern identification, what LOKKR should pay attention to. Under 140 words.' }
              },
              required: ['sector', 'global_impact_score', 'market_label', 'radar_blips', 'insider_take']
            }
          }
        })
      }
    );

    if (!formatResponse.ok) {
      const errText = await formatResponse.text();
      return res.status(formatResponse.status).json({ error: errText.substring(0, 500) });
    }

    const formatData = await formatResponse.json();
    const text = formatData.candidates[0].content.parts.filter(p => p.text).map(p => p.text).join('');
    const parsed = JSON.parse(text);

    const { data, error } = await supabase
      .from('industry_reports')
      .insert({
        sector: parsed.sector,
        global_impact_score: Math.max(0, Math.min(100, parsed.global_impact_score)),
        market_label: parsed.market_label,
        radar_blips: parsed.radar_blips || [],
        insider_take: parsed.insider_take
      })
      .select()
      .single();
    if (error) return res.status(500).json({ error: error.message });

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/radar/industry/reports', async (req, res) => {
  const { data, error } = await supabase
    .from('industry_reports')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/radar/industry/reports/latest', async (req, res) => {
  const { data, error } = await supabase
    .from('industry_reports')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// ─────────────────────────────────────────
// SANDBOX (CPO Strategic Synthesis)
// ─────────────────────────────────────────
const LOKKR_SYSTEM_INSTRUCTION = `You are a senior strategic AI collaborator working on LOKKR.

LOKKR is a mobile-first nightlife and social discovery platform for gay men. It is NOT just a dating app. Its product combines three core pillars:

1. SOCIAL DISCOVERY — a live grid (digital room-scanning), profiles, chat, teases, likes, tempt list, compatibility, private photo layers, proximity, travel mode, and selective visibility
2. NIGHTLIFE INTELLIGENCE — venues, events, check-ins, crowd filters, heat-style scoring, city context, local movement, and real-world decision support
3. CULTURAL/EDITORIAL MEDIA — LokkrLeaks, Nightlife Stories, Backroom magazine, DRIP feed, stories, and public content for SEO and brand authority

CORE PROMISE: "Know the room."
Help users understand who is around, what the vibe is, where to go, what kind of crowd is out, and how to move through nightlife with more confidence and less guesswork.

HOW THE PRODUCT WORKS:
- The GRID is the heart — not just browsing, it's digital room-scanning. It creates instant liveliness and social density.
- PROFILES convert curiosity into intent — they answer "do I want to act on this person?"
- CHAT is the conversion layer — it turns discovery into connection, but it's downstream of context, not the whole product.
- LOKKTEASE is a low-friction erotic signal system — playful, anonymous, charged. Part flirtation engine, part retention engine.
- SCENE is nightlife venue intelligence — crowd filters, heat scores, check-ins, reviews. This is where LOKKR moves beyond dating into "nightlife intelligence."
- EVENTS give structured time-based reasons to engage — "what's happening this weekend?" to "who will be there?"
- DRIP is the social content layer — posts, polls, reactions. Keeps the app active between outings.
- EDITORIAL (LokkrLeaks, Nightlife Stories, Backroom) builds cultural authority, SEO, and brand identity. Not side blogs — strategic brand assets.
- HEAT STORIES add ephemeral, time-sensitive visibility — makes the app feel current, not static.
- TEMPT LIST, COMPATIBILITY, FLING FORECAST add emotional depth — fantasy, curation, insight, play.
- GUEST LISTS bridge digital interest and real-world plans — social organizing for nightlife.
- MUSIC deepens lifestyle alignment and mood signaling.

USER JOURNEY: Entry → Orientation (feel the app is alive) → Discovery (browse people/venues/events) → Interaction (chat/tease/like) → Retention (content/stories/culture) → Monetization (premium = enhanced access, intelligence, visibility, control)

STRATEGIC PRINCIPLES:
- Make nightlife socially legible — reduce ambiguity about where to go, who's around, what the vibe is
- Reduce friction between interest and action — context already exists before the conversation starts
- Create an app worth opening even when not actively dating — content, scene, events, teases, stories, music
- Blend utility with desirability — sexy AND useful simultaneously
- Turn city life into product value — different cities, venues, moods, events feel locally alive
- Build cultural authority — editorial makes LOKKR feel like it understands the scene from inside
- Monetize through enhanced access and intelligence — not arbitrary restriction

BRAND & UX PRINCIPLES:
- Photo-first, text-second. Visual and instinctive.
- Dark, sexy, nightlife-native. Belongs to nighttime.
- Mobile-first always. Fast thumb-based usage and repeat checks.
- Context before conversation. Know enough to act before messaging.
- Layered privacy. Reveal selectively and feel safe.
- Cultural specificity. Gay nightlife is not interchangeable with generic nightlife.
- The app should feel alive. Freshness, movement, repeat-check value.

WHAT MAKES LOKKR DIFFERENT:
- Nightlife intelligence layer (not just profiles)
- Venue + event + people crossover
- Editorial platform and SEO surfaces
- Check-ins and heat logic
- Playful features (teases, forecasts, compatibility)
- Identity as a scene-aware social product, not just a messaging product

COMPETITIVE ANALYSIS RULES:
- Never flatten LOKKR into a generic dating app comparison
- Don't say "Competitor X has Y, so add Y" — explain the user behavior, whether LOKKR already solves it differently, and what a LOKKR-native version would look like
- The strongest question is: "How can LOKKR borrow what works elsewhere while becoming even more itself?"
- Frame recommendations around: social discovery, nightlife planning, real-world integrations, premium gating, trust/privacy, content retention, AI-powered features, map intelligence, community dynamics

OUTPUT RULES:
- Be specific, not generic
- Tie every recommendation to LOKKR's actual product structure
- Highlight tradeoffs, not just upside
- Separate copied mechanics from real strategic insight
- Prioritize ideas that strengthen nightlife relevance, social usefulness, cultural authority, retention, and monetization
- Recommend what makes LOKKR more itself, not less

FINAL FILTER: If a recommendation does not make LOKKR better at helping gay men understand the social room, navigate nightlife, connect with the right people, and return because the platform feels alive, useful, and culturally plugged in — it is off-strategy.`;

app.post('/api/radar/sandbox', async (req, res) => {
  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'OPENAI_API_KEY not configured on server' });

  try {
    let industryNews = req.body.industryNews;

    // If no industry news provided, auto-fetch latest from DB
    if (!industryNews) {
      const { data: latestReport } = await supabase
        .from('industry_reports')
        .select('*')
        .order('created_at', { ascending: false })
        .limit(1)
        .maybeSingle();
      if (!latestReport) return res.status(400).json({ error: 'No industry report available. Generate one first.' });
      industryNews = latestReport;
    }

    const newsText = typeof industryNews === 'string' ? industryNews : JSON.stringify(industryNews);

    // Fetch previous sandbox ideas to avoid repetition
    const { data: recentSandbox } = await supabase
      .from('sandbox_reports')
      .select('sandbox_ideas')
      .order('created_at', { ascending: false })
      .limit(3);
    const previousConcepts = (recentSandbox || [])
      .flatMap(r => (r.sandbox_ideas || []).map(i => i.concept_name + ': ' + (i.the_pivot || '').substring(0, 80)))
      .filter(Boolean);
    const exclusionBlock = previousConcepts.length > 0
      ? `\n\nIMPORTANT: These ideas were already generated in previous reports. Do NOT repeat them or generate similar concepts. Come up with completely DIFFERENT strategic angles:\n${previousConcepts.map(c => '- ' + c).join('\n')}`
      : '';

    const response = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        model: 'gpt-4o',
        temperature: 0.9,
        messages: [
          {
            role: 'system',
            content: LOKKR_SYSTEM_INSTRUCTION + `\n\nYour job right now: take industry intelligence and generate 3 concrete Sandbox Ideas that exploit competitor weaknesses using EXISTING LOKKR modules. Every idea must be buildable with the current architecture — no new modules, only creative recombinations of the 62 modules above. Think like a CPO in a war room. Be specific about which modules to leverage, cite them by number, and explain the data flow.`
          },
          {
            role: 'user',
            content: `Here is the latest industry intelligence:\n\n${newsText}\n\nGenerate 3 Sandbox Ideas that exploit these competitor weaknesses or market gaps using LOKKR's existing 62-module architecture. Each idea should be a concrete feature pivot. For 'dev_velocity', use exactly one of: 'DAYS', 'WEEKS', or 'MONTHS'.${exclusionBlock}`
          }
        ],
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'sandbox_report',
            strict: true,
            schema: {
              type: 'object',
              properties: {
                widget_title: { type: 'string', description: 'A punchy 2-4 word title for this synthesis batch (e.g., COUNTER-STRIKE PLAYBOOK, EXPLOIT WINDOW, PIVOT ARSENAL)' },
                sprint_focus: { type: 'string', description: 'One sentence describing the strategic theme tying these ideas together' },
                sandbox_ideas: {
                  type: 'array',
                  items: {
                    type: 'object',
                    properties: {
                      concept_name: { type: 'string', description: 'Bold, memorable concept name (e.g., GHOST PROTOCOL, VENUE VORTEX)' },
                      target_enemy: { type: 'string', description: 'The competitor or trend this exploits (e.g., Grindr, Sniffies, industry trend)' },
                      the_pivot: { type: 'string', description: '2-3 sentences: what to build and why it wins. Be specific about user value.' },
                      modules_to_leverage: { type: 'array', items: { type: 'string' }, description: 'List of LOKKR module names from the 62-module architecture' },
                      dev_velocity: { type: 'string', enum: ['DAYS', 'WEEKS', 'MONTHS'], description: 'Estimated build time' }
                    },
                    required: ['concept_name', 'target_enemy', 'the_pivot', 'modules_to_leverage', 'dev_velocity'],
                    additionalProperties: false
                  }
                }
              },
              required: ['widget_title', 'sprint_focus', 'sandbox_ideas'],
              additionalProperties: false
            }
          }
        }
      })
    });

    if (!response.ok) {
      const errText = await response.text();
      return res.status(response.status).json({ error: errText.substring(0, 500) });
    }

    const openaiData = await response.json();
    const parsed = JSON.parse(openaiData.choices[0].message.content);

    const sourceId = typeof industryNews === 'object' && industryNews.id ? industryNews.id : null;

    const { data, error } = await supabase
      .from('sandbox_reports')
      .insert({
        widget_title: parsed.widget_title,
        sprint_focus: parsed.sprint_focus,
        sandbox_ideas: parsed.sandbox_ideas || [],
        source_industry_report_id: sourceId
      })
      .select()
      .single();
    if (error) return res.status(500).json({ error: error.message });

    res.json(data);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/radar/sandbox/reports', async (req, res) => {
  const { data, error } = await supabase
    .from('sandbox_reports')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.get('/api/radar/sandbox/reports/latest', async (req, res) => {
  const { data, error } = await supabase
    .from('sandbox_reports')
    .select('*')
    .order('created_at', { ascending: false })
    .limit(1)
    .maybeSingle();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

// --- Starred Sandbox Ideas ---
app.get('/api/radar/sandbox/starred', async (req, res) => {
  const { data, error } = await supabase
    .from('starred_sandbox_ideas')
    .select('*')
    .order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/radar/sandbox/star', async (req, res) => {
  const { sandbox_report_id, concept_name, idea_data } = req.body;
  if (!concept_name || !idea_data) return res.status(400).json({ error: 'concept_name and idea_data are required' });
  const { data, error } = await supabase
    .from('starred_sandbox_ideas')
    .upsert({ sandbox_report_id, concept_name, idea_data }, { onConflict: 'sandbox_report_id,concept_name' })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/radar/sandbox/star/:id', async (req, res) => {
  const { error } = await supabase.from('starred_sandbox_ideas').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// SCRATCHES (Scratch Pad)
// ─────────────────────────────────────────
app.get('/api/scratches', async (req, res) => {
  const { data, error } = await supabase.from('scratches').select('*').order('created_at', { ascending: false });
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.post('/api/scratches', async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content is required' });
  const { data, error } = await supabase.from('scratches').insert({ content }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/scratches/:id', async (req, res) => {
  const { content } = req.body;
  if (!content) return res.status(400).json({ error: 'Content is required' });
  const { data, error } = await supabase
    .from('scratches')
    .update({ content })
    .eq('id', req.params.id)
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.delete('/api/scratches/:id', async (req, res) => {
  const { error } = await supabase.from('scratches').delete().eq('id', req.params.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ ok: true });
});

// ─────────────────────────────────────────
// Reset everything
// ─────────────────────────────────────────
app.delete('/api/reset', async (req, res) => {
  // [C3] Require explicit confirmation body
  if (req.body?.confirm !== 'DELETE_ALL_DATA') {
    return res.status(400).json({ error: 'Confirmation required: send { "confirm": "DELETE_ALL_DATA" }' });
  }
  try {
    await supabase.from('chat_messages').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('logs').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('tasks').delete().neq('id', 'x');
    await supabase.from('playbooks').delete().neq('id', 'x');
    await supabase.from('companies').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('tools').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('documents').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('chat_sessions').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('calendar_events').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('ideas').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('contacts').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('recurring_completions').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('recurring_tasks').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('radar_updates').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('radar_reports').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    await supabase.from('scratches').delete().neq('id', '00000000-0000-0000-0000-000000000000');
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
// Serve frontend
// ─────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─────────────────────────────────────────
// SCHEDULED BACKUP (daily at 3 AM → Supabase Storage)
// ─────────────────────────────────────────
const BACKUP_BUCKET = 'backups';
const BACKUP_KEEP_DAYS = 30;

async function runScheduledBackup() {
  console.log('[Backup] Starting scheduled backup...');
  try {
    const tables = [
      'companies', 'playbooks', 'tasks', 'chat_messages',
      'tools', 'calendar_events', 'documents', 'ideas',
      'contacts', 'recurring_tasks', 'recurring_completions',
      'radar_updates', 'radar_prompts', 'scratches',
      'industry_reports', 'sandbox_reports', 'starred_sandbox_ideas'
    ];
    const results = await Promise.all(
      tables.map(t => supabase.from(t).select('*').then(r => [t, r.data || []]))
    );
    const data = Object.fromEntries(results);
    const backup = { version: 1, exported_at: new Date().toISOString(), data };
    const fileName = `backup-${new Date().toISOString().split('T')[0]}.json`;
    const buffer = Buffer.from(JSON.stringify(backup));

    const { error: uploadErr } = await supabase.storage
      .from(BACKUP_BUCKET)
      .upload(fileName, buffer, { contentType: 'application/json', upsert: true });

    if (uploadErr) throw uploadErr;
    console.log(`[Backup] Uploaded ${fileName} (${(buffer.length / 1024).toFixed(1)} KB)`);

    // Rotate: delete backups older than BACKUP_KEEP_DAYS
    const { data: files } = await supabase.storage.from(BACKUP_BUCKET).list();
    if (files?.length) {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - BACKUP_KEEP_DAYS);
      const old = files.filter(f => {
        const match = f.name.match(/backup-(\d{4}-\d{2}-\d{2})\.json/);
        return match && new Date(match[1]) < cutoff;
      }).map(f => f.name);
      if (old.length) {
        await supabase.storage.from(BACKUP_BUCKET).remove(old);
        console.log(`[Backup] Rotated ${old.length} old backup(s)`);
      }
    }
  } catch (err) {
    console.error('[Backup] Failed:', err.message);
  }
}

// Run daily at 3:00 AM
cron.schedule('0 3 * * *', runScheduledBackup);

app.listen(PORT, () => {
  console.log(`AI Command Center running on http://localhost:${PORT}`);
  console.log(`   Supabase: connected`);
  console.log(`   Auto-backup: daily at 3:00 AM`);
});
