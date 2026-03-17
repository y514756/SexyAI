require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const { createClient } = require('@supabase/supabase-js');

const app = express();
const PORT = process.env.PORT || 3000;

// --- Supabase ---
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// --- Middleware ---
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.static(path.join(__dirname)));

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
  const { data, error } = await supabase.auth.refreshSession({ refresh_token });
  if (error || !data.session) return res.status(401).json({ error: 'Refresh failed' });
  res.json({ token: data.session.access_token, refresh_token: data.session.refresh_token });
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
  const { data, error } = await supabase
    .from('companies')
    .update(req.body)
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
  const { data, error } = await supabase
    .from('tasks')
    .update(req.body)
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
  const { data, error } = await supabase
    .from('logs')
    .update(req.body)
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
  const { name, url, description, category, icon } = req.body;
  const { data, error } = await supabase.from('tools').insert({ name, url, description, category, icon }).select().single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/tools/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('tools')
    .update(req.body)
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
// BULK MIGRATION
// ─────────────────────────────────────────
app.post('/api/migrate', async (req, res) => {
  const { companies, playbooks, tasks, logs, chat, tools } = req.body;
  try {
    if (companies?.length) await supabase.from('companies').upsert(companies.map(c => ({ name: c.name, color: c.color })));
    if (playbooks?.length) await supabase.from('playbooks').upsert(playbooks.map(pb => ({
      id: pb.id, name: pb.name, company: pb.company, global_instructions: pb.globalInstructions, tools: pb.tools, steps: pb.steps
    })));
    if (tasks?.length) await supabase.from('tasks').upsert(tasks.map(t => ({ id: t.id, text: t.text, priority: t.priority, done: t.done })));
    if (logs?.length) await supabase.from('logs').upsert(logs.map(l => ({ content: l.content, timestamp: l.timestamp })));
    if (chat?.length) await supabase.from('chat_messages').upsert(chat.map((m, i) => ({ role: m.role, content: m.content, seq: i })));
    if (tools?.length) await supabase.from('tools').upsert(tools.map(t => ({ name: t.name, url: t.url })));
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
  const { data, error } = await supabase
    .from('calendar_events')
    .update(req.body)
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
  const updates = { ...req.body, updated_at: new Date().toISOString() };
  const { data, error } = await supabase
    .from('documents')
    .update(updates)
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
  const { title, body, color, category, status, company, pinned } = req.body;
  const { data, error } = await supabase
    .from('ideas')
    .insert({ title, body, color, category, status, company, pinned })
    .select()
    .single();
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});

app.patch('/api/ideas/:id', async (req, res) => {
  const { data, error } = await supabase
    .from('ideas')
    .update(req.body)
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
  const { data, error } = await supabase
    .from('contacts')
    .update(req.body)
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
  const { data, error } = await supabase
    .from('recurring_tasks')
    .update(req.body)
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
// Reset everything
// ─────────────────────────────────────────
app.delete('/api/reset', async (req, res) => {
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
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────
// Serve frontend
// ─────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`AI Command Center running on http://localhost:${PORT}`);
  console.log(`   Supabase: ${process.env.SUPABASE_URL || 'SUPABASE_URL not set'}`);
});
