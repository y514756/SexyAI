-- AI Command Center — Supabase Schema
-- Run this once in your Supabase SQL Editor

-- Enable UUID extension (usually already enabled)
create extension if not exists "pgcrypto";

-- Companies
create table if not exists companies (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  color text not null default '#6366F1',
  created_at timestamptz default now()
);

-- Playbooks
create table if not exists playbooks (
  id text primary key,  -- keep client-generated IDs (pb-1, pb-2...) for seed compatibility
  name text not null,
  company text not null,
  global_instructions text,
  tools jsonb default '[]',
  steps jsonb default '[]',
  created_at timestamptz default now()
);

-- Tasks (Agenda)
create table if not exists tasks (
  id text primary key,  -- client-generated timestamp string
  text text not null,
  priority text not null default 'normal',
  done boolean not null default false,
  created_at timestamptz default now()
);

-- Work Logs
create table if not exists logs (
  id uuid primary key default gen_random_uuid(),
  content text not null,
  timestamp bigint not null,
  created_at timestamptz default now()
);

-- Chat Messages
create table if not exists chat_messages (
  id uuid primary key default gen_random_uuid(),
  role text not null check (role in ('user', 'model')),
  content text not null,
  seq integer not null default 0,
  created_at timestamptz default now()
);

-- Tools
create table if not exists tools (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  url text not null,
  cost numeric,
  cost_period text, -- 'monthly', 'yearly', 'weekly', 'one-time'
  created_at timestamptz default now()
);

-- Radar Updates (nightlife intel from Make.com webhook)
create table if not exists radar_updates (
  id uuid primary key default gen_random_uuid(),
  city text not null default 'General',
  content text not null,
  created_at timestamptz default now()
);

-- Ideas / Product Board
create table if not exists ideas (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text,
  color text default '#6366F1',
  category text,
  status text default 'spark',
  company text,
  pinned boolean default false,
  project text,
  version text,
  created_at timestamptz default now()
);
alter table ideas disable row level security;

-- Radar Prompts (saved prompt library)
create table if not exists radar_prompts (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  text text not null,
  created_at timestamptz default now()
);

-- Radar Reports (structured nightlife reports from Gemini)
create table if not exists radar_reports (
  id uuid primary key default gen_random_uuid(),
  city text not null default 'General',
  vibe_score integer not null,
  vibe_label text not null,
  radar_blips jsonb default '[]',
  insider_take text not null,
  created_at timestamptz default now()
);

-- Industry Reports (structured industry intel from Gemini)
create table if not exists industry_reports (
  id uuid primary key default gen_random_uuid(),
  sector text,
  global_impact_score integer,
  market_label text,
  radar_blips jsonb default '[]',
  insider_take text,
  created_at timestamptz default now()
);
alter table industry_reports disable row level security;

-- Sandbox Reports (CPO strategic synthesis from industry intel)
CREATE TABLE IF NOT EXISTS sandbox_reports (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  widget_title text,
  sprint_focus text,
  sandbox_ideas jsonb DEFAULT '[]',
  source_industry_report_id uuid,
  created_at timestamptz DEFAULT now()
);
ALTER TABLE sandbox_reports DISABLE ROW LEVEL SECURITY;

-- Starred Sandbox Ideas (bookmarked CPO ideas)
CREATE TABLE IF NOT EXISTS starred_sandbox_ideas (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  sandbox_report_id uuid REFERENCES sandbox_reports(id) ON DELETE CASCADE,
  concept_name text NOT NULL,
  idea_data jsonb NOT NULL,
  created_at timestamptz DEFAULT now(),
  UNIQUE(sandbox_report_id, concept_name)
);
ALTER TABLE starred_sandbox_ideas DISABLE ROW LEVEL SECURITY;

-- Document Versions (edit history snapshots)
create table if not exists document_versions (
  id uuid primary key default gen_random_uuid(),
  document_id uuid not null references documents(id) on delete cascade,
  title text not null,
  content text not null,
  folder text,
  tags jsonb default '[]',
  company text,
  version_number integer not null default 1,
  created_at timestamptz default now()
);
alter table document_versions disable row level security;

-- Disable RLS on all tables (single-operator app, server-side only access)
alter table companies disable row level security;
alter table playbooks disable row level security;
alter table tasks disable row level security;
alter table logs disable row level security;
alter table chat_messages disable row level security;
alter table tools disable row level security;
alter table radar_updates disable row level security;
alter table radar_prompts disable row level security;
alter table radar_reports disable row level security;
