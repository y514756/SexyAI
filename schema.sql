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
  created_at timestamptz default now()
);

-- Disable RLS on all tables (single-operator app, server-side only access)
alter table companies disable row level security;
alter table playbooks disable row level security;
alter table tasks disable row level security;
alter table logs disable row level security;
alter table chat_messages disable row level security;
alter table tools disable row level security;
