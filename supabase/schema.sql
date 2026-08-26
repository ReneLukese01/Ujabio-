-- ============================================================
-- Ujabio — Supabase schema
-- ============================================================
-- Run this once in your Supabase project's SQL Editor
-- (Dashboard → SQL Editor → New query → paste this whole file → Run).
--
-- The app talks to a single, simple key/value table. It was originally
-- built against Claude.ai's own artifact storage sandbox, which only
-- exposes get/set/delete on (key, shared) pairs — this table is a
-- drop-in replacement for that exact shape, so nothing in the app's own
-- logic had to change to run on a real backend.
--
-- Security note: this table's Row Level Security policy below allows the
-- public "anon" key to read and write freely. That mirrors this app's
-- existing security model (a private, trusted-family tool that does its
-- own client-side password hashing rather than using Supabase Auth), not
-- a hardened multi-tenant SaaS. If you need stronger guarantees later,
-- the natural next step is to move authentication to Supabase Auth and
-- rewrite these policies to check auth.uid() per family, but that is a
-- larger change than this schema alone.
-- ============================================================

create table if not exists public.kv_store (
  key         text        not null,
  shared      boolean     not null default false,
  value       text,
  updated_at  timestamptz not null default now(),
  primary key (key, shared)
);

-- Keep updated_at fresh on every write, useful for debugging/inspection.
create or replace function public.kv_store_set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_kv_store_updated_at on public.kv_store;
create trigger trg_kv_store_updated_at
  before update on public.kv_store
  for each row
  execute function public.kv_store_set_updated_at();

-- Row Level Security: enabled, with a permissive policy for the anon key
-- (see the security note above).
alter table public.kv_store enable row level security;

drop policy if exists "anon full access" on public.kv_store;
create policy "anon full access"
  on public.kv_store
  for all
  to anon
  using (true)
  with check (true);

-- Helpful for the /admin-style lookups the app does (e.g. "does this key
-- exist"), though the primary key above already covers most access paths.
create index if not exists kv_store_key_idx on public.kv_store (key);
