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

-- ============================================================
-- Storage bucket for uploaded files (documents, event photos, profile
-- photos, chat attachments)
-- ============================================================
-- Earlier versions of this app embedded every uploaded file as base64
-- text directly inside the single JSON blob saved to kv_store. Once a
-- family had a few real documents, that blob could grow past what a
-- single database write accepts — the save would then fail silently in
-- the background (it still looked added, since the in-memory copy was
-- already updated), reappearing gone the next time someone signed back
-- in. The app now uploads file bytes here instead, in a dedicated
-- storage bucket, and only keeps a lightweight URL in the family's data.
-- Running this section is required for that fix to actually take effect
-- — without it, uploads silently fall back to the old (broken) behavior.

insert into storage.buckets (id, name, public)
values ('family-files', 'family-files', true)
on conflict (id) do nothing;

-- Same trust model as kv_store above (public anon key, no Supabase Auth):
-- anyone with the anon key can upload/read/delete inside this bucket.
drop policy if exists "anon read family-files" on storage.objects;
create policy "anon read family-files"
  on storage.objects for select
  to anon
  using (bucket_id = 'family-files');

drop policy if exists "anon upload family-files" on storage.objects;
create policy "anon upload family-files"
  on storage.objects for insert
  to anon
  with check (bucket_id = 'family-files');

drop policy if exists "anon update family-files" on storage.objects;
create policy "anon update family-files"
  on storage.objects for update
  to anon
  using (bucket_id = 'family-files');

drop policy if exists "anon delete family-files" on storage.objects;
create policy "anon delete family-files"
  on storage.objects for delete
  to anon
  using (bucket_id = 'family-files');

