-- ============================================================
-- Ujabio — Supabase schema (native Supabase Auth edition)
-- ============================================================
-- Run this whole file once in the SQL Editor
-- (Dashboard → SQL Editor → New query → paste → Run). It is safe to re-run.
--
-- WHAT CHANGED
--   * Sign-in is handled only by Supabase Auth (email + password).
--   * public.profiles holds each user's role. Only role = 'admin' can use
--     the app; the app signs everyone else straight back out.
--   * Row Level Security now evaluates the signed-in user's JWT
--     (role `authenticated`, auth.uid()). The old "anon full access"
--     policies are DROPPED: the public anon key alone can no longer read or
--     write family data.
--   * Each administrator can only reach the keys of their own family.
--   * Custom credential data (password hashes, salts, session tokens, reset
--     codes, throttle counters, invite codes) is purged from kv_store by
--     public.purge_legacy_credentials() — see the migration steps at the end.
--
-- ONE-TIME SETUP / MIGRATION: see section 7 at the bottom of this file.
-- ============================================================


-- ============================================================
-- 1. Key/value store used by the app
-- ============================================================
create table if not exists public.kv_store (
  key         text        not null,
  shared      boolean     not null default false,
  value       text,
  updated_at  timestamptz not null default now(),
  primary key (key, shared)
);

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

create index if not exists kv_store_key_idx on public.kv_store (key);


-- ============================================================
-- 2. Profiles: who is an admin, and of which family
-- ============================================================
create table if not exists public.profiles (
  id           uuid        primary key references auth.users (id) on delete cascade,
  email        text        not null,
  name         text        not null default '',
  role         text        not null default 'member' check (role in ('admin', 'member')),
  family_id    text,
  family_name  text,
  created_at   timestamptz not null default now()
);

alter table public.profiles enable row level security;

-- A signed-in user can read and delete ONLY their own profile row.
-- There is deliberately no INSERT or UPDATE policy for clients: nobody can
-- grant themselves the admin role from the browser. Roles are assigned by
-- public.provision_admin() / the SQL Editor (service role) only.
drop policy if exists "profiles read own" on public.profiles;
create policy "profiles read own"
  on public.profiles for select
  to authenticated
  using (id = auth.uid());

drop policy if exists "profiles delete own" on public.profiles;
create policy "profiles delete own"
  on public.profiles for delete
  to authenticated
  using (id = auth.uid());

revoke all on public.profiles from anon;
revoke insert, update on public.profiles from authenticated;

-- Every new Supabase Auth user gets a profile with the LEAST privileged
-- role. (The project's public sign-up endpoint can therefore never create an
-- admin.)
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, email, name, role)
  values (new.id, lower(new.email), coalesce(new.raw_user_meta_data ->> 'name', ''), 'member')
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();


-- ============================================================
-- 3. Helper functions used by the policies
--    (SECURITY DEFINER so they can read profiles / kv_store without
--     triggering recursive policy evaluation)
-- ============================================================
create or replace function public.is_admin()
returns boolean
language sql stable security definer
set search_path = public
as $$
  select exists (
    select 1 from public.profiles p
    where p.id = auth.uid() and p.role = 'admin'
  );
$$;

create or replace function public.my_family_id()
returns text
language sql stable security definer
set search_path = public
as $$
  select p.family_id from public.profiles p
  where p.id = auth.uid() and p.role = 'admin';
$$;

-- Is this e-mail listed in the family's memberEmails array?
create or replace function public.family_has_member(fid text, member_email text)
returns boolean
language sql stable security definer
set search_path = public
as $$
  select coalesce((
    select (f.value::jsonb -> 'memberEmails') ? lower(member_email)
    from public.kv_store f
    where f.shared and f.key = 'family:' || fid
  ), false);
$$;

grant execute on function public.is_admin()                        to authenticated;
grant execute on function public.my_family_id()                    to authenticated;
grant execute on function public.family_has_member(text, text)     to authenticated;


-- ============================================================
-- 4. Row Level Security for kv_store
-- ============================================================
alter table public.kv_store enable row level security;

-- Old, wide-open policy from the custom-login era: removed.
drop policy if exists "anon full access" on public.kv_store;

-- (a) Family data: a signed-in ADMIN may read/write only their own family's
--     keys, their own app-level user record, and the records of members
--     listed in their family. All of these are `shared = true` rows.
drop policy if exists "kv admin own family" on public.kv_store;
create policy "kv admin own family"
  on public.kv_store for all
  to authenticated
  using (
    shared
    and public.is_admin()
    and (
         key = 'family:' || public.my_family_id()
      or starts_with(key, 'family:' || public.my_family_id() || ':')
      or starts_with(key, 'chat:'   || public.my_family_id() || ':')
      or key = 'user:' || lower(coalesce(auth.jwt() ->> 'email', ''))
      or (starts_with(key, 'user:')
          and public.family_has_member(public.my_family_id(), substr(key, 6)))
    )
  )
  with check (
    shared
    and public.is_admin()
    and (
         key = 'family:' || public.my_family_id()
      or starts_with(key, 'family:' || public.my_family_id() || ':')
      or starts_with(key, 'chat:'   || public.my_family_id() || ':')
      or key = 'user:' || lower(coalesce(auth.jwt() ->> 'email', ''))
      or (starts_with(key, 'user:')
          and public.family_has_member(public.my_family_id(), substr(key, 6)))
    )
  );

-- (b) UI preferences (language, theme, sidebar, auto-lock): non-shared rows
--     whose key starts with "ui_". These are read on the login screen, before
--     anyone is signed in, so the anon role needs access to them — and only
--     to them.
drop policy if exists "kv ui preferences" on public.kv_store;
create policy "kv ui preferences"
  on public.kv_store for all
  to anon, authenticated
  using      (not shared and starts_with(key, 'ui_'))
  with check (not shared and starts_with(key, 'ui_'));


-- ============================================================
-- 5. Storage bucket for uploaded files
-- ============================================================
-- Files are stored under  <family_id>/<folder>/<file>  (the app builds the
-- path this way). The bucket stays public so existing file URLs keep working;
-- WRITING is limited to the signed-in administrator of that family.
insert into storage.buckets (id, name, public)
values ('family-files', 'family-files', true)
on conflict (id) do nothing;

drop policy if exists "anon read family-files"   on storage.objects;
drop policy if exists "anon upload family-files" on storage.objects;
drop policy if exists "anon update family-files" on storage.objects;
drop policy if exists "anon delete family-files" on storage.objects;

drop policy if exists "admin read family-files" on storage.objects;
create policy "admin read family-files"
  on storage.objects for select
  to authenticated
  using (
    bucket_id = 'family-files'
    and public.is_admin()
    and (storage.foldername(name))[1] = public.my_family_id()
  );

drop policy if exists "admin upload family-files" on storage.objects;
create policy "admin upload family-files"
  on storage.objects for insert
  to authenticated
  with check (
    bucket_id = 'family-files'
    and public.is_admin()
    and (storage.foldername(name))[1] = public.my_family_id()
  );

drop policy if exists "admin update family-files" on storage.objects;
create policy "admin update family-files"
  on storage.objects for update
  to authenticated
  using (
    bucket_id = 'family-files'
    and public.is_admin()
    and (storage.foldername(name))[1] = public.my_family_id()
  )
  with check (
    bucket_id = 'family-files'
    and public.is_admin()
    and (storage.foldername(name))[1] = public.my_family_id()
  );

drop policy if exists "admin delete family-files" on storage.objects;
create policy "admin delete family-files"
  on storage.objects for delete
  to authenticated
  using (
    bucket_id = 'family-files'
    and public.is_admin()
    and (storage.foldername(name))[1] = public.my_family_id()
  );


-- ============================================================
-- 6. Admin tooling (callable from the SQL Editor only)
-- ============================================================

-- Make an existing Supabase Auth user an administrator of a family.
-- Create the user first: Dashboard → Authentication → Users → Add user
-- (tick "Auto Confirm User"). Then:
--   select public.provision_admin('admin@example.com', 'Full Name', 'Kasongo');
-- Pass a fourth argument to attach the user to an existing family id.
create or replace function public.provision_admin(
  p_email        text,
  p_name         text,
  p_family_name  text,
  p_family_id    text default null
)
returns void
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  uid uuid;
  fid text;
begin
  select id into uid from auth.users where lower(email) = lower(p_email);
  if uid is null then
    raise exception 'No Supabase Auth user with email %. Create it first (Authentication → Users).', p_email;
  end if;

  fid := coalesce(
    p_family_id,
    (select family_id from public.profiles where id = uid),
    'fam_' || substr(md5(gen_random_uuid()::text), 1, 16)
  );

  insert into public.profiles (id, email, name, role, family_id, family_name)
  values (uid, lower(p_email), coalesce(p_name, ''), 'admin', fid, p_family_name)
  on conflict (id) do update
    set role        = 'admin',
        name        = excluded.name,
        family_id   = excluded.family_id,
        family_name = excluded.family_name;
end;
$$;

-- Migration helper: for every legacy administrator record in kv_store whose
-- e-mail now also exists in Supabase Auth, create the matching admin profile
-- (same family id, so all existing family data is kept). Returns the count.
create or replace function public.migrate_legacy_admins()
returns integer
language plpgsql
security definer
set search_path = public, auth
as $$
declare
  n integer;
begin
  -- The JSON casts live inside the CTEs, after the key filter, because
  -- kv_store also holds non-JSON values (e.g. old invite codes).
  with u as materialized (
    select key, value::jsonb as j
    from public.kv_store
    where shared and starts_with(key, 'user:')
  ),
  f as materialized (
    select key, value::jsonb as j
    from public.kv_store
    where shared and starts_with(key, 'family:')
  )
  insert into public.profiles (id, email, name, role, family_id, family_name)
  select au.id,
         lower(au.email),
         coalesce(u.j ->> 'name', ''),
         'admin',
         u.j ->> 'familyId',
         f.j ->> 'name'
  from auth.users au
  join u on u.key = 'user:' || lower(au.email)
  left join f on f.key = 'family:' || (u.j ->> 'familyId')
  where u.j ->> 'role' = 'admin'
    and u.j ->> 'familyId' is not null
  on conflict (id) do update
    set role        = 'admin',
        name        = excluded.name,
        family_id   = excluded.family_id,
        family_name = excluded.family_name;
  get diagnostics n = row_count;
  return n;
end;
$$;

-- Removes every trace of the old custom login system from kv_store:
-- password hashes, salts, session tokens, reset codes, brute-force counters
-- and invite codes. App data (permissions, photos, families) is untouched.
create or replace function public.purge_legacy_credentials()
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.kv_store
     set value = ((value::jsonb)
                  - 'passwordHash' - 'salt' - 'sessions'
                  - 'resetCode' - 'resetCodeExpires')::text
   where shared and starts_with(key, 'user:');

  delete from public.kv_store
   where shared and (starts_with(key, 'throttle:') or starts_with(key, 'invite:'));
end;
$$;

revoke all on function public.provision_admin(text, text, text, text) from public, anon, authenticated;
revoke all on function public.migrate_legacy_admins()                 from public, anon, authenticated;
revoke all on function public.purge_legacy_credentials()              from public, anon, authenticated;


-- ============================================================
-- 7. ONE-TIME SETUP  (run these by hand, after running the file above)
-- ============================================================
-- A) Existing installation (families already in kv_store):
--    1. Authentication → Users → "Add user" for each current family
--       administrator, using the SAME e-mail they used before, with a new
--       password ("Auto Confirm User" ticked).
--    2. Then run:
--         select public.migrate_legacy_admins();     -- links them to their families
--         select public.purge_legacy_credentials();  -- deletes old hashes/sessions
--
-- B) Brand-new installation:
--    1. Authentication → Users → "Add user" (Auto Confirm User ticked).
--    2. select public.provision_admin('you@example.com', 'Your Name', 'FamilyName');
--
-- C) Authentication → URL Configuration: set Site URL to your Vercel domain
--    and add  https://<your-domain>/  to Redirect URLs (needed for the
--    password-reset e-mail link).
--
-- D) Recommended: Authentication → Sign In / Providers → Email → turn OFF
--    "Allow new users to sign up" so nobody can create accounts through the
--    public endpoint (they could never become admins, but there is no reason
--    to allow it).
