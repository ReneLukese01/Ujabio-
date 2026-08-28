# Deploying Ujabio (GitHub + Vercel + Supabase)

Ujabio is a single self-contained `index.html` file. It was originally built
to run inside Claude.ai's own artifact sandbox, which provides a special
`window.storage` API as its database. That API doesn't exist outside
Claude.ai, so this package wires the app up to a real backend instead:
**Supabase** for storage, **GitHub** to hold the code, and **Vercel** to host
it on the internet.

No build step, no framework, no `npm install` — it's still just one HTML
file. These three steps only take about 10–15 minutes.

---

## 1. Create the Supabase project and database table

1. Go to [supabase.com](https://supabase.com) and create a free account if
   you don't have one, then click **New project**.
2. Pick any project name and a database password (save the password
   somewhere safe — you generally won't need it again for this app, but
   Supabase asks for it).
3. Once the project has finished setting up, open **SQL Editor** in the
   left sidebar, click **New query**, paste in the entire contents of
   [`supabase/schema.sql`](./supabase/schema.sql) from this package, and
   click **Run**. This creates the one table the app needs
   (`kv_store`) and sets up its access policy.
4. Open **Project Settings → API** in the left sidebar. You'll need two
   values from this page in the next step:
   - **Project URL** (looks like `https://xxxxxxxxxxxx.supabase.co`)
   - **anon / public** key (a long string starting with `eyJ...`)

   The anon key is *meant* to be used in client-side code like this app —
   it only works within whatever the table's policy (from the SQL you just
   ran) allows it to do.

## 2. Connect the app to your Supabase project

1. Open `index.html` in any text editor.
2. Search for this block (near the top of the `<script>` section, look for
   `STORAGE ENGINE`):

   ```js
   const SUPABASE_URL = '';
   const SUPABASE_ANON_KEY = '';
   ```

3. Paste your two values from step 1.4 in between the quotes, for example:

   ```js
   const SUPABASE_URL = 'https://xxxxxxxxxxxx.supabase.co';
   const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...';
   ```

4. Save the file. That's the only code change needed — every feature in the
   app (accounts, families, chat, documents, notifications, activity log)
   already reads and writes through this same storage layer.

## 3. Put the code on GitHub

If you don't already have a repository for this project:

```bash
git init
git add index.html supabase/ README.md
git commit -m "Initial deploy: Ujabio"
```

Then create a new, empty repository on [github.com](https://github.com)
(**do not** initialize it with a README, since you already have one), and
push:

```bash
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
git branch -M main
git push -u origin main
```

## 4. Deploy on Vercel

1. Go to [vercel.com](https://vercel.com) and sign in (you can sign in
   directly with your GitHub account).
2. Click **Add New → Project**, then find and import the GitHub repository
   you just pushed.
3. Vercel will detect it as a static site — no framework, no build
   command, and no output directory need to be set. Just click **Deploy**.
4. After a few seconds you'll get a live URL like
   `https://your-repo-name.vercel.app`. That's it — the app is live.

Every time you `git push` a change to the `main` branch afterward, Vercel
redeploys automatically.

### Using your own domain (optional)

In the Vercel project, go to **Settings → Domains** and add your own
domain there, following Vercel's on-screen DNS instructions.

---

## Already deployed and just fixing the file-storage bug?

If you deployed earlier and documents/events were disappearing after
signing out, that was caused by uploaded files never having a real place
to live — the original `schema.sql` only created the database table, not
the file storage bucket the app actually needed. Both files in this
package now fix that. To apply the fix to an existing deployment:

1. Open your Supabase project → **SQL Editor → New query**, paste in the
   *entire* updated `supabase/schema.sql` (yes, even though you ran a
   version of it before — this one adds the missing storage bucket and
   is safe to re-run), and click **Run**.
2. Replace your repo's `index.html` with the updated one from this
   package, keeping your own `SUPABASE_URL`/`SUPABASE_ANON_KEY` values in
   place (search for `SUPABASE_URL` near the top of the script and copy
   your existing values across if you're not just editing in place).
3. Push to GitHub as normal — Vercel redeploys automatically.

Anything uploaded *before* this fix was never actually saved (that's the
bug), so there's nothing to migrate — new uploads from this point on will
persist correctly.

## What changed in the app to make this possible

Only one part of the code was touched: the storage engine. It now tries,
in order:

1. `window.storage` — automatically used if this page is ever opened back
   inside Claude.ai.
2. **Supabase** — used once you've filled in `SUPABASE_URL` and
   `SUPABASE_ANON_KEY` as above.
3. An in-memory fallback — only used if neither of the above is available
   (e.g. you open the file locally without filling in Supabase keys), so
   you can still click through the app, but nothing is saved after you
   close the tab.

No button, form, permission, or design was changed for this — every
feature works exactly as before, just now backed by a real database.

## A note on security

This app does its own client-side password hashing (PBKDF2-SHA256) rather
than using Supabase's built-in authentication system. That was a
reasonable trade-off for a private, trusted-family tool, but it means the
Supabase table's access policy is intentionally permissive (the public
anon key can read/write it), the same trust model the app already had
while running inside Claude.ai. Practically, this means:

- Don't put this on a public URL that strangers will stumble across if
  the data is meant to stay within your family.
- Anyone who obtains a specific record's key (a family ID or invite code)
  and knows how to query Supabase directly could read that record without
  logging in through the app's own UI.

If you need stronger guarantees, the natural next step is migrating to
Supabase Auth with row-level security policies scoped to `auth.uid()` per
family — that's a larger change than this deployment package covers, but
this current setup is a solid, working starting point that matches
exactly how the app already behaved.

## Backing up your data

Since your data now lives in Supabase instead of Claude.ai, back it up
from **Supabase Dashboard → Database → Backups**, or by exporting the
`kv_store` table periodically (Table Editor → kv_store → Export).
