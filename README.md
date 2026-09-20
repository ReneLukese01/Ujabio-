# App Ujabio

Ujabio is a single self-contained `index.html` file. This package wires the app up to a real backend instead:
**Supabase** for storage, **GitHub** to hold the code, and **Vercel** to host
it on the internet.

No build step, no framework, no `npm install`it's still just one HTML
file. 


## How the the app work

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
