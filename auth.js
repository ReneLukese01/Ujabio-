/* ============================================================================
   js/auth.js — Supabase client, session handling and route guards
   ----------------------------------------------------------------------------
   Native Supabase Auth only. There is no custom login, no locally verified
   password and no home-made session token anywhere in the project.

   Load order in index.html (all deferred, so they run in this order, before
   DOMContentLoaded):
       1. supabase-js (UMD build, defines window.supabase)
       2. /js/auth.js                  <- this file (client + guards)
       3. /js/modules/auth-module.js   <- sign in / sign out / password flows

   The one Supabase client created here is shared with the rest of the app
   (storage engine, file uploads). After sign-in, supabase-js attaches the
   user's access token (JWT) to every request that client makes, so Postgres
   Row Level Security and Storage policies evaluate as the `authenticated`
   role with auth.uid() set. See schema.sql for the policies that rely on it.
   ========================================================================== */
(function (global) {
  'use strict';

  var SUPABASE_URL = 'https://wlngnkkujqsiwfetqfow.supabase.co';
  var SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Indsbmdua2t1anFzaXdmZXRxZm93Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3ODc5Mzc5NzgsImV4cCI6MjEwMzUxMzk3OH0.wNVr5vWq3fNR5UZpmh-xAfnR7sk3gJd2RZQMlAOn1BM';

  var ROOT_PATH = '/';
  var DASHBOARD_PATH = '/dashboard';

  /* true  -> stay signed in across browser restarts (localStorage)
     false -> signed out when the tab/window closes (sessionStorage); this
              matches the behaviour the app had before, so it stays the default. */
  var PERSIST_ACROSS_BROWSER_RESTARTS = false;

  /* Captured synchronously, before supabase-js consumes and clears the URL
     hash: lets the app know the page was opened from a password-recovery
     e-mail so it shows "choose a new password" instead of auto-entering. */
  var isRecoveryLink = /(^|[#&?])type=recovery(&|$)/.test(
    (global.location.hash || '') + '&' + (global.location.search || '')
  );

  function pickStorage() {
    try {
      var s = PERSIST_ACROSS_BROWSER_RESTARTS ? global.localStorage : global.sessionStorage;
      var probe = '__auth_probe__';
      s.setItem(probe, '1'); s.removeItem(probe);
      return s;
    } catch (e) { return undefined; } // supabase-js falls back to in-memory
  }

  /* Legacy custom-auth token from earlier versions of the app: always wipe it. */
  function purgeLegacyTokens() {
    try { global.sessionStorage.removeItem('session_token'); } catch (e) { /* ignore */ }
    try { global.localStorage.removeItem('session_token'); } catch (e) { /* ignore */ }
  }
  purgeLegacyTokens();

  var client = null;
  if (global.supabase && typeof global.supabase.createClient === 'function') {
    client = global.supabase.createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      auth: {
        persistSession: true,
        autoRefreshToken: true,
        detectSessionInUrl: true,
        flowType: 'implicit',
        storage: pickStorage(),
        storageKey: 'ujabio-auth'
      }
    });
  } else {
    console.error('[auth] supabase-js failed to load; sign-in is unavailable.');
  }

  /* ---------- helpers ---------- */

  async function getSession() {
    if (!client) return null;
    var res = await client.auth.getSession();
    return (res && !res.error && res.data) ? res.data.session : null;
  }

  /* Reads the caller's own row from public.profiles. RLS only ever returns
     the row whose id equals auth.uid(), and rejects an invalid/expired JWT,
     so this doubles as a server-side check of the token. */
  async function fetchProfile(userId) {
    var res = await client
      .from('profiles')
      .select('id,email,name,role,family_id,family_name')
      .eq('id', userId)
      .maybeSingle();
    if (res.error) throw res.error;
    return res.data || null;
  }

  /* Ends the Supabase session on this device and wipes anything left locally. */
  async function clearSession() {
    try { if (client) await client.auth.signOut({ scope: 'local' }); }
    catch (e) { /* the local session is dropped even if the call fails */ }
    purgeLegacyTokens();
  }

  /* Sends the browser to "/" (index.html). When we are already on "/" there is
     nothing to do (the login screen is showing), which also prevents a loop. */
  function redirectToLogin() {
    if (global.location.pathname !== ROOT_PATH) {
      global.location.replace(ROOT_PATH);
      return true;
    }
    return false;
  }

  /* The app is a single page: "/dashboard" is served by the same index.html
     (see the rewrite in vercel.json), so moving there is a history update. */
  function goToDashboard() {
    if (global.location.pathname !== DASHBOARD_PATH) {
      global.history.pushState({ view: 'dashboard' }, '', DASHBOARD_PATH);
    }
  }
  function leaveDashboard() {
    if (global.location.pathname !== ROOT_PATH) {
      global.history.replaceState(null, '', ROOT_PATH);
    }
  }

  /* ---------- guards ---------- */

  /* Resolves to the native Supabase session, or null after clearing local
     state and redirecting to "/" when nobody is signed in. */
  async function requireAuth() {
    var session = await getSession();
    if (!session) {
      await clearSession();
      redirectToLogin();
      return null;
    }
    return session;
  }

  /* Resolves to { session, profile } for a signed-in user whose
     public.profiles.role is 'admin'. In every other case (no session, no
     profile, role other than admin, lookup failure) the session is cleared and
     the browser is sent to "/" — the guard fails closed. */
  async function requireAdmin() {
    var session = await requireAuth();
    if (!session) return null;
    var profile = null;
    try { profile = await fetchProfile(session.user.id); }
    catch (e) { console.error('[auth] profile lookup failed:', e); }
    if (!profile || profile.role !== 'admin') {
      await clearSession();
      redirectToLogin();
      return null;
    }
    return { session: session, profile: profile };
  }

  /* Auth events (SIGNED_OUT, TOKEN_REFRESHED, PASSWORD_RECOVERY, ...).
     The callback is deferred a tick: supabase-js must not be re-entered from
     inside its own onAuthStateChange handler. */
  function onAuthChange(callback) {
    if (!client) return { unsubscribe: function () {} };
    var res = client.auth.onAuthStateChange(function (event, session) {
      setTimeout(function () { callback(event, session); }, 0);
    });
    return res.data.subscription;
  }

  var AppAuth = {
    client: client,
    ROOT_PATH: ROOT_PATH,
    DASHBOARD_PATH: DASHBOARD_PATH,
    isRecoveryLink: isRecoveryLink,
    getSession: getSession,
    fetchProfile: fetchProfile,
    clearSession: clearSession,
    redirectToLogin: redirectToLogin,
    goToDashboard: goToDashboard,
    leaveDashboard: leaveDashboard,
    requireAuth: requireAuth,
    requireAdmin: requireAdmin,
    onAuthChange: onAuthChange
  };

  global.AppAuth = AppAuth;
  global.requireAuth = requireAuth;
  global.requireAdmin = requireAdmin;
})(window);
