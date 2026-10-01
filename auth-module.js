/* ============================================================================
   js/modules/auth-module.js — authentication actions (Supabase Auth only)
   ----------------------------------------------------------------------------
   Every credential check is performed by Supabase. This module never hashes,
   stores or compares a password itself.

   Depends on js/auth.js (window.AppAuth).
   ========================================================================== */
(function (global) {
  'use strict';

  var AppAuth = global.AppAuth;

  function unavailable() {
    var err = new Error('Authentication service unavailable.');
    err.code = 'unavailable';
    throw err;
  }

  if (!AppAuth || !AppAuth.client) {
    var stub = {};
    ['login', 'logout', 'verifyCurrentPassword', 'changePassword', 'signOutOtherDevices',
     'requestPasswordReset', 'completePasswordReset', 'deleteOwnProfile'].forEach(function (k) {
      stub[k] = function () { return Promise.reject(unavailable()); };
    });
    global.AuthModule = stub;
    return;
  }

  var supabase = AppAuth.client;

  /* Error codes the UI maps to translated messages:
       invalid_credentials | not_admin | rate_limited | weak_password | network | profile_error | unavailable */
  function authError(code, cause) {
    var err = new Error(code);
    err.code = code;
    err.cause = cause;
    return err;
  }

  function classify(error) {
    if (!error) return 'invalid_credentials';
    var status = error.status;
    var code = error.code || '';
    if (status === 429 || /rate_limit/.test(code)) return 'rate_limited';
    if (status === 422 || /same_password|weak_password/.test(code)) return 'weak_password';
    if (error.name === 'AuthRetryableFetchError' || status === 0 ||
        /failed to fetch|network/i.test(error.message || '')) return 'network';
    return 'invalid_credentials';
  }

  function normalizeEmail(email) { return String(email || '').trim().toLowerCase(); }

  /* Sign in, then require public.profiles.role === 'admin'.
     Anything else signs the user straight back out and throws. */
  async function login(email, password) {
    var res = await supabase.auth.signInWithPassword({
      email: normalizeEmail(email),
      password: password
    });
    var data = res.data, error = res.error;
    if (error || !data || !data.session) throw authError(classify(error), error);

    var profile = null;
    try {
      profile = await AppAuth.fetchProfile(data.user.id);
    } catch (e) {
      await AppAuth.clearSession();
      throw authError('profile_error', e);
    }
    if (!profile || profile.role !== 'admin') {
      await AppAuth.clearSession();
      throw authError('not_admin');
    }

    AppAuth.goToDashboard(); // -> /dashboard
    return { session: data.session, profile: profile };
  }

  async function logout() {
    await AppAuth.clearSession();
    AppAuth.leaveDashboard(); // -> /
  }

  /* Re-checks the signed-in admin's password (lock screen and the
     "type your password to confirm" dialogs) against Supabase. */
  async function verifyCurrentPassword(password) {
    var session = await AppAuth.getSession();
    if (!session || !password) return false;
    var res = await supabase.auth.signInWithPassword({
      email: session.user.email,
      password: password
    });
    return !res.error;
  }

  async function changePassword(currentPassword, newPassword) {
    if (!(await verifyCurrentPassword(currentPassword))) throw authError('invalid_credentials');
    var res = await supabase.auth.updateUser({ password: newPassword });
    if (res.error) throw authError(classify(res.error), res.error);
    // Same behaviour as before: a password change signs out every other device.
    await supabase.auth.signOut({ scope: 'others' });
  }

  async function signOutOtherDevices() {
    var res = await supabase.auth.signOut({ scope: 'others' });
    if (res.error) throw authError(classify(res.error), res.error);
  }

  /* Sends the standard Supabase recovery e-mail. Succeeds silently for unknown
     addresses so the form cannot be used to discover which e-mails exist. */
  async function requestPasswordReset(email) {
    var res = await supabase.auth.resetPasswordForEmail(normalizeEmail(email), {
      redirectTo: global.location.origin + AppAuth.ROOT_PATH
    });
    if (res.error) {
      var code = classify(res.error);
      if (code === 'rate_limited' || code === 'network') throw authError(code, res.error);
    }
  }

  /* Called while holding the temporary recovery session created by the e-mail link. */
  async function completePasswordReset(newPassword) {
    var res = await supabase.auth.updateUser({ password: newPassword });
    if (res.error) throw authError(classify(res.error), res.error);
    await logout(); // sign in again with the new password (and the admin check)
  }

  /* Removes the caller's own profile row (account deletion in the app). Without
     a profile the account can no longer pass the admin check. The auth user
     itself can only be deleted from the Supabase dashboard. */
  async function deleteOwnProfile() {
    var session = await AppAuth.getSession();
    if (!session) return;
    var res = await supabase.from('profiles').delete().eq('id', session.user.id);
    if (res.error) throw res.error;
  }

  global.AuthModule = {
    login: login,
    logout: logout,
    verifyCurrentPassword: verifyCurrentPassword,
    changePassword: changePassword,
    signOutOtherDevices: signOutOtherDevices,
    requestPasswordReset: requestPasswordReset,
    completePasswordReset: completePasswordReset,
    deleteOwnProfile: deleteOwnProfile
  };
})(window);
