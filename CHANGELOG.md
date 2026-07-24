## 0.15.0

* **Fix: refreshed access tokens now reach consumers.** `AuthService` refreshes
  the access token silently on a timer 15 min before expiry, but the new token
  never left the service — `AuthBloc` kept emitting the token it produced at
  login, so anything that cached it (API clients, socket auth) went on using a
  token that had since expired. Every authenticated request then failed with
  401 until the app was restarted. Long-lived sessions were the visible case:
  an app open for more than an hour would start failing all authenticated calls.
  * New `AuthService.accessTokenStream` — emits on every new access token
    (login, signup, IdP exchange, and background refresh), published from the
    single point all token writes pass through. **Consumers that cache the
    token should listen to this instead of reading `currentAccessToken` once.**
  * New `AuthTokenRefreshed` event; `AuthBloc` subscribes to
    `accessTokenStream` and re-emits `AuthAuthenticated` with the current
    token. No `AuthLoading` is emitted — a background refresh no longer bounces
    listeners through a loading state.
  * A background refresh no longer signals `authRedirectStream`. It is a silent
    refresh, not a completed redirect; routing it there made `AuthBloc` re-run
    `AuthCheckStatus` (with an `AuthLoading` transition and a redundant
    secure-storage round-trip) roughly once an hour. Redirect/IdP flows still
    signal it as before.
  * `AuthBloc.close()` now cancels its stream subscriptions (previously leaked).

## 0.14.0

* **Native Google Sign-In.** The built-in Google provider now uses the native
  `google_sign_in` account sheet on iOS/Android and posts the resulting
  `id_token` directly to FusionAuth's "Complete the Google Login" IdP endpoint
  (`POST /api/identity-provider/login`) — no browser hop. Falls back to the
  existing browser-OAuth flow (`initiateGoogleLogin()`) on web/desktop or when
  `useNativeGoogle` is false. Mirrors the existing native Apple flow.
  * New `AuthService.initiateGoogleNativeLogin()`.
  * New `GoogleSignInWrapper` (injectable, for testing).
  * New `FusionAuthClient.googleIdpLogin(...)`.
  * New `LoginConfig` fields: `googleServerClientId`, `googleIosClientId`,
    and `useNativeGoogle` (default `true`).
  * Pinned `google_sign_in: ^7.2.0` (v7 API).
  * See the README "Native Google Sign-In" section for the required consumer
    setup (Google Cloud Console client IDs, `Info.plist`, FusionAuth Google IdP
    audience) and the `id_token` audience gotcha.
* Added a Widgetbook app under `widgetbook/` for previewing `LoginPage`
  configurations.

## 0.0.1

* TODO: Describe initial release.
