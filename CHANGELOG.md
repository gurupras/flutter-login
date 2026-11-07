## 0.20.0

Additive. `checkLoginStatus` and the default `AuthBloc` are unchanged.

- `restoreSession()`: loads the stored session with no network and deletes
  nothing. `AuthBloc(offlineFirst: true)` uses it for status checks.
- `refreshNow()`: a forced refresh shared by every entry point, limited to 20
  seconds, answering `RefreshOutcome`. Only `invalid_grant` from `/oauth2/token`
  counts as refused. `refreshOutcomes` and `lastRefreshOutcome` report it.
- The proactive refresh stops retrying on a refusal.
- A refresh that outlives a sign-in or log out stores nothing. A refresh naming
  another account is discarded.
- A sign-in replaces the whole token slot, so the old account's keys cannot
  survive under the new one.
- `cancelPendingSignIn()` drops a running attempt and a later browser redirect.
  The email form has a 20 second limit and no longer shows a raw cancel string.
- `LoginPage` gains `leading` and `savedEmail`.
- The default Google and Apple buttons are the same size. Both use
  flutter_login's row button, with the bundled Google logo and the Material
  Apple icon. `flutter_svg` is now a direct dependency.
- `beginSessionChange()` and `adoptStoredSessionIfChanged()` for apps that move
  tokens themselves or share storage between tabs.

## 0.19.1

* **New: `AuthService.currentEmail`.** The signed-in account's email, so an app
  can show who is signed in. The access token does not carry it under
  FusionAuth's Strict scope handling. It comes from the `user` that the
  password and native Apple or Google sign-ins return, or from the browser
  sign-in's id token `email` claim. It is kept in secure storage across
  restarts, survives refreshes, and is cleared on logout. `TokenResponse` gains
  `email` for the native sign-ins.
  A session signed in before 0.19.1 has no email until its next sign-in.

## 0.19.0

* **Fix: a failed sign-in now tells the user.** When the browser sign-in's code
  exchange failed, `AuthService` sent `false` and nothing reacted, so the user
  stayed on the login page with no message. `false` also stood for "the user
  cancelled", so no listener could tell a failure from a cancel.
* **Breaking:** every sign-in reports a `SignInResult`, one of
  `SignInSucceeded`, `SignInCancelled` or `SignInFailed(message)`. The message
  is always safe to show. The sign-in server's own wording passes through, for
  example "Invalid email or password". A network error says the server could
  not be reached. Anything else says "Couldn't sign in. Try again."
  * `authRedirectStream` (`Stream<bool>`) is replaced by `signInResults`. It
    carries every success, plus the failure or cancel of the browser flow,
    which has no caller to return to.
  * `login`, `signUp`, `initiateGoogleNativeLogin` and `initiateAppleLogin`
    return `Future<SignInResult>` and never throw. `recoverPassword` returns
    `Future<String?>`: null on success, otherwise the message to show.
  * `FusionAuthClient` throws `AuthServerException(statusCode, body)` instead
    of the bare body.
  * `AuthLogin`, `AuthSignUp`, `AuthRecoverPassword` and
    `AuthRecoverPasswordSuccess` are removed. A sign-in attempt is not a
    session event. A failed attempt used to emit `AuthError`, which an app
    reads as "signed out". Now `AuthBloc` changes state only when a sign-in
    succeeds.
* `LoginPage` shows email, phone Google and Apple failures in the login form's
  own error banner, and a failed browser sign-in in a snackbar. A cancel stays
  silent. It no longer snackbars `AuthError`, whose text was a raw exception.

## 0.18.2

* **Fix: background token refresh falls back to the server-side refresh.** A
  native-form login stores both a refresh token and `lastLoginCredentials`. The
  proactive refresh only tried FusionAuth's public refresh-token grant whenever
  a refresh token existed, and a confidential client rejects that grant with
  `invalid_client`. Every scheduled refresh and retry failed the same way, and
  the access token expired in place, so an app left open for about an hour
  started getting 401s. The proactive refresh now falls back to
  `/login/refresh-tokens` with `lastLoginCredentials`, as `checkLoginStatus`
  already did at startup. If both paths fail, the retry backoff still applies.

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
