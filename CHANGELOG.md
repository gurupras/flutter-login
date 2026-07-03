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
