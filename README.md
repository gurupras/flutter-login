# Liblogin

A comprehensive Flutter authentication library supporting FusionAuth, OAuth2, and native redirect handling.

## Features

- **FusionAuth Integration**: Seamless connection with FusionAuth for user management.
- **Social Login**: Native Google and Apple Sign-In on iOS/Android (on-device account sheet → FusionAuth IdP login API), with an automatic browser-OAuth fallback on web/desktop.
- **Secure Storage**: Automatic token management and secure storage using `flutter_secure_storage`.
- **Auto-Refresh**: Proactive background token refresh 15 minutes before expiry, using the standard OAuth2 refresh token grant. Works for all auth methods including Google OAuth.
- **Bloc-based Architecture**: Easy integration into Flutter apps using the BLoC pattern.
- **Cross-Platform**: Custom native implementations for Android and iOS to handle OAuth redirects.

## Getting started

Add the following to your `pubspec.yaml`:

```yaml
dependencies:
  liblogin:
    path: ../liblogin
  liblogin_native:
    path: ../liblogin_native
```

### Platform Setup

To handle the authentication redirect (e.g., after Google login), you must configure both platforms:

#### Android

1.  **Register Redirect Activity**: Add the `RedirectActivity` to your `android/app/src/main/AndroidManifest.xml` inside the `<application>` tag. 

    ```xml
    <activity
        android:name="me.gurupras.liblogin.RedirectActivity"
        android:exported="true">
        <intent-filter>
            <action android:name="android.intent.action.VIEW" />
            <category android:name="android.intent.category.DEFAULT" />
            <category android:name="android.intent.category.BROWSABLE" />
            <!-- Ensure scheme and host match your loginRedirectURI -->
            <data
                android:scheme="your.package.name"
                android:host="login-callback" />
        </intent-filter>
    </activity>
    ```

#### iOS

1.  **Configure URL Schemes**: In `ios/Runner/Info.plist`, add your custom URL scheme to allow the browser to redirect back to your app.

    ```xml
    <key>CFBundleURLTypes</key>
    <array>
        <dict>
            <key>CFBundleTypeRole</key>
            <string>Editor</string>
            <key>CFBundleURLName</key>
            <string>auth_callback</string>
            <key>CFBundleURLSchemes</key>
            <array>
                <string>your.package.name</string>
            </array>
        </dict>
    </array>
    ```

## Usage

### 1. Initialize Configuration

```dart
final config = LoginConfig(
  loginDomain: 'your-auth-domain.com',
  signupOrigin: 'https://your-api.com',
  loginTenantID: 'your-tenant-id',
  loginClientID: 'your-client-id',
  loginRedirectURI: 'your.package.name://login-callback',
  googleIdentityProviderID: 'google-idp-id',
  // Optional — provide to enable the built-in Apple button.
  appleIdentityProviderID: 'apple-idp-id',
  appleBundleID: 'your.bundle.id',
  // Optional — native Google Sign-In. See "Native Google Sign-In" below.
  // The FusionAuth-configured Google **web** client ID; makes the native
  // id_token's `aud` match what FusionAuth validates against.
  googleServerClientId: 'xxxx.apps.googleusercontent.com',
  // useNativeGoogle defaults to true (native on iOS/Android, web elsewhere).
);

final authService = AuthService(config: config);
await authService.init(); // Essential for generating/loading the device ID
```

### 2. Provide AuthBloc

Wrap your app or the login screen with `BlocProvider`:

```dart
BlocProvider(
  create: (context) => AuthBloc(authService: authService)..add(AuthCheckStatus()),
  child: MaterialApp(
    home: BlocBuilder<AuthBloc, AuthState>(
      builder: (context, state) {
        if (state is AuthAuthenticated) {
          return HomePage();
        }
        return LoginPage(title: 'Welcome');
      },
    ),
  ),
)
```

### 3. Using the Login Page

The library provides a pre-built `LoginPage` that integrates with `AuthBloc`:

```dart
LoginPage(title: 'My App Login')
```

By default this renders the email/password form plus a Google social button
(using the `googleIdentityProviderID` from your `LoginConfig`). If
`appleIdentityProviderID` is also set, an Apple button is rendered alongside it
using the official Apple-branded button style from `sign_in_button`.

#### Sign in with Apple

To enable the built-in Apple button:

1. **Configure FusionAuth.** Create an Apple Identity Provider in FusionAuth,
   upload the `.p8` key from your Apple Developer account, and register both
   your iOS app's bundle ID and your Services ID under "Configured
   applications". Note the IdP's UUID.
2. **Set `appleIdentityProviderID`** in your `LoginConfig` to that UUID.
3. **Re-use the existing redirect plumbing.** The Apple flow uses the same
   `loginRedirectURI` deep link as Google — no additional `AndroidManifest.xml`
   or `Info.plist` entries are required beyond what Google login already
   needs.

That's it. Tapping the Apple button calls
`AuthService.initiateAppleLogin()`, which forwards the configured Apple IdP
UUID as `idp_hint` to FusionAuth's `/oauth2/authorize` endpoint. FusionAuth
delegates to Apple, then redirects back to your app with an authorization code
that liblogin exchanges for tokens automatically.

If `appleIdentityProviderID` is null, the default providers list silently
omits the Apple button — there is no behavioural change for existing
consumers.

> **iOS App Store note.** Apple's App Store Review Guideline 4.8 requires
> apps that offer third-party social login to also offer Sign in with Apple
> using the **native** system sheet (not a Safari redirect). The redirect
> flow above works on every platform and is sufficient for Android, web, and
> non–App Store iOS distributions. For App Store submissions you may need
> to add a native iOS path on top of this redirect flow — file a follow-up
> if review requires it.

#### Native Google Sign-In

By default the built-in Google button now uses the **native** `google_sign_in`
account sheet on iOS/Android — the user picks a Google account on-device and
the resulting `id_token` is posted straight to FusionAuth's "Complete the
Google Login" IdP endpoint (`POST /api/identity-provider/login`). No browser
hop. On web/desktop (or when `useNativeGoogle: false`), it transparently falls
back to the existing browser OAuth flow (`initiateGoogleLogin()`), which is
left fully intact.

Tapping the Google button calls `AuthService.initiateGoogleNativeLogin()` on
mobile; you can also call it directly for a custom button.

**The audience gotcha (read this).** With `google_sign_in`, the `id_token.aud`
defaults to the platform (iOS/Android) OAuth client ID. FusionAuth validates
the token against the client ID configured on its Google IdP (typically the
**web** client). For FusionAuth to accept the native token you must make the
two agree — pick **one**:

- **(Recommended) Set `LoginConfig.googleServerClientId`** to FusionAuth's
  configured Google **web** client ID. liblogin passes it to `google_sign_in`
  as `serverClientId`, so the issued `id_token.aud` is that web client ID — the
  value FusionAuth expects. One field, done.
- **Or register the native client IDs on the FusionAuth Google IdP** as
  additional accepted client IDs, and leave `googleServerClientId` null.

New `LoginConfig` fields:

| Field | Required | Purpose |
| --- | --- | --- |
| `googleServerClientId` | Recommended | Google **web** client ID → `serverClientId` for `google_sign_in`, sets the native `id_token`'s `aud` to what FusionAuth validates. |
| `googleIosClientId` | Optional | iOS OAuth client ID → `clientId`. Usually supplied via `Info.plist` instead. |
| `useNativeGoogle` | Optional (default `true`) | `false` forces the web OAuth flow everywhere. |

##### Consumer integration steps (done outside this library)

These live in the downstream app and external consoles — liblogin can't do
them for you:

1. **Google Cloud Console.** Create an **iOS** OAuth client ID for your bundle
   (e.g. `xyz.twoseven.app.flutterRemoteControl`), and — if you use
   `googleServerClientId` — a **Web** OAuth client ID.
2. **iOS `Info.plist`.** Add the reversed iOS client ID under
   `CFBundleURLTypes` (the `com.googleusercontent.apps.…` URL scheme) and set
   `GIDClientID` to the iOS client ID (or pass client IDs to `GoogleSignIn`
   via `LoginConfig.googleIosClientId`). See the
   [`google_sign_in_ios` README](https://pub.dev/packages/google_sign_in_ios).
3. **Android.** No client-ID entry is needed in the manifest; Google matches
   the app by package name + SHA-1. Register your signing SHA-1 fingerprints on
   an **Android** OAuth client ID in the Cloud Console.
4. **FusionAuth Google IdP.** Ensure it accepts the native token's audience —
   either configure it with the web client ID that matches
   `googleServerClientId`, or add your native client IDs to its accepted client
   IDs. The IdP UUID is at *Settings → Identity Providers → Google →* (the UUID
   in the edit URL); set it as `googleIdentityProviderID`.
5. **`LoginConfig`.** Populate `googleServerClientId` (and optionally
   `googleIosClientId` / `useNativeGoogle`).

#### Configuring social providers

`LoginPage` exposes `LoginProvider` (re-exported from
[`flutter_login`](https://github.com/gurupras/flutter_login)) so you can supply
your own list of social buttons. When you provide `socialProviders`, the
built-in Google entry is replaced — include it explicitly if you still want it.

```dart
LoginPage(
  title: 'My App',
  socialProviders: [
    LoginProvider(
      icon: FontAwesome.google,
      label: 'Continue with Google',
      callback: () async {
        await context.read<AuthService>().initiateGoogleLogin();
        return null;
      },
    ),
    LoginProvider(
      button: Buttons.apple,
      label: 'Continue with Apple',
      callback: () async {
        await context.read<AuthService>().initiateAppleLogin();
        return null;
      },
    ),
  ],
)
```

#### Social-only login (no email/password)

Pass `enableEmailPassword: false` to hide the username/password form, leaving
only the configured social providers. `socialProviders` must be non-empty in
this mode (asserted at construction).

```dart
LoginPage(
  title: 'My App',
  enableEmailPassword: false,
  socialProviders: [
    LoginProvider(
      icon: FontAwesome.google,
      label: 'Continue with Google',
      callback: () async {
        await context.read<AuthService>().initiateGoogleLogin();
        return null;
      },
    ),
  ],
)
```

You can also pass `termsOfService: [...]` (`TermOfService` is re-exported from
this library); in social-only mode all entries render below the provider
buttons.

### 4. Accessing Token Data

When the user is authenticated, you can access the decoded fields of the access token (such as user ID, roles, etc.).

#### From AuthBloc

The `AuthAuthenticated` state includes a `decodedAccessToken` property:

```dart
if (state is AuthAuthenticated) {
  final userId = state.decodedAccessToken.sub;
  final roles = state.decodedAccessToken.roles;
  final email = state.decodedAccessToken.iss; // Depends on your provider configuration
}
```

#### From AuthService

You can also access the decoded token directly from the `AuthService`:

```dart
final decodedToken = authService.decodedAccessToken;
if (decodedToken != null) {
  print('Authenticated User ID: ${decodedToken.sub}');
}
```

### 5. Handling Background Token Refresh

When the background refresh timer fires (15 minutes before expiry), the library refreshes the token and emits a new `AuthAuthenticated` state on the bloc. If you pass the access token to an API client, update it whenever the state changes:

```dart
BlocListener<AuthBloc, AuthState>(
  listener: (context, state) {
    if (state is AuthAuthenticated) {
      apiClient.setToken(state.accessToken);
    }
  },
  child: ...,
)
```

## Troubleshooting

- **Redirect not working**: Ensure the `loginRedirectURI` in your `LoginConfig` matches the `scheme` and `host` configured in `AndroidManifest.xml` and `Info.plist` exactly.
- **Session expiry**: The library proactively refreshes tokens 15 minutes before expiry using the standard OAuth2 refresh token grant. This works for all login methods, including Google OAuth. Ensure `AuthService.init()` is called on app start so the device ID and stored credentials are loaded before the first `AuthCheckStatus` event.