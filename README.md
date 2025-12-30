# Liblogin

A comprehensive Flutter authentication library supporting FusionAuth, OAuth2, and native redirect handling.

## Features

- **FusionAuth Integration**: Seamless connection with FusionAuth for user management.
- **Social Login**: Support for Google Login via OAuth2.
- **Secure Storage**: Automatic token management and secure storage using `flutter_secure_storage`.
- **Auto-Refresh**: Background token refresh logic to keep users logged in.
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

## Troubleshooting

- **Redirect not working**: Ensure the `loginRedirectURI` in your `LoginConfig` matches the `scheme` and `host` configured in `AndroidManifest.xml` and `Info.plist` exactly.
- **Session expiry**: The library automatically schedules a token refresh 15 minutes before expiration. Ensure `AuthService.init()` is called on app start.