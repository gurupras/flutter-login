/// The kind of device a sign-in comes from, as FusionAuth's
/// `metaData.device.type` names it.
enum LoginDeviceType {
  mobile('MOBILE'),
  tablet('TABLET'),
  desktop('DESKTOP'),
  browser('BROWSER');

  const LoginDeviceType(this.wire);

  /// The value sent to the server.
  final String wire;
}

/// How a sign-in names the device it comes from, so a list of the account's
/// sessions can show "Pixel 8" instead of "Unknown device". Stored by
/// FusionAuth on the session's refresh token (`metaData.device`).
class LoginDevice {
  const LoginDevice({required this.name, required this.type});

  /// Shown to the person, e.g. "Pixel 8" or "Chrome on Windows".
  final String name;
  final LoginDeviceType type;

  Map<String, String> toJson() => {'name': name, 'type': type.wire};
}

class LoginConfig {
  final String loginDomain;
  final String signupOrigin;
  final String loginTenantID;
  final String loginClientID;
  final String loginRedirectURI;
  final String googleIdentityProviderID;

  /// FusionAuth IdP UUID for Apple Sign-In. When provided, the default login
  /// page renders an Apple button alongside Google. Optional — omit to hide
  /// Apple from the built-in providers list.
  final String? appleIdentityProviderID;

  /// iOS/macOS bundle identifier registered as the Apple "Configured
  /// application" on the FusionAuth Apple IdP. Sent as `data.redirect_uri`
  /// when completing native Apple Sign-In: Apple's token endpoint requires
  /// `redirect_uri` to match a registered client identifier, and for native
  /// flows that identifier is the bundle ID itself (Apple doesn't use a URL
  /// for native apps). Required when [appleIdentityProviderID] is set.
  final String? appleBundleID;

  /// OAuth **web** client ID that FusionAuth's Google Identity Provider is
  /// configured with. Passed to `google_sign_in` as its `serverClientId` so
  /// that the native `id_token` is issued with `aud` set to this web client ID
  /// instead of the platform (iOS/Android) client ID.
  ///
  /// This is the recommended way to make FusionAuth accept the native token:
  /// FusionAuth validates the token's `aud` against the client ID configured on
  /// its Google IdP (typically the web client). If you instead register the
  /// native client IDs directly on the FusionAuth Google IdP, you may leave
  /// this null. See the README "Native Google Sign-In" section.
  final String? googleServerClientId;

  /// iOS OAuth client ID for Google Sign-In. Optional — on iOS this is normally
  /// supplied via `Info.plist` (`GIDClientID` + the reversed-client-id URL
  /// scheme). Provide it here only if you prefer to configure the client ID
  /// programmatically rather than through the plist.
  final String? googleIosClientId;

  /// When true (the default), the built-in Google provider button uses the
  /// native `google_sign_in` flow ([AuthService.initiateGoogleNativeLogin]) on
  /// iOS/Android and transparently falls back to the web OAuth flow
  /// ([AuthService.initiateGoogleLogin]) on every other platform (web,
  /// desktop). Set to false to always use the web flow.
  final bool useNativeGoogle;

  final String? appID; // Optional, for device ID generation if needed

  /// Names this device on every sign-in (email, browser, native Google and
  /// Apple). Optional; null or a failure sends no device, which the server
  /// shows as an unknown device. Never called for a token refresh, which is
  /// not a sign-in and creates no session.
  final Future<LoginDevice?> Function()? describeDevice;

  LoginConfig({
    required this.loginDomain,
    required this.signupOrigin,
    required this.loginTenantID,
    required this.loginClientID,
    required this.loginRedirectURI,
    required this.googleIdentityProviderID,
    this.appleIdentityProviderID,
    this.appleBundleID,
    this.googleServerClientId,
    this.googleIosClientId,
    this.useNativeGoogle = true,
    this.appID,
    this.describeDevice,
  });
}
