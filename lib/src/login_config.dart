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

  final String? appID; // Optional, for device ID generation if needed

  LoginConfig({
    required this.loginDomain,
    required this.signupOrigin,
    required this.loginTenantID,
    required this.loginClientID,
    required this.loginRedirectURI,
    required this.googleIdentityProviderID,
    this.appleIdentityProviderID,
    this.appleBundleID,
    this.appID,
  });
}
