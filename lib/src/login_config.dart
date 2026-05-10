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
  final String? appID; // Optional, for device ID generation if needed

  LoginConfig({
    required this.loginDomain,
    required this.signupOrigin,
    required this.loginTenantID,
    required this.loginClientID,
    required this.loginRedirectURI,
    required this.googleIdentityProviderID,
    this.appleIdentityProviderID,
    this.appID,
  });
}
