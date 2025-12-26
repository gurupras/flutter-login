class LoginConfig {
  final String loginDomain;
  final String signupOrigin;
  final String loginTenantID;
  final String loginClientID;
  final String loginRedirectURI;
  final String googleIdentityProviderID;
  final String? appID; // Optional, for device ID generation if needed

  LoginConfig({
    required this.loginDomain,
    required this.signupOrigin,
    required this.loginTenantID,
    required this.loginClientID,
    required this.loginRedirectURI,
    required this.googleIdentityProviderID,
    this.appID,
  });
}
