/// The outcome of one sign-in attempt.
///
/// Cancelling and failing are separate on purpose: a cancel is the user's own
/// choice and stays silent, while a failure must tell the user something.
sealed class SignInResult {
  const SignInResult();
}

class SignInSucceeded extends SignInResult {
  const SignInSucceeded();
}

/// The user backed out (dismissed the provider sheet or the consent screen).
class SignInCancelled extends SignInResult {
  const SignInCancelled();
}

class SignInFailed extends SignInResult {
  /// Safe to show the user as-is. Never a raw exception or server payload.
  final String message;

  const SignInFailed(this.message);
}

/// A non-200 answer from the sign-in server or FusionAuth.
///
/// Carries the status code so callers can tell a rejected request (4xx) from
/// a server fault, which a bare body string could not.
class AuthServerException implements Exception {
  final int statusCode;
  final String body;

  AuthServerException(this.statusCode, this.body);

  @override
  String toString() => 'HTTP $statusCode: $body';
}

class TokenResponse {
  final String accessToken;
  final int expiresIn;
  final String? idToken;
  final String? refreshToken;
  final String tokenType;
  final String? userID;

  /// The account's email when the response names it (FusionAuth's
  /// identity-provider login returns it in `user`); null otherwise.
  final String? email;

  /// The server-side `/login/refresh-tokens` path ROTATES this credential on
  /// every call and returns the NEW one here. It MUST be persisted and used on
  /// the next refresh, or FusionAuth rejects the stale one with
  /// `refresh_token_not_found`. Null on the direct FusionAuth token endpoint
  /// (which uses a reusable refresh_token instead).
  final dynamic lastLoginCredentials;

  TokenResponse({
    required this.accessToken,
    required this.expiresIn,
    this.idToken,
    this.refreshToken,
    required this.tokenType,
    this.userID,
    this.email,
    this.lastLoginCredentials,
  });

  factory TokenResponse.fromJson(Map<String, dynamic> json) {
    return TokenResponse(
      accessToken: json['access_token'] as String,
      expiresIn: (json['expires_in'] as int?) ?? 0,
      idToken: json['id_token'] as String?,
      refreshToken: json['refresh_token'] as String?,
      tokenType: (json['token_type'] as String?) ?? 'Bearer',
      userID: json['userId'] as String?,
      lastLoginCredentials: json['lastLoginCredentials'],
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'access_token': accessToken,
      'expires_in': expiresIn,
      'id_token': idToken,
      'refresh_token': refreshToken,
      'token_type': tokenType,
      'userId': userID,
      'lastLoginCredentials': lastLoginCredentials,
    };
  }
}

class DecodedAccessToken {
  final String? aud;
  final int? exp;
  final int? iat;
  final String? iss;
  final String sub;
  final String? jti;
  final String? authenticationType;
  final String? applicationId;
  final List<String>? roles;
  final String? sid;
  final int? authTime;
  final String? tid;

  DecodedAccessToken({
    this.aud,
    this.exp,
    this.iat,
    this.iss,
    required this.sub,
    this.jti,
    this.authenticationType,
    this.applicationId,
    this.roles,
    this.sid,
    this.authTime,
    this.tid,
  });

  factory DecodedAccessToken.fromJson(Map<String, dynamic> json) {
    return DecodedAccessToken(
      aud: json['aud'] as String?,
      exp: json['exp'] as int?,
      iat: json['iat'] as int?,
      iss: json['iss'] as String?,
      sub: json['sub'] as String,
      jti: json['jti'] as String?,
      authenticationType: json['authenticationType'] as String?,
      applicationId: json['applicationId'] as String?,
      roles: (json['roles'] as List<dynamic>?)?.map((e) => e as String).toList(),
      sid: json['sid'] as String?,
      authTime: json['auth_time'] as int?,
      tid: json['tid'] as String?,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'aud': aud,
      'exp': exp,
      'iat': iat,
      'iss': iss,
      'sub': sub,
      'jti': jti,
      'authenticationType': authenticationType,
      'applicationId': applicationId,
      'roles': roles,
      'sid': sid,
      'auth_time': authTime,
      'tid': tid,
    };
  }
}

class LoginResponse {
  final String accessToken;
  final String? idToken;
  final String? refreshToken;
  final dynamic lastLoginCredentials;
  final Map<String, dynamic>? user;

  LoginResponse({
    required this.accessToken,
    this.idToken,
    this.refreshToken,
    this.lastLoginCredentials,
    this.user,
  });

  factory LoginResponse.fromJson(Map<String, dynamic> json) {
    return LoginResponse(
      accessToken: json['access_token'] as String,
      idToken: json['id_token'] as String?,
      refreshToken: json['refresh_token'] as String?,
      lastLoginCredentials: json['lastLoginCredentials'],
      user: json['user'] as Map<String, dynamic>?,
    );
  }

  Map<String, dynamic> toJson() {
    return {
      'access_token': accessToken,
      'id_token': idToken,
      'refresh_token': refreshToken,
      'lastLoginCredentials': lastLoginCredentials,
      'user': user,
    };
  }
}
