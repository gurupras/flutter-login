class TokenResponse {
  final String accessToken;
  final int expiresIn;
  final String? idToken;
  final String? refreshToken;
  final String tokenType;
  final String userID;

  TokenResponse({
    required this.accessToken,
    required this.expiresIn,
    this.idToken,
    this.refreshToken,
    required this.tokenType,
    required this.userID,
  });

  factory TokenResponse.fromJson(Map<String, dynamic> json) {
    return TokenResponse(
      accessToken: json['access_token'] as String,
      expiresIn: json['expires_in'] as int,
      idToken: json['id_token'] as String?,
      refreshToken: json['refresh_token'] as String?,
      tokenType: json['token_type'] as String,
      userID: json['userId'] as String,
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
