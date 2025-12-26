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
