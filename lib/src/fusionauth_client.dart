import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:liblogin/src/auth_models.dart';
import 'package:liblogin/src/login_config.dart';

class FusionAuthClient {
  final String domain;
  final String signupOrigin;
  final String clientID;
  final String tenantID;
  final String redirectUri;
  final http.Client _client;

  FusionAuthClient({required LoginConfig config, http.Client? httpClient})
    : domain = config.loginDomain,
      signupOrigin = config.signupOrigin,
      clientID = config.loginClientID,
      tenantID = config.loginTenantID,
      redirectUri = config.loginRedirectURI,
      _client = httpClient ?? http.Client();

  String get _origin => domain.contains('://') ? domain : 'https://$domain';

  String? _getCredentialsString(dynamic lastLoginCredentials) {
    if (lastLoginCredentials == null) {
      return null;
    }
    if (lastLoginCredentials is Map &&
        lastLoginCredentials.containsKey('data')) {
      return lastLoginCredentials['data'] as String?;
    }
    if (lastLoginCredentials is String) {
      return lastLoginCredentials;
    }
    return json.encode(lastLoginCredentials);
  }

  Future<LoginResponse> login({
    required String username,
    required String password,
    String? scope,
    Map<String, dynamic> device = const {},
    dynamic lastLoginCredentials,
    String? clientId,
  }) async {
    final body = {
      'username': username,
      'password': password,
      'clientID': clientId ?? clientID,
      if (scope != null) 'scope': scope,
      'device': device,
      if (lastLoginCredentials != null)
        'lastLoginCredentials': _getCredentialsString(lastLoginCredentials),
    };

    final result = await _client.post(
      Uri.parse('$signupOrigin/login/login'),
      headers: {'content-type': 'application/json'},
      body: json.encode(body),
    );

    if (result.statusCode == 200) {
      final response = json.decode(result.body);
      return LoginResponse.fromJson(response);
    } else {
      throw result.body;
    }
  }

  Future<TokenResponse> oauthRefreshTokenGrant(String refreshToken) async {
    final result = await _client.post(
      Uri.parse('$_origin/oauth2/token'),
      headers: {'content-type': 'application/x-www-form-urlencoded'},
      body: {
        'client_id': clientID,
        'grant_type': 'refresh_token',
        'refresh_token': refreshToken,
      },
    );

    if (result.statusCode == 200) {
      final response = json.decode(result.body);
      return TokenResponse.fromJson(response);
    } else {
      throw result.body;
    }
  }

  Future<TokenResponse> resourceOwnerPasswordCredentialsGrant(
    String username,
    String password,
  ) async {
    final result = await _client.post(
      Uri.parse('$_origin/oauth2/token'),
      headers: {'content-type': 'application/x-www-form-urlencoded'},
      body: {
        'client_id': clientID,
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid email offline_access',
      },
    );

    if (result.statusCode == 200) {
      final response = json.decode(result.body);
      return TokenResponse.fromJson(response);
    } else {
      throw result.body;
    }
  }

  Future<TokenResponse> refreshTokenGrant(
    dynamic lastLoginCredentials, {
    String? clientId,
  }) async {
    final body = {
      'lastLoginCredentials': _getCredentialsString(lastLoginCredentials),
      'clientID': clientId ?? clientID,
      'includeRefreshToken': true,
    };

    final result = await _client.post(
      Uri.parse('$signupOrigin/login/refresh-tokens'),
      headers: {'content-type': 'application/json'},
      body: json.encode(body),
    );

    if (result.statusCode == 200) {
      final response = json.decode(result.body);
      return TokenResponse.fromJson(response);
    } else {
      throw result.body;
    }
  }

  Future<TokenResponse> exchangeAuthorizationCode(
    String code,
    String codeVerifier,
  ) async {
    final result = await _client.post(
      Uri.parse('$_origin/oauth2/token'),
      headers: {'content-type': 'application/x-www-form-urlencoded'},
      body: {
        'client_id': clientID,
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': redirectUri,
        'code_verifier': codeVerifier,
      },
    );

    if (result.statusCode == 200) {
      final response = json.decode(result.body);
      return TokenResponse.fromJson(response);
    } else {
      throw result.body;
    }
  }
}
