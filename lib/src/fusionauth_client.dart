import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:liblogin/src/auth_models.dart';
import 'package:liblogin/src/login_config.dart';

class FusionAuthClient {
  final String domain;
  final String clientID;
  final String tenantID;
  final String redirectUri;
  final http.Client _client;

  FusionAuthClient({required LoginConfig config, http.Client? httpClient})
    : domain = config.loginDomain,
      clientID = config.loginClientID,
      tenantID = config.loginTenantID,
      redirectUri = config.loginRedirectURI,
      _client = httpClient ?? http.Client();

  Future<TokenResponse> resourceOwnerPasswordCredentialsGrant(
    String username,
    String password,
  ) async {
    final result = await _client.post(
      Uri.parse('https://$domain/oauth2/token'),
      headers: {'content-type': 'application/x-www-form-urlencoded'},
      body: {
        'client_id': clientID,
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid offline_access',
      },
    );

    if (result.statusCode == 200) {
      final response = json.decode(result.body);
      return TokenResponse.fromJson(response);
    } else {
      throw result.body;
    }
  }

  Future<TokenResponse> refreshTokenGrant(String refreshToken) async {
    final body = {
      'client_id': clientID,
      'grant_type': 'refresh_token',
      'refresh_token': refreshToken,
    };

    final result = await _client.post(
      Uri.parse('https://$domain/oauth2/token'),
      headers: {'content-type': 'application/x-www-form-urlencoded'},
      body: body,
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
      Uri.parse('https://$domain/oauth2/token'),
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
