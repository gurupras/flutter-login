import 'dart:math';
import 'dart:convert';
import 'dart:async';
import 'package:crypto/crypto.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:jwt_decoder/jwt_decoder.dart';
import 'package:http/http.dart' as http;
import 'package:liblogin_native/liblogin_native.dart';
import 'package:nanoid/nanoid.dart';
import 'package:logger/logger.dart';

import 'package:liblogin/src/auth_models.dart';
import 'package:liblogin/src/fusionauth_client.dart';
import 'package:liblogin/src/login_config.dart';

// Wrapper for JwtDecoder to allow mocking
class JwtDecoderWrapper {
  bool isExpired(String token) => JwtDecoder.isExpired(token);
  Map<String, dynamic> decode(String token) => JwtDecoder.decode(token);
}

class AuthService {
  final LoginConfig _config;
  final FlutterSecureStorage _secureStorage;
  late final FusionAuthClient _fusionAuthClient;
  final http.Client _httpClient;
  final JwtDecoderWrapper _jwtDecoder;

  static const String _deviceIDKey = 'deviceID';
  static const String _accessTokenKey = 'accessToken';
  static const String _refreshTokenKey = 'refreshToken';
  static const String _userIDKey = 'userID';

  final log = Logger(
    printer: PrefixPrinter(
      PrettyPrinter(),
      debug: '[liblogin:AuthService] D/',
      warning: '[liblogin:AuthService] W/',
      error: '[liblogin:AuthService] E/',
      info: '[liblogin:AuthService] I/',
      fatal: '[liblogin:AuthService] F/',
      trace: '[liblogin:AuthService] T/',
    ),
  );

  String? _currentAccessToken;
  String? _currentRefreshToken;
  String? _currentDeviceID;

  final StreamController<bool> _authRedirectController =
      StreamController<bool>.broadcast();
  Stream<bool> get authRedirectStream => _authRedirectController.stream;

  String? get currentAccessToken => _currentAccessToken;

  Timer? _refreshTokenTimer;
  bool _isRefreshing = false;

  AuthService({
    required LoginConfig config,
    FlutterSecureStorage? secureStorage,
    http.Client? httpClient,
    JwtDecoderWrapper? jwtDecoder,
    FusionAuthClient? fusionAuthClient, // Add this for injection
  })  : _config = config,
        _secureStorage = secureStorage ?? const FlutterSecureStorage(),
        _httpClient = httpClient ?? http.Client(),
        _jwtDecoder = jwtDecoder ?? JwtDecoderWrapper(),
        _fusionAuthClient = fusionAuthClient ??
            FusionAuthClient(
              config: config,
              httpClient: httpClient ?? http.Client(),
            ) {
    LibloginNative().setAuthRedirectHandler((url) => _handleAuthRedirect(url));
  }

  Future<void> _handleAuthRedirect(String urlString) async {
    log.i('Received handleAuthRedirect from native code with URL: $urlString');
    final Uri uri = Uri.parse(urlString);
    await _processAuthRedirect(uri);
  }

  Future<void> init() async {
    _currentDeviceID = await _secureStorage.read(key: _deviceIDKey);
    if (_currentDeviceID == null) {
      _currentDeviceID = nanoid();
      await _secureStorage.write(key: _deviceIDKey, value: _currentDeviceID);
    }
  }

  void dispose() {
    _authRedirectController.close();
    _refreshTokenTimer?.cancel();
  }

  Future<void> _processAuthRedirect(Uri uri) async {
    try {
      final String? code = uri.queryParameters['code'];
      if (code == null) {
        log.w('Authorization code not found in redirect URI');
        _authRedirectController.add(false);

        return;
      }

      final codeVerifier = await _secureStorage.read(key: 'code_verifier');
      final tokens = await _fusionAuthClient.exchangeAuthorizationCode(
        code,
        codeVerifier!,
      );
      await _storeTokens(tokens);
      log.i('Exchanged code for tokens and stored them successfully');
      _authRedirectController.add(true);
    } catch (e) {
      log.e('Failed to handle auth redirect: $e');
      _authRedirectController.add(false);
    }
  }

  Future<bool> login(String username, String password) async {
    try {
      final tokens = await _fusionAuthClient
          .resourceOwnerPasswordCredentialsGrant(username, password);
      await _storeTokens(tokens);

      return true;
    } catch (e) {
      log.e('Login failed: $e');
      return false;
    }
  }

  Future<bool> signUp(String username, String password) async {
    try {
      final response = await _httpClient.post(
        Uri.parse('${_config.signupOrigin}/login/signup'),
        headers: {'content-type': 'application/json'},
        body: json.encode({'email': username, 'password': password}),
      );

      if (response.statusCode == 200) {
        // After successful signup, attempt to log in to get tokens
        final bool loginSuccess = await login(username, password);
        if (!loginSuccess) {}
        return loginSuccess;
      } else {
        log.e('Sign up failed: ${response.body}');

        return false;
      }
    } catch (e) {
      log.e('Sign up failed: $e');
      return false;
    }
  }

  String? codeVerifier;

  Future<bool> initiateGoogleLogin() async {
    try {
      codeVerifier = AuthService.generateCodeVerifier();
      final codeChallenge = AuthService.generateCodeChallenge(codeVerifier!);
      await _secureStorage.write(
        key: 'code_verifier',
        value: codeVerifier,
      );

      final Uri authUri =
          Uri.parse('https://${_config.loginDomain}/oauth2/authorize').replace(
        queryParameters: {
          'client_id': _config.loginClientID,
          'redirect_uri': _config.loginRedirectURI,
          'response_type': 'code',
          'scope': 'openid email offline_access',
          'code_challenge': codeChallenge,
          'code_challenge_method': 'S256',
          'tenantId': _config.loginTenantID,
          'idp_hint': _config.googleIdentityProviderID,
        },
      );

      // Delegate the platform-specific login flow to the plugin
      final bool launched = await LibloginNative().login(
        authUri: authUri,
        redirectUri: _config.loginRedirectURI,
      );

      if (!launched) {
        log.w('Could not launch $authUri');
      }
      return launched;
    } catch (e) {
      log.e('Failed to initiate Google login: $e');
      return false;
    }
  }

  static String generateCodeVerifier() {
    final secureRandom = List<int>.generate(32, (i) => 0);
    final random = Random.secure();
    for (int i = 0; i < secureRandom.length; i++) {
      secureRandom[i] = random.nextInt(256);
    }
    return base64Url.encode(secureRandom).replaceAll('=', '');
  }

  static String generateCodeChallenge(String codeVerifier) {
    final sha256Digest = sha256.convert(utf8.encode(codeVerifier));
    return base64Url.encode(sha256Digest.bytes).replaceAll('=', '');
  }

  Future<bool> recoverPassword(String email) async {
    // This is a placeholder. Actual implementation would involve FusionAuth API for password recovery.
    log.i('Password recovery requested for: $email');
    await Future.delayed(const Duration(seconds: 1));
    return true;
  }

  Future<void> logout() async {
    await _secureStorage.delete(key: _accessTokenKey);
    await _secureStorage.delete(key: _refreshTokenKey);
    await _secureStorage.delete(key: _userIDKey);
    _currentAccessToken = null;
    _currentRefreshToken = null;
    _refreshTokenTimer?.cancel();
  }

  Future<void> _storeTokens(TokenResponse tokens) async {
    _currentAccessToken = tokens.accessToken;
    _currentRefreshToken = tokens.refreshToken;

    await _secureStorage.write(key: _accessTokenKey, value: tokens.accessToken);
    await _secureStorage.write(
      key: _refreshTokenKey,
      value: tokens.refreshToken,
    );
    await _secureStorage.write(key: _userIDKey, value: tokens.userID);

    _scheduleTokenRefresh();
  }

  void _scheduleTokenRefresh() {
    _refreshTokenTimer?.cancel();

    if (_currentAccessToken == null) {
      return;
    }

    try {
      final decodedToken = _jwtDecoder.decode(_currentAccessToken!);
      final exp = decodedToken['exp'] as int;
      final expirationDateTime = DateTime.fromMillisecondsSinceEpoch(
        exp * 1000,
      );
      final now = DateTime.now();

      final refreshTime = expirationDateTime.subtract(
        const Duration(minutes: 15),
      );
      final durationUntilRefresh = refreshTime.difference(now);

      if (durationUntilRefresh.isNegative) {
        log.i(
          'Access token already expired or close to expiration. Attempting immediate refresh.',
        );
        _attemptTokenRefresh();
      } else {
        log.i(
          'Scheduling token refresh in ${durationUntilRefresh.inMinutes} minutes.',
        );
        _refreshTokenTimer = Timer(durationUntilRefresh, () {
          log.i('Scheduled token refresh triggered.');
          _attemptTokenRefresh();
        });
      }
    } catch (e) {
      log.e('Error scheduling token refresh: $e');
    }
  }

  Future<void> _attemptTokenRefresh() async {
    if (_isRefreshing) {
      log.d('Refresh already in progress. Skipping.');
      return;
    }
    _isRefreshing = true;
    try {
      log.i('Attempting token refresh...');
      await checkLoginStatus();
    } finally {
      _isRefreshing = false;
    }
  }

  Future<bool> checkLoginStatus() async {
    _currentAccessToken = await _secureStorage.read(key: _accessTokenKey);
    _currentRefreshToken = await _secureStorage.read(key: _refreshTokenKey);
    await _secureStorage.read(key: _userIDKey);

    if (_currentAccessToken != null &&
        !_jwtDecoder.isExpired(_currentAccessToken!)) {
      // Token is valid and not expired

      _scheduleTokenRefresh();
      return true;
    } else if (_currentRefreshToken != null) {
      // Try to refresh the token
      try {
        final newTokens = await _fusionAuthClient.refreshTokenGrant(
          _currentRefreshToken!,
        );
        await _storeTokens(newTokens);

        return true;
      } catch (e) {
        log.e('Failed to refresh token: $e');
        await logout(); // Clear invalid tokens

        return false;
      }
    } else {
      return false;
    }
  }
}
