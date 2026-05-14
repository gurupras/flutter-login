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
import 'package:sign_in_with_apple/sign_in_with_apple.dart';

import 'package:liblogin/src/auth_models.dart';
import 'package:liblogin/src/fusionauth_client.dart';
import 'package:liblogin/src/login_config.dart';

// Wrapper for JwtDecoder to allow mocking
class JwtDecoderWrapper {
  bool isExpired(String token) => JwtDecoder.isExpired(token);
  Map<String, dynamic> decode(String token) => JwtDecoder.decode(token);
}

// Wrapper for SignInWithApple to allow mocking
class AppleSignInWrapper {
  Future<AuthorizationCredentialAppleID> getCredential() {
    return SignInWithApple.getAppleIDCredential(
      scopes: [
        AppleIDAuthorizationScopes.email,
        AppleIDAuthorizationScopes.fullName,
      ],
    );
  }
}

class AuthService {
  final LoginConfig _config;
  final FlutterSecureStorage _secureStorage;
  late final FusionAuthClient _fusionAuthClient;
  final http.Client _httpClient;
  final JwtDecoderWrapper _jwtDecoder;

  static const String _deviceIDKey = 'deviceID';
  static const String _accessTokenKey = 'accessToken';
  static const String _idTokenKey = 'idToken';
  static const String _refreshTokenKey = 'refreshToken';
  static const String _userIDKey = 'userID';
  static const String _lastLoginCredentialsKey = 'lastLoginCredentials';

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
  String? _currentIdToken;
  String? _currentRefreshToken;
  String? _currentDeviceID;
  dynamic _currentLastLoginCredentials;

  final StreamController<bool> _authRedirectController =
      StreamController<bool>.broadcast();
  Stream<bool> get authRedirectStream => _authRedirectController.stream;

  String? get currentAccessToken => _currentAccessToken;
  String? get currentIdToken => _currentIdToken;
  dynamic get lastLoginCredentials => _currentLastLoginCredentials;

  /// Read-only access to the [LoginConfig] used to construct this service.
  /// Useful for widgets that need to introspect optional provider IDs without
  /// duplicating config plumbing.
  LoginConfig get config => _config;

  DecodedAccessToken? get decodedAccessToken {
    if (_currentAccessToken == null) {
      return null;
    }
    return DecodedAccessToken.fromJson(
      _jwtDecoder.decode(_currentAccessToken!),
    );
  }

  Timer? _refreshTokenTimer;
  bool _isRefreshing = false;

  final LibloginNative _libloginNative;
  final AppleSignInWrapper _appleSignIn;

  AuthService({
    required LoginConfig config,
    FlutterSecureStorage? secureStorage,
    http.Client? httpClient,
    JwtDecoderWrapper? jwtDecoder,
    FusionAuthClient? fusionAuthClient,
    LibloginNative? libloginNative,
    AppleSignInWrapper? appleSignIn,
  }) : _config = config,
       _secureStorage = secureStorage ?? const FlutterSecureStorage(),
       _httpClient = httpClient ?? http.Client(),
       _jwtDecoder = jwtDecoder ?? JwtDecoderWrapper(),
       _fusionAuthClient =
           fusionAuthClient ??
           FusionAuthClient(
             config: config,
             httpClient: httpClient ?? http.Client(),
           ),
       _libloginNative = libloginNative ?? LibloginNative(),
       _appleSignIn = appleSignIn ?? AppleSignInWrapper() {
    log.i('[AuthService] constructor: registering auth redirect handler');
    _libloginNative.setAuthRedirectHandler((url) => _handleAuthRedirect(url));
  }

  Future<void> _handleAuthRedirect(String urlString) async {
    log.i('[AuthService] _handleAuthRedirect called with URL: $urlString');
    final Uri uri = Uri.parse(urlString);
    await _processAuthRedirect(uri);
  }

  Future<void> init() async {
    _currentDeviceID = await _secureStorage.read(key: _deviceIDKey);
    if (_currentDeviceID == null) {
      _currentDeviceID = nanoid();
      await _secureStorage.write(key: _deviceIDKey, value: _currentDeviceID);
    }
    _currentIdToken = await _secureStorage.read(key: _idTokenKey);
    _currentLastLoginCredentials = await _secureStorage.read(
      key: _lastLoginCredentialsKey,
    );
    if (_currentLastLoginCredentials != null) {
      try {
        _currentLastLoginCredentials = json.decode(
          _currentLastLoginCredentials,
        );
      } catch (e) {
        // Not JSON, keep as string
      }
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
      final response = await _fusionAuthClient.login(
        username: username,
        password: password,
        scope: 'openid email offline_access',
        lastLoginCredentials: _currentLastLoginCredentials,
      );
      await _storeLoginResponse(response);

      return true;
    } catch (e, stackTrace) {
      log.e('Login failed', error: e, stackTrace: stackTrace);
      String? message;
      try {
        final body = json.decode(e.toString());
        if (body is Map && body.containsKey('message')) {
          message = body['message'];
        }
      } catch (_) {
        // Fallback to raw error string if not JSON or doesn't have message
      }
      if (message != null) {
        throw message;
      }
      rethrow;
    }
  }

  Future<bool> signUp(String username, String password) async {
    try {
      final response = await _httpClient.post(
        Uri.parse('${_config.signupOrigin}/login/register'),
        headers: {'content-type': 'application/json'},
        body: json.encode({
          'email': username,
          'password': password,
          'clientID': _config.loginClientID,
        }),
      );

      if (response.statusCode == 200) {
        // After successful signup, attempt to log in to get tokens
        try {
          final bool loginSuccess = await login(username, password);
          return loginSuccess;
        } catch (loginError) {
          String? message;
          try {
            final body = json.decode(response.body);
            if (body is Map && body.containsKey('message')) {
              message = body['message'];
            }
          } catch (e) {
            // Ignore decoding errors
          }
          if (message != null) {
            throw message;
          }
          rethrow;
        }
      } else {
        log.e('Sign up failed: ${response.body}');
        try {
          final body = json.decode(response.body);
          if (body is Map && body.containsKey('message')) {
            throw body['message'];
          }
        } catch (_) {
          // If registration body doesn't have a message, throw the raw body
          throw response.body;
        }
        return false;
      }
    } catch (e, stackTrace) {
      log.e('Sign up failed', error: e, stackTrace: stackTrace);
      rethrow;
    }
  }

  String? codeVerifier;

  Future<bool> initiateGoogleLogin() {
    return _initiateSocialLogin(
      idpHint: _config.googleIdentityProviderID,
      providerLabel: 'Google',
    );
  }

  /// Initiates native Sign in with Apple using [AppleSignInWrapper], then
  /// exchanges the resulting identity token with FusionAuth's IdP login API.
  ///
  /// Throws a [StateError] if [LoginConfig.appleIdentityProviderID] is not set.
  Future<bool> initiateAppleLogin() async {
    final appleIdpID = _config.appleIdentityProviderID;
    if (appleIdpID == null) {
      throw StateError(
        'appleIdentityProviderID is not configured on LoginConfig. '
        'Set it before calling initiateAppleLogin().',
      );
    }
    final appleBundleID = _config.appleBundleID;
    if (appleBundleID == null) {
      throw StateError(
        'appleBundleID is not configured on LoginConfig. '
        'Set it (typically the iOS/macOS bundle identifier) before calling '
        'initiateAppleLogin().',
      );
    }
    try {
      final credential = await _appleSignIn.getCredential();
      final identityToken = credential.identityToken;
      if (identityToken == null) {
        log.w('Apple sign in returned null identity token');
        return false;
      }
      try {
        final claims = _jwtDecoder.decode(identityToken);
        log.i(
          'Apple id_token claims: aud=${claims['aud']} iss=${claims['iss']} '
          'sub=${claims['sub']} email=${claims['email']} '
          'iat=${claims['iat']} exp=${claims['exp']}',
        );
      } catch (e) {
        log.w('Could not decode Apple id_token for diagnostics: $e');
      }
      log.i(
        'Sending to FusionAuth appleIdpLogin: '
        'identityProviderId=$appleIdpID redirectUri=$appleBundleID',
      );
      final tokens = await _fusionAuthClient.appleIdpLogin(
        identityToken: identityToken,
        authorizationCode: credential.authorizationCode,
        identityProviderId: appleIdpID,
        redirectUri: appleBundleID,
      );
      await _storeTokens(tokens);
      _authRedirectController.add(true);
      return true;
    } on SignInWithAppleAuthorizationException catch (e) {
      if (e.code == AuthorizationErrorCode.canceled) {
        log.i('Apple sign in cancelled by user');
        return false;
      }
      log.e('Apple sign in failed: ${e.message}');
      _authRedirectController.add(false);
      return false;
    } catch (e, stackTrace) {
      log.e('Apple sign in failed', error: e, stackTrace: stackTrace);
      _authRedirectController.add(false);
      return false;
    }
  }

  Future<bool> _initiateSocialLogin({
    required String idpHint,
    required String providerLabel,
  }) async {
    try {
      codeVerifier = AuthService.generateCodeVerifier();
      final codeChallenge = AuthService.generateCodeChallenge(codeVerifier!);
      await _secureStorage.write(key: 'code_verifier', value: codeVerifier);

      final String origin = _config.loginDomain.contains('://')
          ? _config.loginDomain
          : 'https://${_config.loginDomain}';

      final Uri authUri = Uri.parse('$origin/oauth2/authorize').replace(
        queryParameters: {
          'client_id': _config.loginClientID,
          'redirect_uri': _config.loginRedirectURI,
          'response_type': 'code',
          'scope': 'openid email offline_access',
          'code_challenge': codeChallenge,
          'code_challenge_method': 'S256',
          'tenantId': _config.loginTenantID,
          'idp_hint': idpHint,
        },
      );

      // Delegate the platform-specific login flow to the plugin
      final bool launched = await _libloginNative.login(
        authUri: authUri,
        redirectUri: _config.loginRedirectURI,
      );

      if (!launched) {
        log.w('Could not launch $authUri');
      }
      return launched;
    } catch (e) {
      log.e('Failed to initiate $providerLabel login: $e');
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
    try {
      final response = await _httpClient.post(
        Uri.parse('${_config.signupOrigin}/login/forgot-password'),
        headers: {'content-type': 'application/json'},
        body: json.encode({'email': email}),
      );

      if (response.statusCode == 200) {
        log.i('Password recovery initiated for: $email');
        return true;
      } else {
        log.e('Password recovery failed: ${response.body}');
        return false;
      }
    } catch (e, stackTrace) {
      log.e('Password recovery failed', error: e, stackTrace: stackTrace);
      return false;
    }
  }

  Future<void> logout() async {
    await _secureStorage.delete(key: _accessTokenKey);
    await _secureStorage.delete(key: _idTokenKey);
    await _secureStorage.delete(key: _refreshTokenKey);
    await _secureStorage.delete(key: _userIDKey);
    await _secureStorage.delete(key: _lastLoginCredentialsKey);
    _currentAccessToken = null;
    _currentIdToken = null;
    _currentRefreshToken = null;
    _currentLastLoginCredentials = null;
    _refreshTokenTimer?.cancel();
  }

  Future<void> _storeLoginResponse(LoginResponse response) async {
    _currentAccessToken = response.accessToken;
    _currentIdToken = response.idToken;
    _currentRefreshToken = response.refreshToken;
    _currentLastLoginCredentials = response.lastLoginCredentials;

    await _secureStorage.write(
      key: _accessTokenKey,
      value: response.accessToken,
    );
    if (response.idToken != null) {
      await _secureStorage.write(
        key: _idTokenKey,
        value: response.idToken,
      );
    }
    if (response.refreshToken != null) {
      await _secureStorage.write(
        key: _refreshTokenKey,
        value: response.refreshToken,
      );
    }
    if (response.lastLoginCredentials != null) {
      final value = response.lastLoginCredentials is String
          ? response.lastLoginCredentials
          : json.encode(response.lastLoginCredentials);
      await _secureStorage.write(key: _lastLoginCredentialsKey, value: value);
    }

    // Extract userID from decoded token or user object
    final decoded = _jwtDecoder.decode(response.accessToken);
    final userID = decoded['sub'] as String;
    await _secureStorage.write(key: _userIDKey, value: userID);

    _scheduleTokenRefresh();
  }

  Future<void> _storeTokens(TokenResponse tokens) async {
    _currentAccessToken = tokens.accessToken;
    _currentIdToken = tokens.idToken;
    _currentRefreshToken = tokens.refreshToken;

    await _secureStorage.write(key: _accessTokenKey, value: tokens.accessToken);
    if (tokens.idToken != null) {
      await _secureStorage.write(
        key: _idTokenKey,
        value: tokens.idToken,
      );
    }
    if (tokens.refreshToken != null) {
      await _secureStorage.write(
        key: _refreshTokenKey,
        value: tokens.refreshToken,
      );
    }

    String? userID = tokens.userID;
    if (userID == null) {
      final decoded = _jwtDecoder.decode(tokens.accessToken);
      userID = decoded['sub'] as String?;
    }

    if (userID != null) {
      await _secureStorage.write(key: _userIDKey, value: userID);
    }

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
      log.i('Attempting proactive token refresh...');
      final TokenResponse newTokens;
      if (_currentRefreshToken != null) {
        newTokens = await _fusionAuthClient.oauthRefreshTokenGrant(
          _currentRefreshToken!,
        );
      } else if (_currentLastLoginCredentials != null) {
        newTokens = await _fusionAuthClient.refreshTokenGrant(
          _currentLastLoginCredentials!,
        );
      } else {
        log.w('No refresh credentials available for proactive refresh.');
        return;
      }
      await _storeTokens(newTokens);
      _authRedirectController.add(true);
    } catch (e) {
      log.e('Proactive token refresh failed: $e');
    } finally {
      _isRefreshing = false;
    }
  }

  Future<bool> checkLoginStatus() async {
    _currentAccessToken = await _secureStorage.read(key: _accessTokenKey);
    _currentIdToken = await _secureStorage.read(key: _idTokenKey);
    _currentRefreshToken = await _secureStorage.read(key: _refreshTokenKey);
    await _secureStorage.read(key: _userIDKey);

    if (_currentAccessToken != null &&
        !_jwtDecoder.isExpired(_currentAccessToken!)) {
      // Token is valid and not expired
      _scheduleTokenRefresh();
      return true;
    }

    // Token expired or absent — try OAuth refresh token first (covers all auth
    // methods including Google OAuth, which never sets lastLoginCredentials)
    if (_currentRefreshToken != null) {
      try {
        final newTokens = await _fusionAuthClient.oauthRefreshTokenGrant(
          _currentRefreshToken!,
        );
        await _storeTokens(newTokens);
        return true;
      } catch (e) {
        log.e('Failed to refresh with OAuth refresh token: $e');
        // Fall through to lastLoginCredentials
      }
    }

    if (_currentLastLoginCredentials != null) {
      try {
        final newTokens = await _fusionAuthClient.refreshTokenGrant(
          _currentLastLoginCredentials!,
        );
        await _storeTokens(newTokens);
        return true;
      } catch (e) {
        log.e('Failed to refresh token: $e');
        await logout();
        return false;
      }
    }

    return false;
  }
}
