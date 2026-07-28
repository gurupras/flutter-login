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
import 'package:google_sign_in/google_sign_in.dart';
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

// Wrapper for google_sign_in to allow mocking.
//
// Uses the google_sign_in v7 API (`GoogleSignIn.instance`, `initialize`,
// `authenticate`). [initialize] must be called exactly once before
// [authenticate]; this wrapper handles that lazily on the first call.
class GoogleSignInWrapper {
  final GoogleSignIn _googleSignIn;

  /// FusionAuth's Google **web** client ID, forwarded to
  /// [GoogleSignIn.initialize] as `serverClientId` so the issued `id_token`
  /// carries the audience FusionAuth expects. See
  /// [LoginConfig.googleServerClientId].
  final String? serverClientId;

  /// Platform (iOS) OAuth client ID, forwarded as `clientId`. Usually null and
  /// supplied via native config instead. See [LoginConfig.googleIosClientId].
  final String? clientId;

  bool _initialized = false;

  GoogleSignInWrapper({
    GoogleSignIn? googleSignIn,
    this.serverClientId,
    this.clientId,
  }) : _googleSignIn = googleSignIn ?? GoogleSignIn.instance;

  Future<void> _ensureInitialized() async {
    if (_initialized) return;
    await _googleSignIn.initialize(
      clientId: clientId,
      serverClientId: serverClientId,
    );
    _initialized = true;
  }

  /// Triggers the native Google account sheet and returns the resulting
  /// `id_token`, or null if Google returned no id token.
  ///
  /// Throws a [GoogleSignInException] (e.g. with
  /// [GoogleSignInExceptionCode.canceled] when the user dismisses the sheet),
  /// which callers are expected to handle.
  Future<String?> getIdToken() async {
    await _ensureInitialized();
    final account = await _googleSignIn.authenticate();
    return account.authentication.idToken;
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

  final StreamController<String> _accessTokenController =
      StreamController<String>.broadcast();

  /// Emits every time a new access token is obtained — initial login, signup,
  /// IdP/redirect exchange, and (critically) the silent background refresh
  /// driven by [_scheduleTokenRefresh].
  ///
  /// Consumers that cache the token (API clients, socket auth) MUST listen to
  /// this rather than reading [currentAccessToken] once at login. Without it a
  /// long-lived process keeps using the token it was handed at startup, which
  /// begins failing with 401 as soon as that token expires — even though this
  /// service has already refreshed it behind the scenes.
  Stream<String> get accessTokenStream => _accessTokenController.stream;

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

  // Self-healing retry for the proactive refresh. When a scheduled refresh
  // fails (transient network error, device was Dozing at fire time, …) we do
  // NOT give up — a single missed refresh would otherwise leave the token
  // permanently stale for the life of the process. Instead we re-arm a bounded,
  // exponential backoff and keep trying until one succeeds. Reset on success
  // (via [_scheduleTokenRefresh]) and cancelled in [dispose]/[logout].
  Timer? _refreshRetryTimer;
  static const Duration _initialRefreshRetryDelay = Duration(seconds: 30);
  static const Duration _maxRefreshRetryDelay = Duration(minutes: 5);
  Duration _nextRefreshRetryDelay = _initialRefreshRetryDelay;

  final LibloginNative _libloginNative;
  final AppleSignInWrapper _appleSignIn;
  final GoogleSignInWrapper _googleSignIn;

  AuthService({
    required LoginConfig config,
    FlutterSecureStorage? secureStorage,
    http.Client? httpClient,
    JwtDecoderWrapper? jwtDecoder,
    FusionAuthClient? fusionAuthClient,
    LibloginNative? libloginNative,
    AppleSignInWrapper? appleSignIn,
    GoogleSignInWrapper? googleSignIn,
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
       _appleSignIn = appleSignIn ?? AppleSignInWrapper(),
       _googleSignIn =
           googleSignIn ??
           GoogleSignInWrapper(
             serverClientId: config.googleServerClientId,
             clientId: config.googleIosClientId,
           ) {
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
    _accessTokenController.close();
    _refreshTokenTimer?.cancel();
    _refreshRetryTimer?.cancel();
  }

  /// Publish a newly-obtained access token to [accessTokenStream].
  ///
  /// Guarded because a scheduled refresh can land after [dispose] — adding to
  /// a closed controller throws.
  void _publishAccessToken(String token) {
    if (_accessTokenController.isClosed) return;
    _accessTokenController.add(token);
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

  /// Initiates native Google Sign-In using [GoogleSignInWrapper], then
  /// exchanges the resulting `id_token` with FusionAuth's IdP login API.
  ///
  /// Structural mirror of [initiateAppleLogin]. Returns true on success. On
  /// user cancellation or a missing id_token it returns false quietly (no
  /// `authRedirectStream` event); on any other failure it emits false and
  /// returns false.
  ///
  /// Throws a [StateError] if [LoginConfig.googleIdentityProviderID] is empty.
  Future<bool> initiateGoogleNativeLogin() async {
    final googleIdpID = _config.googleIdentityProviderID;
    if (googleIdpID.isEmpty) {
      throw StateError(
        'googleIdentityProviderID is not configured on LoginConfig. '
        'Set it before calling initiateGoogleNativeLogin().',
      );
    }
    try {
      final idToken = await _googleSignIn.getIdToken();
      if (idToken == null) {
        log.w('Google sign in returned null id token');
        return false;
      }
      try {
        final claims = _jwtDecoder.decode(idToken);
        log.i(
          'Google id_token claims: aud=${claims['aud']} iss=${claims['iss']} '
          'sub=${claims['sub']} email=${claims['email']} '
          'iat=${claims['iat']} exp=${claims['exp']}',
        );
      } catch (e) {
        log.w('Could not decode Google id_token for diagnostics: $e');
      }
      log.i(
        'Sending to FusionAuth googleIdpLogin: '
        'identityProviderId=$googleIdpID',
      );
      final tokens = await _fusionAuthClient.googleIdpLogin(
        idToken: idToken,
        identityProviderId: googleIdpID,
      );
      await _storeTokens(tokens);
      _authRedirectController.add(true);
      return true;
    } on GoogleSignInException catch (e) {
      if (e.code == GoogleSignInExceptionCode.canceled) {
        log.i('Google sign in cancelled by user');
        return false;
      }
      log.e('Google sign in failed: ${e.code} ${e.description}');
      _authRedirectController.add(false);
      return false;
    } catch (e, stackTrace) {
      log.e('Google sign in failed', error: e, stackTrace: stackTrace);
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
    _refreshRetryTimer?.cancel();
    _nextRefreshRetryDelay = _initialRefreshRetryDelay;
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
    _publishAccessToken(response.accessToken);
  }

  Future<void> _storeTokens(TokenResponse tokens) async {
    _currentAccessToken = tokens.accessToken;
    _currentIdToken = tokens.idToken;
    // Only adopt a refresh token when the response actually carries one. A
    // refresh response may omit it (the server-side /login/refresh-tokens path
    // returns a rotated lastLoginCredentials instead), and nulling a good
    // in-memory refresh token would strand the next refresh on the wrong path.
    if (tokens.refreshToken != null) {
      _currentRefreshToken = tokens.refreshToken;
    }

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
    // Persist the ROTATED lastLoginCredentials so the next server-side refresh
    // uses the fresh credential. Without this the second refresh re-sends a
    // consumed one and FusionAuth answers refresh_token_not_found. Mirrors
    // _storeLoginResponse.
    if (tokens.lastLoginCredentials != null) {
      _currentLastLoginCredentials = tokens.lastLoginCredentials;
      final value = tokens.lastLoginCredentials is String
          ? tokens.lastLoginCredentials as String
          : json.encode(tokens.lastLoginCredentials);
      await _secureStorage.write(key: _lastLoginCredentialsKey, value: value);
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
    _publishAccessToken(tokens.accessToken);
  }

  void _scheduleTokenRefresh() {
    _refreshTokenTimer?.cancel();
    // A (re)schedule means we hold a fresh, valid token again: tear down any
    // pending failure-retry and reset the backoff so a future outage starts
    // from the short delay.
    _refreshRetryTimer?.cancel();
    _nextRefreshRetryDelay = _initialRefreshRetryDelay;

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
      // _storeTokens publishes to accessTokenStream, which is what propagates
      // the new token to listeners. Deliberately NOT signalling
      // _authRedirectController here: this is a silent background refresh, not
      // a completed redirect, and routing it through the redirect stream makes
      // AuthBloc re-run AuthCheckStatus — bouncing every listener through
      // AuthLoading (and a redundant secure-storage round-trip) roughly once an
      // hour, for a token the service has already updated in place.
      await _storeTokens(newTokens);
    } catch (e) {
      // Do NOT swallow the failure: a single missed refresh would strand the
      // token stale for the rest of the process. Re-arm a bounded backoff so a
      // transient outage recovers on its own. (On success, _storeTokens ->
      // _scheduleTokenRefresh resets this state and restores the normal timer.)
      log.e('Proactive token refresh failed: $e');
      _scheduleRefreshRetry();
    } finally {
      _isRefreshing = false;
    }
  }

  /// Re-arms a proactive-refresh attempt after a failure, using an
  /// exponential-ish backoff capped at [_maxRefreshRetryDelay]. Cancels any
  /// existing retry timer first so we never leak concurrent timers.
  void _scheduleRefreshRetry() {
    _refreshRetryTimer?.cancel();

    final Duration delay = _nextRefreshRetryDelay;
    log.w(
      'Scheduling proactive token refresh retry in ${delay.inSeconds} seconds.',
    );
    _refreshRetryTimer = Timer(delay, () {
      log.i('Retrying proactive token refresh.');
      _attemptTokenRefresh();
    });

    // Escalate for the next failure, capped.
    final int nextMs = delay.inMilliseconds * 2;
    _nextRefreshRetryDelay = nextMs >= _maxRefreshRetryDelay.inMilliseconds
        ? _maxRefreshRetryDelay
        : Duration(milliseconds: nextMs);
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
