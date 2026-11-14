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
  static const String _emailKey = 'email';
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
  String? _currentEmail;
  // Stored with the session, so the account stays known when the access token
  // is missing or unreadable.
  String? _currentUserID;

  final StreamController<SignInResult> _signInResultController =
      StreamController<SignInResult>.broadcast();

  /// Reports sign-in outcomes to listeners that did not start the attempt.
  ///
  /// - Every [SignInSucceeded], from any flow, so the session (AuthBloc) picks
  ///   up the new tokens.
  /// - [SignInFailed] and [SignInCancelled] only from the browser redirect
  ///   flow, which finishes long after [initiateGoogleLogin] has returned and
  ///   so has no caller to hand its result to.
  ///
  /// The direct flows ([login], [signUp], [initiateGoogleNativeLogin],
  /// [initiateAppleLogin]) return their failure or cancel to the caller
  /// instead, so a failure is reported exactly once.
  Stream<SignInResult> get signInResults => _signInResultController.stream;

  static const String _genericSignInFailure = "Couldn't sign in. Try again.";
  static const String _networkFailure =
      "Couldn't reach the sign-in server. Check your connection and try again.";
  static const String _genericRecoveryFailure =
      "Couldn't send the reset email. Try again.";

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

  final StreamController<RefreshOutcome> _refreshOutcomeController =
      StreamController<RefreshOutcome>.broadcast();

  /// The outcome of every refresh, including the silent timer-driven ones, so
  /// an app learns the login was refused without having asked.
  Stream<RefreshOutcome> get refreshOutcomes =>
      _refreshOutcomeController.stream;

  /// The current session's latest refresh outcome, null when it has had none.
  /// Lets a listener that arrives late know what it missed.
  RefreshOutcome? get lastRefreshOutcome => _lastRefreshOutcome;
  RefreshOutcome? _lastRefreshOutcome;

  String? get currentAccessToken => _currentAccessToken;
  String? get currentIdToken => _currentIdToken;

  /// The signed-in account's email, for showing who is signed in. Taken from
  /// the login response's user, or from an id token's `email` claim, and kept
  /// across restarts; null until a sign-in has said it. The access token does
  /// not carry it.
  String? get currentEmail => _currentEmail;
  dynamic get lastLoginCredentials => _currentLastLoginCredentials;

  /// Read-only access to the [LoginConfig] used to construct this service.
  /// Useful for widgets that need to introspect optional provider IDs without
  /// duplicating config plumbing.
  LoginConfig get config => _config;

  /// The session's claims. A missing or unreadable access token still answers
  /// with the stored user id, so the account stays known until a refresh.
  DecodedAccessToken? get decodedAccessToken {
    final token = _currentAccessToken;
    if (token != null) {
      try {
        return DecodedAccessToken.fromJson(_jwtDecoder.decode(token));
      } catch (e) {
        log.w('Stored access token is unreadable: $e');
      }
    }
    final userID = _currentUserID;
    return userID == null ? null : DecodedAccessToken(sub: userID);
  }

  /// The account the current tokens belong to, or null when none is known.
  String? get _currentSubject {
    final token = _currentAccessToken;
    if (token != null) {
      try {
        final sub = _jwtDecoder.decode(token)['sub'];
        if (sub is String) return sub;
      } catch (_) {
        // An unreadable token says nothing. The stored id still does.
      }
    }
    return _currentUserID;
  }

  Timer? _refreshTokenTimer;

  /// One overall limit for a refresh, whichever routes it tries.
  static const Duration refreshBudget = Duration(seconds: 20);

  /// A limit on a form sign-in, so a stalled connection cannot hold the form.
  static const Duration _signInTimeLimit = Duration(seconds: 20);

  // The one refresh running now. Every entry point shares it.
  Future<RefreshOutcome>? _refreshInFlight;

  // Bumped by sign-in, log out and a session restore. A refresh that started
  // under an older value stores and publishes nothing.
  int _authGeneration = 0;

  // Token writes run one at a time, so a refresh landing mid sign-in cannot
  // leave one account's keys mixed with another's.
  Future<void>? _tokenWrites;

  Future<T> _serialised<T>(Future<T> Function() body) {
    final previous = _tokenWrites;
    final result = previous == null ? body() : previous.then((_) => body());
    final tail = result.then<void>((_) {}, onError: (Object _) {});
    _tokenWrites = tail;
    tail.whenComplete(() {
      if (identical(_tokenWrites, tail)) _tokenWrites = null;
    });
    return result;
  }

  void _bumpAuthGeneration() {
    _authGeneration++;
    _refreshInFlight = null;
    _lastRefreshOutcome = null;
  }

  /// Call before an app moves another account's tokens into the slot itself,
  /// then call [restoreSession]. A refresh still running stores nothing, so it
  /// cannot write the old account's tokens over the new ones.
  Future<void> beginSessionChange() async {
    _bumpAuthGeneration();
    _refreshTokenTimer?.cancel();
    _refreshRetryTimer?.cancel();
    _nextRefreshRetryDelay = _initialRefreshRetryDelay;
    await _tokenWrites;
  }

  // Bumped when the person backs out of signing in. An attempt that started
  // under an older value stores nothing and answers [SignInCancelled].
  int _signInAttempt = 0;
  bool _browserAttemptPending = false;
  bool _dropNextRedirect = false;

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
    _currentEmail = await _secureStorage.read(key: _emailKey);
    await _loadLastLoginCredentials();
  }

  Future<void> _loadLastLoginCredentials() async {
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
    _signInResultController.close();
    _accessTokenController.close();
    _refreshOutcomeController.close();
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

  void _publishSignInResult(SignInResult result) {
    if (_signInResultController.isClosed) return;
    _signInResultController.add(result);
  }

  /// Turns a sign-in error into a message the user can be shown.
  ///
  /// [serverWritesForUsers] is true only for the sign-in server's own
  /// `/login/*` endpoints, whose 4xx answers are hand-written sentences
  /// ("Invalid email or password", "A user already exists with this email").
  /// FusionAuth's endpoints answer with JSON for programs, so they never pass
  /// their body through.
  static String _userFacingFailure(
    Object error, {
    required bool serverWritesForUsers,
    String fallback = _genericSignInFailure,
  }) {
    if (error is TimeoutException || error is http.ClientException) {
      return _networkFailure;
    }
    if (serverWritesForUsers &&
        error is AuthServerException &&
        error.statusCode >= 400 &&
        error.statusCode < 500) {
      final text = error.body.trim();
      final looksLikeASentence =
          text.isNotEmpty &&
          text.length <= 200 &&
          !text.startsWith('{') &&
          !text.startsWith('[') &&
          !text.startsWith('<');
      if (looksLikeASentence) return text;
    }
    return fallback;
  }

  Future<void> _processAuthRedirect(Uri uri) async {
    final attempt = _signInAttempt;
    _browserAttemptPending = false;
    if (_dropNextRedirect) {
      _dropNextRedirect = false;
      log.i('Dropping a browser sign-in the user already backed out of');
      return;
    }
    try {
      final String? code = uri.queryParameters['code'];
      if (code == null) {
        // OAuth reports a user who declined consent as error=access_denied.
        final error = uri.queryParameters['error'];
        if (error == 'access_denied') {
          log.i('Sign-in redirect reports the user cancelled');
          _publishSignInResult(const SignInCancelled());
          return;
        }
        log.w('Authorization code not found in redirect URI (error=$error)');
        _publishSignInResult(const SignInFailed(_genericSignInFailure));
        return;
      }

      final codeVerifier = await _secureStorage.read(key: 'code_verifier');
      final tokens = await _fusionAuthClient.exchangeAuthorizationCode(
        code,
        codeVerifier!,
      );
      if (attempt != _signInAttempt) {
        log.i('Dropping a browser sign-in the user already backed out of');
        return;
      }
      await _replaceSessionWithTokens(tokens);
      log.i('Exchanged code for tokens and stored them successfully');
      _publishSignInResult(const SignInSucceeded());
    } catch (e) {
      log.e('Failed to handle auth redirect: $e');
      _publishSignInResult(
        SignInFailed(_userFacingFailure(e, serverWritesForUsers: false)),
      );
    }
  }

  /// The app's description of this device for a sign-in, as the server's
  /// `metaData.device` JSON. Null when the app gives none or describing fails:
  /// a sign-in never fails because the device could not be named.
  Future<Map<String, String>?> _describeDevice() async {
    final describe = _config.describeDevice;
    if (describe == null) return null;
    try {
      return (await describe())?.toJson();
    } catch (e) {
      log.w('Could not describe this device for sign-in: $e');
      return null;
    }
  }

  /// Email and password sign-in. Never throws: a failure comes back as
  /// [SignInFailed] carrying a message safe to show.
  Future<SignInResult> login(String username, String password) async {
    final attempt = _signInAttempt;
    try {
      final device = await _describeDevice();
      final response = await _fusionAuthClient
          .login(
            username: username,
            password: password,
            scope: 'openid email offline_access',
            device: device ?? const {},
            // Never the stored credential blob: the server's /login/login
            // lets the blob override the typed email and password, so a typed
            // sign-in would land in whatever account the blob holds.
          )
          .timeout(_signInTimeLimit);
      if (attempt != _signInAttempt) return const SignInCancelled();
      await _storeLoginResponse(response);
      _publishSignInResult(const SignInSucceeded());
      return const SignInSucceeded();
    } catch (e, stackTrace) {
      log.e('Login failed', error: e, stackTrace: stackTrace);
      return SignInFailed(_userFacingFailure(e, serverWritesForUsers: true));
    }
  }

  /// Registers, then signs in. Never throws. The server asks new users to
  /// verify their email, so the follow-up sign-in usually fails with the
  /// server's "Please verify your email" sentence, which is passed through.
  Future<SignInResult> signUp(String username, String password) async {
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
      if (response.statusCode != 200) {
        throw AuthServerException(response.statusCode, response.body);
      }
    } catch (e, stackTrace) {
      log.e('Sign up failed', error: e, stackTrace: stackTrace);
      return SignInFailed(_userFacingFailure(e, serverWritesForUsers: true));
    }
    return login(username, password);
  }

  String? codeVerifier;

  /// Opens the browser sign-in page and returns whether it opened. The
  /// outcome of the sign-in itself arrives later on [signInResults].
  Future<bool> initiateGoogleLogin() {
    return _initiateSocialLogin(
      idpHint: _config.googleIdentityProviderID,
      providerLabel: 'Google',
    );
  }

  /// Initiates native Sign in with Apple using [AppleSignInWrapper], then
  /// exchanges the resulting identity token with FusionAuth's IdP login API.
  ///
  /// Returns [SignInCancelled] when the user dismisses the Apple sheet and
  /// [SignInFailed] for anything else that goes wrong, including Apple
  /// returning no identity token. Only success is also published on
  /// [signInResults].
  ///
  /// Throws a [StateError] if [LoginConfig.appleIdentityProviderID] is not set.
  Future<SignInResult> initiateAppleLogin() async {
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
    final attempt = _signInAttempt;
    try {
      final credential = await _appleSignIn.getCredential();
      final identityToken = credential.identityToken;
      if (identityToken == null) {
        log.w('Apple sign in returned null identity token');
        return const SignInFailed(_genericSignInFailure);
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
        device: await _describeDevice(),
      );
      if (attempt != _signInAttempt) return const SignInCancelled();
      await _replaceSessionWithTokens(tokens);
      _publishSignInResult(const SignInSucceeded());
      return const SignInSucceeded();
    } on SignInWithAppleAuthorizationException catch (e) {
      if (e.code == AuthorizationErrorCode.canceled) {
        log.i('Apple sign in cancelled by user');
        return const SignInCancelled();
      }
      log.e('Apple sign in failed: ${e.message}');
      return const SignInFailed(_genericSignInFailure);
    } catch (e, stackTrace) {
      log.e('Apple sign in failed', error: e, stackTrace: stackTrace);
      return SignInFailed(_userFacingFailure(e, serverWritesForUsers: false));
    }
  }

  /// Initiates native Google Sign-In using [GoogleSignInWrapper], then
  /// exchanges the resulting `id_token` with FusionAuth's IdP login API.
  ///
  /// Structural mirror of [initiateAppleLogin]: [SignInCancelled] when the
  /// user dismisses the Google sheet, [SignInFailed] for anything else
  /// (including a missing id_token), and only success is also published on
  /// [signInResults].
  ///
  /// Throws a [StateError] if [LoginConfig.googleIdentityProviderID] is empty.
  Future<SignInResult> initiateGoogleNativeLogin() async {
    final googleIdpID = _config.googleIdentityProviderID;
    if (googleIdpID.isEmpty) {
      throw StateError(
        'googleIdentityProviderID is not configured on LoginConfig. '
        'Set it before calling initiateGoogleNativeLogin().',
      );
    }
    final attempt = _signInAttempt;
    try {
      final idToken = await _googleSignIn.getIdToken();
      if (idToken == null) {
        log.w('Google sign in returned null id token');
        return const SignInFailed(_genericSignInFailure);
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
        device: await _describeDevice(),
      );
      if (attempt != _signInAttempt) return const SignInCancelled();
      await _replaceSessionWithTokens(tokens);
      _publishSignInResult(const SignInSucceeded());
      return const SignInSucceeded();
    } on GoogleSignInException catch (e) {
      if (e.code == GoogleSignInExceptionCode.canceled) {
        log.i('Google sign in cancelled by user');
        return const SignInCancelled();
      }
      log.e('Google sign in failed: ${e.code} ${e.description}');
      return const SignInFailed(_genericSignInFailure);
    } catch (e, stackTrace) {
      log.e('Google sign in failed', error: e, stackTrace: stackTrace);
      return SignInFailed(_userFacingFailure(e, serverWritesForUsers: false));
    }
  }

  Future<bool> _initiateSocialLogin({
    required String idpHint,
    required String providerLabel,
  }) async {
    _browserAttemptPending = true;
    _dropNextRedirect = false;
    try {
      codeVerifier = AuthService.generateCodeVerifier();
      final codeChallenge = AuthService.generateCodeChallenge(codeVerifier!);
      await _secureStorage.write(key: 'code_verifier', value: codeVerifier);

      final String origin = _config.loginDomain.contains('://')
          ? _config.loginDomain
          : 'https://${_config.loginDomain}';
      final device = await _describeDevice();

      final Uri authUri = Uri.parse('$origin/oauth2/authorize').replace(
        queryParameters: {
          if (device != null) 'metaData.device.name': device['name']!,
          if (device != null) 'metaData.device.type': device['type']!,
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

  /// Asks the server to email a password reset link. Returns null on success,
  /// otherwise a message safe to show the user. Never throws.
  Future<String?> recoverPassword(String email) async {
    try {
      final response = await _httpClient.post(
        Uri.parse('${_config.signupOrigin}/login/forgot-password'),
        headers: {'content-type': 'application/json'},
        body: json.encode({'email': email}),
      );
      if (response.statusCode != 200) {
        throw AuthServerException(response.statusCode, response.body);
      }
      log.i('Password recovery initiated for: $email');
      return null;
    } catch (e, stackTrace) {
      log.e('Password recovery failed', error: e, stackTrace: stackTrace);
      return _userFacingFailure(
        e,
        serverWritesForUsers: true,
        fallback: _genericRecoveryFailure,
      );
    }
  }

  /// The person backed out of signing in. Whatever is still running stores
  /// nothing, and a browser redirect that arrives later is dropped.
  void cancelPendingSignIn() {
    _signInAttempt++;
    if (_browserAttemptPending) _dropNextRedirect = true;
  }

  Future<void> logout() async {
    _bumpAuthGeneration();
    _refreshTokenTimer?.cancel();
    _refreshRetryTimer?.cancel();
    _nextRefreshRetryDelay = _initialRefreshRetryDelay;
    await _serialised(() async {
      await _secureStorage.delete(key: _accessTokenKey);
      await _secureStorage.delete(key: _idTokenKey);
      await _secureStorage.delete(key: _refreshTokenKey);
      await _secureStorage.delete(key: _userIDKey);
      await _secureStorage.delete(key: _emailKey);
      await _secureStorage.delete(key: _lastLoginCredentialsKey);
      _currentAccessToken = null;
      _currentEmail = null;
      _currentIdToken = null;
      _currentRefreshToken = null;
      _currentLastLoginCredentials = null;
      _currentUserID = null;
    });
  }

  Future<void> _storeLoginResponse(LoginResponse response) async {
    // A password login's token always names its user. Read it before touching
    // the slot, so a bad response leaves the old session whole.
    final userID = _jwtDecoder.decode(response.accessToken)['sub'] as String;
    await _replaceSession(
      accessToken: response.accessToken,
      idToken: response.idToken,
      refreshToken: response.refreshToken,
      lastLoginCredentials: response.lastLoginCredentials,
      userID: userID,
      email: response.user?['email'] as String? ?? _emailOf(response.idToken),
    );
  }

  Future<void> _replaceSessionWithTokens(TokenResponse tokens) {
    return _replaceSession(
      accessToken: tokens.accessToken,
      idToken: tokens.idToken,
      refreshToken: tokens.refreshToken,
      lastLoginCredentials: tokens.lastLoginCredentials,
      userID:
          tokens.userID ??
          _jwtDecoder.decode(tokens.accessToken)['sub'] as String?,
      email: tokens.email ?? _emailOf(tokens.idToken),
    );
  }

  /// A sign-in replaces the whole token slot: a key the new session lacks is
  /// deleted, so the old account's credentials cannot renew under the new one.
  Future<void> _replaceSession({
    required String accessToken,
    required String? idToken,
    required String? refreshToken,
    required dynamic lastLoginCredentials,
    required String? userID,
    required String? email,
  }) {
    _bumpAuthGeneration();
    return _serialised(() async {
      _currentAccessToken = accessToken;
      _currentIdToken = idToken;
      _currentRefreshToken = refreshToken;
      _currentLastLoginCredentials = lastLoginCredentials;
      _currentUserID = userID;
      final cleanEmail = email?.trim();
      _currentEmail = cleanEmail == null || cleanEmail.isEmpty
          ? null
          : cleanEmail;

      await _secureStorage.write(key: _accessTokenKey, value: accessToken);
      await _writeOrDelete(_idTokenKey, idToken);
      await _writeOrDelete(_refreshTokenKey, refreshToken);
      await _writeOrDelete(
        _lastLoginCredentialsKey,
        lastLoginCredentials == null || lastLoginCredentials is String
            ? lastLoginCredentials as String?
            : json.encode(lastLoginCredentials),
      );
      await _writeOrDelete(_userIDKey, userID);
      await _writeOrDelete(_emailKey, _currentEmail);

      _scheduleTokenRefresh();
      _publishAccessToken(accessToken);
    });
  }

  Future<void> _writeOrDelete(String key, String? value) {
    return value == null
        ? _secureStorage.delete(key: key)
        : _secureStorage.write(key: key, value: value);
  }

  /// The `email` claim of [idToken], or null.
  String? _emailOf(String? idToken) {
    if (idToken == null) return null;
    try {
      final email = _jwtDecoder.decode(idToken)['email'];
      return email is String ? email : null;
    } catch (_) {
      return null;
    }
  }

  /// Keeps [email] as [currentEmail] when it says one; null leaves it as is.
  Future<void> _storeEmail(String? email) async {
    if (email == null || email.trim().isEmpty) return;
    _currentEmail = email.trim();
    await _secureStorage.write(key: _emailKey, value: _currentEmail);
  }

  Future<void> _storeTokens(TokenResponse tokens) async {
    _currentAccessToken = tokens.accessToken;
    _currentIdToken = tokens.idToken;
    // Only adopt a refresh token when the response actually carries one. A
    // refresh response may omit it, and nulling a good in-memory refresh token
    // would strand the next refresh on the wrong route.
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
    // Keep whatever lastLoginCredentials the server sends back. The backend
    // reissues the blob but nothing in it rotates, so an older copy still works.
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
      _currentUserID = userID;
      await _secureStorage.write(key: _userIDKey, value: userID);
    }
    // A refresh usually has no id token; the email from the sign-in stays.
    await _storeEmail(tokens.email ?? _emailOf(tokens.idToken));

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

  /// Refreshes now, whatever the token's age, sharing one run with every other
  /// entry point. Never throws, never deletes, and answers within
  /// [refreshBudget]. Reads the tokens [restoreSession] or a sign-in loaded.
  Future<RefreshOutcome> refreshNow() {
    final running = _refreshInFlight;
    if (running != null) return running;
    final run = _budgetedRefresh(_authGeneration);
    _refreshInFlight = run;
    run.whenComplete(() {
      if (identical(_refreshInFlight, run)) _refreshInFlight = null;
    });
    return run;
  }

  Future<RefreshOutcome> _budgetedRefresh(int generation) async {
    RefreshOutcome outcome;
    try {
      // A reply that lands after the limit is still stored if the session has
      // not changed: nothing rotates, so it is simply a good token.
      outcome = await _refreshOnce(generation).timeout(refreshBudget);
    } catch (e) {
      log.w('Token refresh got no usable answer: ${e.runtimeType}');
      outcome = RefreshOutcome.unreachable;
    }
    log.i('Token refresh finished: ${outcome.name}');
    if (outcome != RefreshOutcome.superseded) _lastRefreshOutcome = outcome;
    if (!_refreshOutcomeController.isClosed) {
      _refreshOutcomeController.add(outcome);
    }
    return outcome;
  }

  /// Only `invalid_grant` from `/oauth2/token` proves a login is dead.
  static bool _isRefusal(AuthServerException e) {
    if (e.statusCode != 400) return false;
    try {
      final body = json.decode(e.body);
      return body is Map && body['error'] == 'invalid_grant';
    } catch (_) {
      return false;
    }
  }

  Future<RefreshOutcome> _refreshOnce(int generation) async {
    bool stale() => generation != _authGeneration;
    final refreshToken = _currentRefreshToken;
    final credentials = _currentLastLoginCredentials;
    final expectedSubject = _currentSubject;

    TokenResponse? tokens;
    var failure = RefreshOutcome.noPath;
    if (refreshToken != null) {
      try {
        tokens = await _fusionAuthClient.oauthRefreshTokenGrant(refreshToken);
      } on AuthServerException catch (e) {
        if (_isRefusal(e)) {
          return stale() ? RefreshOutcome.superseded : RefreshOutcome.refused;
        }
        log.w('OAuth refresh failed with HTTP ${e.statusCode}');
        failure = RefreshOutcome.unreachable;
      } catch (e) {
        log.w('OAuth refresh failed: ${e.runtimeType}');
        failure = RefreshOutcome.unreachable;
      }
    }
    // The server-side route renews logins with no refresh token, and still
    // covers a confidential client, which FusionAuth answers with
    // invalid_client on the route above.
    if (tokens == null && credentials != null && !stale()) {
      try {
        tokens = await _fusionAuthClient.refreshTokenGrant(credentials);
      } on AuthServerException catch (e) {
        log.w('Server-side refresh failed with HTTP ${e.statusCode}');
        // 400 is what this route says for a dead login and an outage alike.
        if (e.statusCode != 400) failure = RefreshOutcome.unreachable;
      } catch (e) {
        log.w('Server-side refresh failed: ${e.runtimeType}');
        failure = RefreshOutcome.unreachable;
      }
    }
    if (stale()) return RefreshOutcome.superseded;
    final received = tokens;
    if (received == null) return failure;

    return _serialised(() async {
      if (stale()) return RefreshOutcome.superseded;
      final subject =
          received.userID ??
          _jwtDecoder.decode(received.accessToken)['sub'] as String?;
      if (subject != null &&
          expectedSubject != null &&
          subject != expectedSubject) {
        log.e('[INTEGRITY] Discarded a refresh for a different account');
        return RefreshOutcome.unreachable;
      }
      // _storeTokens publishes to accessTokenStream, which is what propagates
      // the new token. Deliberately NOT signalling signInResults: a silent
      // refresh is not a completed sign-in, and publishing SignInSucceeded for
      // it makes AuthBloc bounce every listener through AuthLoading.
      await _storeTokens(received);
      return RefreshOutcome.renewed;
    });
  }

  Future<void> _attemptTokenRefresh() async {
    if (_refreshInFlight != null) {
      log.d('Refresh already in progress. Skipping.');
      return;
    }
    log.i('Attempting proactive token refresh...');
    final hadCredentials =
        _currentRefreshToken != null || _currentLastLoginCredentials != null;
    final outcome = await refreshNow();
    switch (outcome) {
      case RefreshOutcome.renewed || RefreshOutcome.superseded:
        // _storeTokens rescheduled, or the new session armed its own timer.
        break;
      case RefreshOutcome.refused:
        log.w('The login was refused. Proactive refresh stops here.');
      case RefreshOutcome.noPath when !hadCredentials:
        log.w('No refresh credentials available for proactive refresh.');
      case RefreshOutcome.unreachable || RefreshOutcome.noPath:
        // Do NOT give up: a single missed refresh would strand the token stale
        // for the rest of the process. On success, _storeTokens ->
        // _scheduleTokenRefresh resets this state.
        _scheduleRefreshRetry();
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

  /// Loads the stored session with no network, and reports whether one exists.
  /// A session is any stored tokens that name an account: an expired access
  /// token is still a session, and so is a missing or unreadable one with a
  /// stored user id. Renewal runs behind this and reports on [refreshOutcomes].
  ///
  /// Unlike [checkLoginStatus], this never deletes anything and never waits on
  /// the server.
  Future<bool> restoreSession() async {
    await beginSessionChange();
    _currentAccessToken = await _secureStorage.read(key: _accessTokenKey);
    _currentIdToken = await _secureStorage.read(key: _idTokenKey);
    _currentRefreshToken = await _secureStorage.read(key: _refreshTokenKey);
    _currentUserID = await _secureStorage.read(key: _userIDKey);
    _currentEmail = await _secureStorage.read(key: _emailKey);
    await _loadLastLoginCredentials();

    if (_currentSubject == null) return false;

    var readable = false;
    if (_currentAccessToken != null) {
      try {
        _jwtDecoder.decode(_currentAccessToken!);
        readable = true;
      } catch (_) {
        // Handled below: an unreadable token is renewed like a missing one.
      }
    }
    if (readable) {
      _scheduleTokenRefresh();
    } else {
      unawaited(_attemptTokenRefresh());
    }
    return true;
  }

  /// Picks up tokens another tab or process stored, with no network. Answers
  /// whether the stored session differed from the one held here.
  Future<bool> adoptStoredSessionIfChanged() async {
    final access = await _secureStorage.read(key: _accessTokenKey);
    final refresh = await _secureStorage.read(key: _refreshTokenKey);
    if (access == _currentAccessToken && refresh == _currentRefreshToken) {
      return false;
    }
    await restoreSession();
    return true;
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
