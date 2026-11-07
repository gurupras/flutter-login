import 'dart:async';

import 'package:fake_async/fake_async.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:liblogin/src/auth_models.dart';
import 'package:liblogin/src/auth_service.dart';
import 'package:liblogin/src/login_config.dart';
import 'package:mockito/mockito.dart';

import 'auth_service_test.mocks.dart';

/// Keeps what it is given, so a test can read the slot back.
class _MemoryStorage extends Fake implements FlutterSecureStorage {
  final Map<String, String> values = {};

  @override
  Future<String?> read({
    required String key,
    AndroidOptions? aOptions,
    AppleOptions? iOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async => values[key];

  @override
  Future<void> write({
    required String key,
    required String? value,
    AndroidOptions? aOptions,
    AppleOptions? iOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async {
    if (value == null) {
      values.remove(key);
    } else {
      values[key] = value;
    }
  }

  @override
  Future<void> delete({
    required String key,
    AndroidOptions? aOptions,
    AppleOptions? iOptions,
    LinuxOptions? lOptions,
    WebOptions? webOptions,
    AppleOptions? mOptions,
    WindowsOptions? wOptions,
  }) async {
    values.remove(key);
  }
}

/// A token is its own claims: `<sub>:<seconds from now>`, or `bad` to throw.
class _Jwt extends Fake implements JwtDecoderWrapper {
  @override
  Map<String, dynamic> decode(String token) {
    if (token == 'bad') throw const FormatException('not a token');
    final parts = token.split(':');
    final exp =
        DateTime.now()
            .add(Duration(seconds: int.parse(parts[1])))
            .millisecondsSinceEpoch ~/
        1000;
    return {'sub': parts[0], 'exp': exp};
  }

  @override
  bool isExpired(String token) =>
      (decode(token)['exp'] as int) * 1000 <
      DateTime.now().millisecondsSinceEpoch;
}

const _tenDays = 864000;
const _expired = -3600;

TokenResponse _tokens(String sub, {String? refresh, dynamic credentials}) =>
    TokenResponse(
      accessToken: '$sub:$_tenDays',
      expiresIn: _tenDays,
      tokenType: 'Bearer',
      refreshToken: refresh,
      lastLoginCredentials: credentials,
    );

final _deadLogin = AuthServerException(
  400,
  '{"error":"invalid_grant","error_reason":"refresh_token_not_found"}',
);

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  late _MemoryStorage storage;
  late MockFusionAuthClient client;
  late MockLibloginNative native;
  late MockGoogleSignInWrapper google;
  late AuthService service;

  setUp(() {
    storage = _MemoryStorage();
    client = MockFusionAuthClient();
    native = MockLibloginNative();
    google = MockGoogleSignInWrapper();
    when(native.setAuthRedirectHandler(any)).thenAnswer((_) async {});
    service = AuthService(
      config: LoginConfig(
        loginDomain: 'example.com',
        signupOrigin: 'https://signup.example.com',
        loginTenantID: 'tenant',
        loginClientID: 'client',
        loginRedirectURI: 'https://example.com/callback',
        googleIdentityProviderID: 'google-idp',
      ),
      secureStorage: storage,
      httpClient: MockClient(),
      jwtDecoder: _Jwt(),
      fusionAuthClient: client,
      libloginNative: native,
      appleSignIn: MockAppleSignInWrapper(),
      googleSignIn: google,
    );
  });

  tearDown(() => service.dispose());

  void storeSession({
    String? access = 'a:$_expired',
    String? refresh = 'refresh-a',
    String? userID = 'a',
    String? credentials,
  }) {
    if (access != null) storage.values['accessToken'] = access;
    if (refresh != null) storage.values['refreshToken'] = refresh;
    if (userID != null) storage.values['userID'] = userID;
    if (credentials != null) {
      storage.values['lastLoginCredentials'] = credentials;
    }
  }

  group('restoreSession', () {
    test('an expired token is still a session, and nothing waits on the server',
        () async {
      storeSession();
      final hanging = Completer<TokenResponse>();
      when(client.oauthRefreshTokenGrant(any))
          .thenAnswer((_) => hanging.future);

      expect(await service.restoreSession(), isTrue);

      expect(service.decodedAccessToken?.sub, 'a');
      expect(service.currentAccessToken, 'a:$_expired');
      expect(storage.values['refreshToken'], 'refresh-a');
    });

    test('nothing stored is no session', () async {
      expect(await service.restoreSession(), isFalse);
      verifyNever(client.oauthRefreshTokenGrant(any));
    });

    test('an unreadable token with a stored user id keeps the account known',
        () async {
      storeSession(access: 'bad');
      when(client.oauthRefreshTokenGrant(any))
          .thenAnswer((_) => Completer<TokenResponse>().future);

      expect(await service.restoreSession(), isTrue);
      expect(service.decodedAccessToken?.sub, 'a');
    });

    test('a missing access token with a stored user id keeps the account known',
        () async {
      storeSession(access: null);
      when(client.oauthRefreshTokenGrant(any))
          .thenAnswer((_) async => _tokens('a'));

      expect(await service.restoreSession(), isTrue);
      expect(service.decodedAccessToken?.sub, 'a');
    });

    test('a refused background renewal deletes nothing and stops retrying', () {
      fakeAsync((fa) {
        storeSession(credentials: '{"data":"blob"}');
        when(client.oauthRefreshTokenGrant(any)).thenThrow(_deadLogin);
        final outcomes = <RefreshOutcome>[];
        service.refreshOutcomes.listen(outcomes.add);

        service.restoreSession();
        fa.flushMicrotasks();

        expect(outcomes, [RefreshOutcome.refused]);
        expect(storage.values['accessToken'], 'a:$_expired');
        expect(storage.values['refreshToken'], 'refresh-a');
        expect(storage.values['lastLoginCredentials'], '{"data":"blob"}');

        fa.elapse(const Duration(minutes: 30));
        verify(client.oauthRefreshTokenGrant(any)).called(1);
      });
    });
  });

  group('refreshNow', () {
    Future<void> restored({String? credentials, String? refresh = 'refresh-a'}) async {
      storeSession(access: 'a:$_tenDays', refresh: refresh, credentials: credentials);
      await service.restoreSession();
    }

    test('stores and publishes a new token, even when the old one is valid',
        () async {
      await restored();
      when(client.oauthRefreshTokenGrant('refresh-a'))
          .thenAnswer((_) async => _tokens('a'));
      final published = <String>[];
      service.accessTokenStream.listen(published.add);

      expect(await service.refreshNow(), RefreshOutcome.renewed);
      await pumpEventQueue();

      expect(published, ['a:$_tenDays']);
      verify(client.oauthRefreshTokenGrant('refresh-a')).called(1);
    });

    test('only invalid_grant from the token route is a refusal', () async {
      await restored(credentials: 'blob');
      when(client.oauthRefreshTokenGrant(any)).thenThrow(_deadLogin);

      expect(await service.refreshNow(), RefreshOutcome.refused);
      verifyNever(client.refreshTokenGrant(any));
    });

    for (final (name, error) in <(String, Object)>[
      ('no network', http.ClientException('no route')),
      ('a server fault', AuthServerException(503, 'down')),
      ('rate limiting', AuthServerException(429, 'slow down')),
      ('a 400 that is not JSON', AuthServerException(400, 'Failed')),
      ('a 400 with another error', AuthServerException(400, '{"error":"invalid_request"}')),
      ('a 401', AuthServerException(401, '{"error":"invalid_client"}')),
      ('a bad reply', const FormatException('html')),
    ]) {
      test('$name is unreachable and deletes nothing', () async {
        await restored();
        when(client.oauthRefreshTokenGrant(any)).thenThrow(error);

        expect(await service.refreshNow(), RefreshOutcome.unreachable);
        expect(storage.values['refreshToken'], 'refresh-a');
        expect(storage.values['accessToken'], 'a:$_tenDays');
      });
    }

    test('a stalled server answers unreachable within the budget', () {
      fakeAsync((fa) {
        storeSession(access: 'a:$_tenDays');
        service.restoreSession();
        fa.flushMicrotasks();
        when(client.oauthRefreshTokenGrant(any))
            .thenAnswer((_) => Completer<TokenResponse>().future);

        RefreshOutcome? outcome;
        service.refreshNow().then((o) => outcome = o);
        fa.elapse(AuthService.refreshBudget - const Duration(seconds: 1));
        expect(outcome, isNull);
        fa.elapse(const Duration(seconds: 1));
        expect(outcome, RefreshOutcome.unreachable);
      });
    });

    test('no refresh token uses the server-side route, whose 400 proves nothing',
        () async {
      await restored(refresh: null, credentials: 'blob');
      when(client.refreshTokenGrant(any))
          .thenThrow(AuthServerException(400, 'Failed'));

      expect(await service.refreshNow(), RefreshOutcome.noPath);
      expect(storage.values['lastLoginCredentials'], 'blob');
    });

    test('no credentials at all is no path', () async {
      await restored(refresh: null);
      expect(await service.refreshNow(), RefreshOutcome.noPath);
    });

    test('concurrent callers share one network call', () async {
      await restored();
      final reply = Completer<TokenResponse>();
      when(client.oauthRefreshTokenGrant(any)).thenAnswer((_) => reply.future);

      final first = service.refreshNow();
      final second = service.refreshNow();
      reply.complete(_tokens('a'));

      expect(await first, RefreshOutcome.renewed);
      expect(await second, RefreshOutcome.renewed);
      verify(client.oauthRefreshTokenGrant(any)).called(1);
    });

    test('a refresh that outlives a log out stores nothing', () async {
      await restored();
      final reply = Completer<TokenResponse>();
      when(client.oauthRefreshTokenGrant(any)).thenAnswer((_) => reply.future);

      final refresh = service.refreshNow();
      await service.logout();
      reply.complete(_tokens('a', refresh: 'late'));

      expect(await refresh, RefreshOutcome.superseded);
      expect(storage.values['accessToken'], isNull);
      expect(service.currentAccessToken, isNull);
    });

    test('a refusal that outlives a sign-in says nothing about the new session',
        () async {
      await restored();
      final reply = Completer<TokenResponse>();
      when(client.oauthRefreshTokenGrant(any)).thenAnswer((_) => reply.future);
      when(
        client.login(
          username: anyNamed('username'),
          password: anyNamed('password'),
          scope: anyNamed('scope'),
          lastLoginCredentials: anyNamed('lastLoginCredentials'),
        ),
      ).thenAnswer(
        (_) async => LoginResponse.fromJson({
          'access_token': 'b:$_tenDays',
          'refresh_token': 'refresh-b',
          'expires_in': _tenDays,
          'token_type': 'Bearer',
        }),
      );

      final refresh = service.refreshNow();
      await service.login('b@example.com', 'pw');
      reply.completeError(_deadLogin);

      expect(await refresh, RefreshOutcome.superseded);
      expect(storage.values['refreshToken'], 'refresh-b');
    });

    test('a refresh naming another account is discarded', () async {
      await restored();
      when(client.oauthRefreshTokenGrant(any))
          .thenAnswer((_) async => _tokens('b'));

      expect(await service.refreshNow(), RefreshOutcome.unreachable);
      expect(storage.values['accessToken'], 'a:$_tenDays');
    });
  });

  group('moving tokens by hand', () {
    test('a refresh running when the swap begins cannot overwrite it', () async {
      storeSession(access: 'a:$_tenDays');
      await service.restoreSession();
      final reply = Completer<TokenResponse>();
      when(client.oauthRefreshTokenGrant(any)).thenAnswer((_) => reply.future);

      final refresh = service.refreshNow();
      await service.beginSessionChange();
      storage.values['accessToken'] = 'b:$_tenDays';
      storage.values['refreshToken'] = 'refresh-b';
      storage.values['userID'] = 'b';
      reply.complete(_tokens('a', refresh: 'late'));

      expect(await refresh, RefreshOutcome.superseded);
      expect(storage.values['refreshToken'], 'refresh-b');
      await service.restoreSession();
      expect(service.decodedAccessToken?.sub, 'b');
    });

    test('tokens stored elsewhere are adopted, unchanged ones are not', () async {
      storeSession(access: 'a:$_tenDays');
      await service.restoreSession();

      expect(await service.adoptStoredSessionIfChanged(), isFalse);

      storage.values['accessToken'] = 'a:${_tenDays + 1}';
      expect(await service.adoptStoredSessionIfChanged(), isTrue);
      expect(service.currentAccessToken, 'a:${_tenDays + 1}');
    });

    test('the last outcome is remembered until the session changes', () async {
      storeSession(access: 'a:$_tenDays');
      await service.restoreSession();
      when(client.oauthRefreshTokenGrant(any)).thenThrow(_deadLogin);

      await service.refreshNow();
      expect(service.lastRefreshOutcome, RefreshOutcome.refused);

      await service.restoreSession();
      expect(service.lastRefreshOutcome, isNull);
    });
  });

  group('a sign-in replaces the whole slot', () {
    test('keys the new session lacks do not survive from the old account',
        () async {
      storeSession(access: 'a:$_tenDays', credentials: 'a-blob');
      storage.values['email'] = 'a@example.com';
      storage.values['idToken'] = 'a-id';
      await service.init();
      await service.restoreSession();
      when(google.getIdToken()).thenAnswer((_) async => 'google-id');
      when(
        client.googleIdpLogin(
          idToken: anyNamed('idToken'),
          identityProviderId: anyNamed('identityProviderId'),
        ),
      ).thenAnswer((_) async => _tokens('b', refresh: 'refresh-b'));

      expect(await service.initiateGoogleNativeLogin(), isA<SignInSucceeded>());

      expect(storage.values['accessToken'], 'b:$_tenDays');
      expect(storage.values['refreshToken'], 'refresh-b');
      expect(storage.values['userID'], 'b');
      expect(storage.values.containsKey('lastLoginCredentials'), isFalse);
      expect(storage.values.containsKey('idToken'), isFalse);
      expect(storage.values.containsKey('email'), isFalse);
      expect(service.lastLoginCredentials, isNull);
    });
  });

  group('backing out of a sign-in', () {
    test('a form attempt that returns afterwards stores nothing', () async {
      final reply = Completer<LoginResponse>();
      when(
        client.login(
          username: anyNamed('username'),
          password: anyNamed('password'),
          scope: anyNamed('scope'),
          lastLoginCredentials: anyNamed('lastLoginCredentials'),
        ),
      ).thenAnswer((_) => reply.future);

      final attempt = service.login('b@example.com', 'pw');
      service.cancelPendingSignIn();
      reply.complete(
        LoginResponse.fromJson({
          'access_token': 'b:$_tenDays',
          'expires_in': _tenDays,
          'token_type': 'Bearer',
        }),
      );

      expect(await attempt, isA<SignInCancelled>());
      expect(storage.values['accessToken'], isNull);
    });

    test('a stalled form attempt fails with a message instead of hanging', () {
      fakeAsync((fa) {
        when(
          client.login(
            username: anyNamed('username'),
            password: anyNamed('password'),
            scope: anyNamed('scope'),
            lastLoginCredentials: anyNamed('lastLoginCredentials'),
          ),
        ).thenAnswer((_) => Completer<LoginResponse>().future);

        SignInResult? result;
        service.login('b@example.com', 'pw').then((r) => result = r);
        fa.elapse(const Duration(seconds: 21));

        expect(result, isA<SignInFailed>());
      });
    });

    test('a browser redirect arriving after Not now is dropped', () async {
      when(
        native.login(
          authUri: anyNamed('authUri'),
          redirectUri: anyNamed('redirectUri'),
        ),
      ).thenAnswer((_) async => true);
      final handler =
          verify(native.setAuthRedirectHandler(captureAny)).captured.single
              as Future<void> Function(String);
      final results = <SignInResult>[];
      service.signInResults.listen(results.add);

      await service.initiateGoogleLogin();
      service.cancelPendingSignIn();
      await handler('https://example.com/callback?code=late');
      await pumpEventQueue();

      expect(results, isEmpty);
      verifyNever(client.exchangeAuthorizationCode(any, any));
      expect(storage.values['accessToken'], isNull);
    });

    test('a browser sign-in with nothing cancelled still lands', () async {
      storage.values['code_verifier'] = 'verifier';
      when(client.exchangeAuthorizationCode(any, any))
          .thenAnswer((_) async => _tokens('b', refresh: 'refresh-b'));
      final handler =
          verify(native.setAuthRedirectHandler(captureAny)).captured.single
              as Future<void> Function(String);

      await handler('https://example.com/callback?code=fresh');

      expect(storage.values['refreshToken'], 'refresh-b');
    });
  });
}
