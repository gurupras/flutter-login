import 'dart:async';
import 'dart:convert';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:liblogin/src/auth_service.dart';
import 'package:liblogin/src/fusionauth_client.dart';
import 'package:liblogin/src/login_config.dart';
import 'package:liblogin/src/auth_models.dart';
import 'package:liblogin_native/liblogin_native.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:fake_async/fake_async.dart';

import 'auth_service_test.mocks.dart';

// Mock the url_launcher functions
class MockUrlLauncher {
  Future<bool> canLaunch(String url) => Future.value(true);
  Future<bool> launch(String url, {LaunchMode? mode}) => Future.value(true);
}

@GenerateMocks([
  FlutterSecureStorage,
  http.Client,
  JwtDecoderWrapper,
  FusionAuthClient,
  MethodChannel,
  LibloginNative,
])
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  group('AuthService', () {
    fakeAsync((async) {
      late MockFlutterSecureStorage mockSecureStorage;
      late MockClient mockHttpClient;
      late MockJwtDecoderWrapper mockJwtDecoder;
      late MockFusionAuthClient mockFusionAuthClient;
      late MockLibloginNative mockLibloginNative;
      late LoginConfig config;
      late AuthService authService;

      setUp(() {
        mockSecureStorage = MockFlutterSecureStorage();
        mockHttpClient = MockClient();
        mockJwtDecoder = MockJwtDecoderWrapper();
        mockFusionAuthClient = MockFusionAuthClient();
        mockLibloginNative = MockLibloginNative();

        config = LoginConfig(
          loginDomain: 'example.com',
          signupOrigin: 'https://signup.example.com',
          loginTenantID: 'some-tenant-id',
          loginClientID: 'some-client-id',
          loginRedirectURI: 'https://example.com/callback',
          googleIdentityProviderID: 'google-idp',
        );

        // Add default stubs for JwtDecoderWrapper
        when(mockJwtDecoder.decode(any)).thenReturn({
          'exp':
              DateTime.now()
                  .add(const Duration(hours: 1))
                  .millisecondsSinceEpoch ~/
              1000, // Future expiration
        });
        when(
          mockJwtDecoder.isExpired(any),
        ).thenReturn(false); // Not expired by default

        // Mock LibloginNative
        when(
          mockLibloginNative.setAuthRedirectHandler(any),
        ).thenAnswer((_) async => {});

        // Mock the MethodChannel constructor for liblogin
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(
              const MethodChannel('me.gurupras.liblogin'),
              (MethodCall methodCall) async {
                if (methodCall.method == 'handleAuthRedirect') {
                  // Simulate a redirect
                  return null;
                }
                return null;
              },
            );

        // Mock canLaunchUrl and launchUrl for url_launcher
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(
              const MethodChannel('plugins.flutter.io/url_launcher'),
              (MethodCall methodCall) async {
                if (methodCall.method == 'canLaunch') {
                  return true;
                }
                if (methodCall.method == 'launch') {
                  return true;
                }
                return null;
              },
            );

        authService = AuthService(
          config: config,
          secureStorage: mockSecureStorage,
          httpClient: mockHttpClient,
          jwtDecoder: mockJwtDecoder,
          fusionAuthClient: mockFusionAuthClient,
          libloginNative: mockLibloginNative,
        );
      });

      tearDown(() {
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(
              const MethodChannel('me.gurupras.liblogin'),
              null,
            );
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(
              const MethodChannel('plugins.flutter.io/url_launcher'),
              null,
            );
      });

      test('init generates and stores device ID if not present', () async {
        when(
          mockSecureStorage.read(key: 'deviceID'),
        ).thenAnswer((_) async => null);
        when(
          mockSecureStorage.read(key: 'lastLoginCredentials'),
        ).thenAnswer((_) async => null);
        when(
          mockSecureStorage.write(key: 'deviceID', value: anyNamed('value')),
        ).thenAnswer((_) async => {});

        await authService.init();
        async.elapse(Duration.zero); // Add this line

        verify(mockSecureStorage.read(key: 'deviceID')).called(1);
        verify(mockSecureStorage.read(key: 'lastLoginCredentials')).called(1);
        verify(
          mockSecureStorage.write(key: 'deviceID', value: anyNamed('value')),
        ).called(1);
      });

      test('init reads existing device ID if present', () async {
        when(
          mockSecureStorage.read(key: 'deviceID'),
        ).thenAnswer((_) async => 'existing_device_id');
        when(
          mockSecureStorage.read(key: 'lastLoginCredentials'),
        ).thenAnswer((_) async => null);

        await authService.init();
        async.elapse(Duration.zero); // Add this line

        verify(mockSecureStorage.read(key: 'deviceID')).called(1);
        verify(mockSecureStorage.read(key: 'lastLoginCredentials')).called(1);
        verifyNever(
          mockSecureStorage.write(key: 'deviceID', value: anyNamed('value')),
        );
      });

      test(
        'login calls FusionAuthClient.login and stores tokens on success',
        () async {
          final loginResponse = LoginResponse(
            accessToken: 'access',
            refreshToken: 'refresh',
            lastLoginCredentials: 'last',
            user: {'id': 'user123'},
          );
          when(
            mockFusionAuthClient.login(
              username: anyNamed('username'),
              password: anyNamed('password'),
              scope: anyNamed('scope'),
              lastLoginCredentials: anyNamed('lastLoginCredentials'),
              device: anyNamed('device'),
            ),
          ).thenAnswer((_) async => loginResponse);
          when(mockJwtDecoder.decode('access')).thenReturn({
            'sub': 'user123',
            'exp': (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600,
          });
          when(
            mockSecureStorage.write(
              key: anyNamed('key'),
              value: anyNamed('value'),
            ),
          ).thenAnswer((_) async => {});

          final result = await authService.login('user', 'pass');
          async.elapse(
            const Duration(hours: 1),
          ); // Elapse time for token refresh timer

          expect(result, isTrue);
          verify(
            mockFusionAuthClient.login(
              username: 'user',
              password: 'pass',
              scope: 'openid email offline_access',
              lastLoginCredentials: null,
            ),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'accessToken', value: 'access'),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'refreshToken', value: 'refresh'),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'lastLoginCredentials', value: 'last'),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'userID', value: 'user123'),
          ).called(1);
        },
      );

      test('login throws on FusionAuthClient.login error', () async {
        const errorMessage = 'Login failed';
        when(
          mockFusionAuthClient.login(
            username: anyNamed('username'),
            password: anyNamed('password'),
            scope: anyNamed('scope'),
            lastLoginCredentials: anyNamed('lastLoginCredentials'),
            device: anyNamed('device'),
          ),
        ).thenThrow(errorMessage);

        expect(
          () => authService.login('user', 'pass'),
          throwsA(errorMessage),
        );
        async.elapse(Duration.zero); // Add this line

        verify(
          mockFusionAuthClient.login(
            username: 'user',
            password: 'pass',
            scope: 'openid email offline_access',
            lastLoginCredentials: null,
          ),
        ).called(1);
        verifyNever(
          mockSecureStorage.write(
            key: anyNamed('key'),
            value: anyNamed('value'),
          ),
        );
      });

      test('login throws descriptive message from backend', () async {
        const backendMessage = 'Invalid credentials';
        final errorResponse = json.encode({'message': backendMessage});
        when(
          mockFusionAuthClient.login(
            username: anyNamed('username'),
            password: anyNamed('password'),
            scope: anyNamed('scope'),
            lastLoginCredentials: anyNamed('lastLoginCredentials'),
            device: anyNamed('device'),
          ),
        ).thenThrow(errorResponse);

        expect(
          () => authService.login('user', 'pass'),
          throwsA(backendMessage),
        );
        async.elapse(Duration.zero);
      });

      test('signUp calls http client and then login on success', () async {
        when(
          mockHttpClient.post(
            any,
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer((_) async => http.Response('', 200));
        final loginResponse = LoginResponse(
          accessToken: 'access',
          refreshToken: 'refresh',
          lastLoginCredentials: 'last',
          user: {'id': 'user123'},
        );
        when(
          mockFusionAuthClient.login(
            username: anyNamed('username'),
            password: anyNamed('password'),
            scope: anyNamed('scope'),
            lastLoginCredentials: anyNamed('lastLoginCredentials'),
            device: anyNamed('device'),
          ),
        ).thenAnswer((_) async => loginResponse);
        when(mockJwtDecoder.decode('access')).thenReturn({
          'sub': 'user123',
          'exp': (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600,
        });
        when(
          mockSecureStorage.write(
            key: anyNamed('key'),
            value: anyNamed('value'),
          ),
        ).thenAnswer((_) async => {});

        final result = await authService.signUp('newuser', 'newpass');
        async.elapse(
          const Duration(hours: 1),
        ); // Elapse time for token refresh timer

        expect(result, isTrue);
        verify(
          mockHttpClient.post(
            Uri.parse('https://signup.example.com/login/register'),
            headers: {'content-type': 'application/json'},
            body: '{"email":"newuser","password":"newpass"}',
          ),
        ).called(1);
        verify(
          mockFusionAuthClient.login(
            username: 'newuser',
            password: 'newpass',
            scope: 'openid email offline_access',
            lastLoginCredentials: null,
          ),
        ).called(1);
      });

      test('signUp throws if http client post fails', () async {
        when(
          mockHttpClient.post(
            any,
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer((_) async => http.Response('Error', 400));

        expect(
          () => authService.signUp('newuser', 'newpass'),
          throwsA(anything),
        );
        async.elapse(Duration.zero); // Add this line

        verify(
          mockHttpClient.post(
            any,
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).called(1);
        verifyNever(
          mockFusionAuthClient.resourceOwnerPasswordCredentialsGrant(any, any),
        );
      });

      test(
        'signUp throws verification message when registration succeeds but login fails',
        () async {
          const verificationMessage =
              'Please verify your email ID before logging in.';
          when(
            mockHttpClient.post(
              any,
              headers: anyNamed('headers'),
              body: anyNamed('body'),
            ),
          ).thenAnswer(
            (_) async =>
                http.Response(json.encode({'message': verificationMessage}), 200),
          );

          when(
            mockFusionAuthClient.login(
              username: anyNamed('username'),
              password: anyNamed('password'),
              scope: anyNamed('scope'),
              lastLoginCredentials: anyNamed('lastLoginCredentials'),
              device: anyNamed('device'),
            ),
          ).thenThrow(json.encode({'message': 'User is not verified'}));

          expect(
            () => authService.signUp('test@example.com', 'password'),
            throwsA(verificationMessage),
          );
          async.elapse(Duration.zero);
        },
      );

      test('recoverPassword returns true (placeholder)', () async {
        when(
          mockHttpClient.post(
            Uri.parse('https://signup.example.com/login/forgot-password'),
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer((_) async => http.Response('', 200));

        final result = await authService.recoverPassword('email@example.com');
        async.elapse(Duration.zero); // Add this line
        expect(result, isTrue);
      });

      test('logout clears stored tokens', () async {
        when(
          mockSecureStorage.delete(key: anyNamed('key')),
        ).thenAnswer((_) async => {});

        await authService.logout();
        async.elapse(Duration.zero); // Add this line

        verify(mockSecureStorage.delete(key: 'accessToken')).called(1);
        verify(mockSecureStorage.delete(key: 'refreshToken')).called(1);
        verify(mockSecureStorage.delete(key: 'userID')).called(1);
        verify(mockSecureStorage.delete(key: 'lastLoginCredentials')).called(1);
      });

      group('checkLoginStatus', () {
        test('returns true if access token is valid and not expired', () async {
          when(
            mockSecureStorage.read(key: 'accessToken'),
          ).thenAnswer((_) async => 'valid_access_token');
          when(
            mockSecureStorage.read(key: 'refreshToken'),
          ).thenAnswer((_) async => 'valid_refresh_token');
          when(
            mockSecureStorage.read(key: 'userID'),
          ).thenAnswer((_) async => 'user123');
          when(
            mockSecureStorage.read(key: 'deviceID'),
          ).thenAnswer((_) async => 'device-id');
          when(
            mockSecureStorage.read(key: 'lastLoginCredentials'),
          ).thenAnswer((_) async => null);
          when(
            mockJwtDecoder.isExpired('valid_access_token'),
          ).thenReturn(false);

          await authService.init();
          final result = await authService.checkLoginStatus();
          async.elapse(
            const Duration(hours: 1),
          ); // Elapse time for token refresh timer

          expect(result, isTrue);
          verify(mockSecureStorage.read(key: 'accessToken')).called(1);
          verify(mockJwtDecoder.isExpired('valid_access_token')).called(1);
          verifyNever(mockFusionAuthClient.refreshTokenGrant(any));
        });

        test(
          'returns true if access token is expired but refresh token is valid and refreshes',
          () async {
            when(
              mockSecureStorage.read(key: 'accessToken'),
            ).thenAnswer((_) async => 'expired_access_token');
            when(
              mockSecureStorage.read(key: 'refreshToken'),
            ).thenAnswer((_) async => 'valid_refresh_token');
            when(
              mockSecureStorage.read(key: 'lastLoginCredentials'),
            ).thenAnswer((_) async => 'valid_last_login_credentials');
            when(
              mockSecureStorage.read(key: 'userID'),
            ).thenAnswer((_) async => 'user123');
            when(
              mockSecureStorage.read(key: 'deviceID'),
            ).thenAnswer((_) async => 'device-id');
            when(
              mockJwtDecoder.isExpired('expired_access_token'),
            ).thenReturn(true);

            final newTokenResponse = TokenResponse(
              accessToken: 'new_access',
              expiresIn: 3600,
              tokenType: 'Bearer',
              userID: 'user123',
              refreshToken: 'new_refresh',
            );
            when(
              mockFusionAuthClient.refreshTokenGrant(
                'valid_last_login_credentials',
              ),
            ).thenAnswer((_) async => newTokenResponse);
            when(
              mockSecureStorage.write(
                key: anyNamed('key'),
                value: anyNamed('value'),
              ),
            ).thenAnswer((_) async => {});

            await authService.init();
            final result = await authService.checkLoginStatus();
            async.elapse(
              const Duration(hours: 1),
            ); // Elapse time for token refresh timer

            expect(result, isTrue);
            verify(mockSecureStorage.read(key: 'accessToken')).called(1);
            verify(mockJwtDecoder.isExpired('expired_access_token')).called(1);
            verify(
              mockFusionAuthClient.refreshTokenGrant(
                'valid_last_login_credentials',
              ),
            ).called(1);
            verify(
              mockSecureStorage.write(key: 'accessToken', value: 'new_access'),
            ).called(1);
            verify(
              mockSecureStorage.write(
                key: 'refreshToken',
                value: 'new_refresh',
              ),
            ).called(1);
          },
        );

        test(
          'returns false if both access and refresh tokens are invalid',
          () async {
            when(
              mockSecureStorage.read(key: 'accessToken'),
            ).thenAnswer((_) async => 'expired_access_token');
            when(
              mockSecureStorage.read(key: 'refreshToken'),
            ).thenAnswer((_) async => 'invalid_refresh_token');
            when(
              mockSecureStorage.read(key: 'lastLoginCredentials'),
            ).thenAnswer((_) async => 'valid_last_login_credentials');
            when(
              mockSecureStorage.read(key: 'userID'),
            ).thenAnswer((_) async => 'user123');
            when(
              mockSecureStorage.read(key: 'deviceID'),
            ).thenAnswer((_) async => 'device-id');
            when(
              mockJwtDecoder.isExpired('expired_access_token'),
            ).thenReturn(true);
            when(
              mockFusionAuthClient.refreshTokenGrant(
                'valid_last_login_credentials',
              ),
            ).thenThrow('Refresh failed');
            when(
              mockSecureStorage.delete(key: anyNamed('key')),
            ).thenAnswer((_) async => {});

            await authService.init();
            final result = await authService.checkLoginStatus();
            async.elapse(Duration.zero); // Add this line

            expect(result, isFalse);
            verify(mockSecureStorage.read(key: 'accessToken')).called(1);
            verify(mockJwtDecoder.isExpired('expired_access_token')).called(1);
            verify(
              mockFusionAuthClient.refreshTokenGrant(
                'valid_last_login_credentials',
              ),
            ).called(1);
            verify(mockSecureStorage.delete(key: 'accessToken')).called(1);
            verify(mockSecureStorage.delete(key: 'refreshToken')).called(1);
            verify(mockSecureStorage.delete(key: 'userID')).called(1);
          },
        );

        test('returns false if no tokens are present', () async {
          when(
            mockSecureStorage.read(key: 'accessToken'),
          ).thenAnswer((_) async => null);
          when(
            mockSecureStorage.read(key: 'refreshToken'),
          ).thenAnswer((_) async => null);
          when(
            mockSecureStorage.read(key: 'userID'),
          ).thenAnswer((_) async => null);
          when(
            mockSecureStorage.read(key: 'deviceID'),
          ).thenAnswer((_) async => 'device-id');
          when(
            mockSecureStorage.read(key: 'lastLoginCredentials'),
          ).thenAnswer((_) async => null);

          await authService.init();
          final result = await authService.checkLoginStatus();
          async.elapse(Duration.zero); // Add this line

          expect(result, isFalse);
          verify(mockSecureStorage.read(key: 'accessToken')).called(1);
          verifyNever(mockJwtDecoder.isExpired(any));
          verifyNever(mockFusionAuthClient.refreshTokenGrant(any));
        });

        test(
          'decodedAccessToken returns decoded token when accessToken is set',
          () async {
            final tokenData = {
              'aud': '2f65e5e0-aa9f-4ec2-9e84-a8032dc229d7',
              'exp': 1768323069,
              'iat': 1767459069,
              'iss': 'planda.day',
              'sub': 'ffbd1747-e5a9-4300-adc2-c35443be0bfe',
              'jti': 'a8cffe4b-3d57-4d7b-b24c-eb8f7d9f17d9',
              'authenticationType': 'GOOGLE',
              'applicationId': '2f65e5e0-aa9f-4ec2-9e84-a8032dc229d7',
              'roles': <String>[],
              'sid': '54289f9c-9073-4283-a9b0-68021eae1ba3',
              'auth_time': 1767459069,
              'tid': '676c7011-741e-4145-bcb8-b8bd12ba1ee3',
            };

            when(
              mockSecureStorage.read(key: 'accessToken'),
            ).thenAnswer((_) async => 'mock_access_token');
            when(
              mockSecureStorage.read(key: 'refreshToken'),
            ).thenAnswer((_) async => 'mock_refresh_token');
            when(
              mockSecureStorage.read(key: 'userID'),
            ).thenAnswer((_) async => 'user123');
            when(
              mockSecureStorage.read(key: 'deviceID'),
            ).thenAnswer((_) async => 'device-id');
            when(
              mockSecureStorage.read(key: 'lastLoginCredentials'),
            ).thenAnswer((_) async => null);
            when(
              mockJwtDecoder.isExpired('mock_access_token'),
            ).thenReturn(false);
            when(
              mockJwtDecoder.decode('mock_access_token'),
            ).thenReturn(tokenData);

            await authService.init();
            await authService.checkLoginStatus();
            async.elapse(Duration.zero);

            final decoded = authService.decodedAccessToken;
            expect(decoded, isNotNull);
            expect(decoded!.sub, 'ffbd1747-e5a9-4300-adc2-c35443be0bfe');
            expect(decoded.aud, '2f65e5e0-aa9f-4ec2-9e84-a8032dc229d7');
            expect(decoded.authenticationType, 'GOOGLE');
          },
        );

        test(
          'decodedAccessToken returns null when accessToken is not set',
          () async {
            expect(authService.decodedAccessToken, isNull);
          },
        );
      });

      group('initiateGoogleLogin', () {
        test('initiates Google login successfully', () async {
          when(
            mockSecureStorage.write(
              key: 'code_verifier',
              value: anyNamed('value'),
            ),
          ).thenAnswer((_) async => {});
          when(
            mockLibloginNative.login(
              authUri: anyNamed('authUri'),
              redirectUri: anyNamed('redirectUri'),
            ),
          ).thenAnswer((_) async => true);

          final result = await authService.initiateGoogleLogin();
          async.elapse(Duration.zero); // Add this line

          expect(result, isTrue);
          verify(
            mockSecureStorage.write(
              key: 'code_verifier',
              value: anyNamed('value'),
            ),
          ).called(1);
          verify(
            mockLibloginNative.login(
              authUri: anyNamed('authUri'),
              redirectUri: config.loginRedirectURI,
            ),
          ).called(1);
        });

        test('returns false if LibloginNative fails to launch', () async {
          when(
            mockSecureStorage.write(
              key: 'code_verifier',
              value: anyNamed('value'),
            ),
          ).thenAnswer((_) async => {});
          when(
            mockLibloginNative.login(
              authUri: anyNamed('authUri'),
              redirectUri: anyNamed('redirectUri'),
            ),
          ).thenAnswer((_) async => false);

          final result = await authService.initiateGoogleLogin();
          async.elapse(Duration.zero); // Add this line

          expect(result, isFalse);
          verify(
            mockSecureStorage.write(
              key: 'code_verifier',
              value: anyNamed('value'),
            ),
          ).called(1);
          verify(
            mockLibloginNative.login(
              authUri: anyNamed('authUri'),
              redirectUri: config.loginRedirectURI,
            ),
          ).called(1);
        });
      });

      test('_generateCodeVerifier generates a non-empty string', () {
        final codeVerifier = AuthService.generateCodeVerifier();
        async.elapse(Duration.zero); // Add this line
        expect(codeVerifier, isNotEmpty);
        expect(
          codeVerifier.length,
          greaterThanOrEqualTo(43),
        ); // PKCE verifier length
      });

      test('_generateCodeChallenge generates a non-empty string', () {
        const codeVerifier = 'test_code_verifier';
        final codeChallenge = AuthService.generateCodeChallenge(codeVerifier);
        async.elapse(Duration.zero); // Add this line
        expect(codeChallenge, isNotEmpty);
        expect(codeChallenge.length, 43); // PKCE challenge length
      });

      group('_processAuthRedirect', () {
        test('processes redirect with code successfully', () async {
          final uri = Uri.parse('https://example.com/callback?code=auth_code');
          final tokenResponse = TokenResponse(
            accessToken: 'access',
            expiresIn: 3600,
            tokenType: 'Bearer',
            userID: 'user123',
            refreshToken: 'refresh',
          );

          when(
            mockSecureStorage.read(key: 'code_verifier'),
          ).thenAnswer((_) async => 'mock_code_verifier');
          when(
            mockFusionAuthClient.exchangeAuthorizationCode(
              'auth_code',
              'mock_code_verifier',
            ),
          ).thenAnswer((_) async => tokenResponse);
          when(
            mockSecureStorage.write(
              key: anyNamed('key'),
              value: anyNamed('value'),
            ),
          ).thenAnswer((_) async => {});

          final completer = Completer<bool>();
          authService.authRedirectStream.listen((success) {
            completer.complete(success);
          });

          // Capture the handler
          final verifyResult = verify(
            mockLibloginNative.setAuthRedirectHandler(captureAny),
          );
          final handler = verifyResult.captured.single as Function(String);

          // Trigger the handler
          handler(uri.toString());

          async.flushMicrotasks(); // Ensure microtasks are run
          async.elapse(
            const Duration(hours: 1),
          ); // Elapse enough time for the timer

          expect(await completer.future, isTrue);
          verify(
            mockFusionAuthClient.exchangeAuthorizationCode(
              'auth_code',
              'mock_code_verifier',
            ),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'accessToken', value: 'access'),
          ).called(1);
        });

        test('does not process redirect if code is missing', () async {
          final uri = Uri.parse('https://example.com/callback');

          final completer = Completer<bool>();
          authService.authRedirectStream.listen((success) {
            completer.complete(success);
          });

          // Capture the handler
          final verifyResult = verify(
            mockLibloginNative.setAuthRedirectHandler(captureAny),
          );
          final handler = verifyResult.captured.single as Function(String);

          // Trigger the handler
          handler(uri.toString());

          async.flushMicrotasks();
          async.elapse(Duration.zero); // Add this line

          expect(await completer.future, isFalse);
          verifyNever(mockFusionAuthClient.exchangeAuthorizationCode(any, any));
          verifyNever(
            mockSecureStorage.write(
              key: anyNamed('key'),
              value: anyNamed('value'),
            ),
          );
        });

        test(
          'emits false on authRedirectStream if token exchange fails',
          () async {
            final uri = Uri.parse(
              'https://example.com/callback?code=auth_code',
            );

            when(
              mockSecureStorage.read(key: 'code_verifier'),
            ).thenAnswer((_) async => 'mock_code_verifier');
            when(
              mockFusionAuthClient.exchangeAuthorizationCode(
                'auth_code',
                'mock_code_verifier',
              ),
            ).thenThrow('Exchange failed');

            final completer = Completer<bool>();
            authService.authRedirectStream.listen((success) {
              completer.complete(success);
            });

            // Capture the handler
            final verifyResult = verify(
              mockLibloginNative.setAuthRedirectHandler(captureAny),
            );
            final handler = verifyResult.captured.single as Function(String);

            // Trigger the handler
            handler(uri.toString());

            async.flushMicrotasks();
            async.elapse(Duration.zero); // Add this line

            expect(await completer.future, isFalse);
            verify(
              mockFusionAuthClient.exchangeAuthorizationCode(
                'auth_code',
                'mock_code_verifier',
              ),
            ).called(1);
            verifyNever(
              mockSecureStorage.write(
                key: anyNamed('key'),
                value: anyNamed('value'),
              ),
            );
          },
        );
      });
    });
  });
}
