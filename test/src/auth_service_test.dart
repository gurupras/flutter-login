import 'dart:async';
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
])
void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  group('AuthService', () {
    fakeAsync((async) {
      late MockFlutterSecureStorage mockSecureStorage;
      late MockClient mockHttpClient;
      late MockJwtDecoderWrapper mockJwtDecoder;
      late MockFusionAuthClient mockFusionAuthClient;
      late LoginConfig config;
      late AuthService authService;
      late MockMethodChannel mockMethodChannel;

      setUp(() {
        mockSecureStorage = MockFlutterSecureStorage();
        mockHttpClient = MockClient();
        mockJwtDecoder = MockJwtDecoderWrapper();
        mockFusionAuthClient = MockFusionAuthClient();
        mockMethodChannel = MockMethodChannel();

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
          mockSecureStorage.write(key: 'deviceID', value: anyNamed('value')),
        ).thenAnswer((_) async => {});

        await authService.init();
        async.elapse(Duration.zero); // Add this line

        verify(mockSecureStorage.read(key: 'deviceID')).called(1);
        verify(
          mockSecureStorage.write(key: 'deviceID', value: anyNamed('value')),
        ).called(1);
      });

      test('init reads existing device ID if present', () async {
        when(
          mockSecureStorage.read(key: 'deviceID'),
        ).thenAnswer((_) async => 'existing_device_id');

        await authService.init();
        async.elapse(Duration.zero); // Add this line

        verify(mockSecureStorage.read(key: 'deviceID')).called(1);
        verifyNever(
          mockSecureStorage.write(key: 'deviceID', value: anyNamed('value')),
        );
      });

      test(
        'login calls FusionAuthClient and stores tokens on success',
        () async {
          final tokenResponse = TokenResponse(
            accessToken: 'access',
            expiresIn: 3600,
            tokenType: 'Bearer',
            userID: 'user123',
            refreshToken: 'refresh',
          );
          when(
            mockFusionAuthClient.resourceOwnerPasswordCredentialsGrant(
              any,
              any,
            ),
          ).thenAnswer((_) async => tokenResponse);
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
            mockFusionAuthClient.resourceOwnerPasswordCredentialsGrant(
              'user',
              'pass',
            ),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'accessToken', value: 'access'),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'refreshToken', value: 'refresh'),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'userID', value: 'user123'),
          ).called(1);
        },
      );

      test('login returns false on FusionAuthClient error', () async {
        when(
          mockFusionAuthClient.resourceOwnerPasswordCredentialsGrant(any, any),
        ).thenThrow('Login failed');

        final result = await authService.login('user', 'pass');
        async.elapse(Duration.zero); // Add this line

        expect(result, isFalse);
        verify(
          mockFusionAuthClient.resourceOwnerPasswordCredentialsGrant(
            'user',
            'pass',
          ),
        ).called(1);
        verifyNever(
          mockSecureStorage.write(
            key: anyNamed('key'),
            value: anyNamed('value'),
          ),
        );
      });

      test('signUp calls http client and then login on success', () async {
        when(
          mockHttpClient.post(
            any,
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer((_) async => http.Response('', 200));
        final tokenResponse = TokenResponse(
          accessToken: 'access',
          expiresIn: 3600,
          tokenType: 'Bearer',
          userID: 'user123',
          refreshToken: 'refresh',
        );
        when(
          mockFusionAuthClient.resourceOwnerPasswordCredentialsGrant(any, any),
        ).thenAnswer((_) async => tokenResponse);
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
            Uri.parse('https://signup.example.com/login/signup'),
            headers: {'content-type': 'application/json'},
            body: '{"email":"newuser","password":"newpass"}',
          ),
        ).called(1);
        verify(
          mockFusionAuthClient.resourceOwnerPasswordCredentialsGrant(
            'newuser',
            'newpass',
          ),
        ).called(1);
      });

      test('signUp returns false if http client post fails', () async {
        when(
          mockHttpClient.post(
            any,
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer((_) async => http.Response('Error', 400));

        final result = await authService.signUp('newuser', 'newpass');
        async.elapse(Duration.zero); // Add this line

        expect(result, isFalse);
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

      test('recoverPassword returns true (placeholder)', () async {
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
            mockJwtDecoder.isExpired('valid_access_token'),
          ).thenReturn(false);

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
              mockSecureStorage.read(key: 'userID'),
            ).thenAnswer((_) async => 'user123');
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
              mockFusionAuthClient.refreshTokenGrant('valid_refresh_token'),
            ).thenAnswer((_) async => newTokenResponse);
            when(
              mockSecureStorage.write(
                key: anyNamed('key'),
                value: anyNamed('value'),
              ),
            ).thenAnswer((_) async => {});

            final result = await authService.checkLoginStatus();
            async.elapse(
              const Duration(hours: 1),
            ); // Elapse time for token refresh timer

            expect(result, isTrue);
            verify(mockSecureStorage.read(key: 'accessToken')).called(1);
            verify(mockJwtDecoder.isExpired('expired_access_token')).called(1);
            verify(
              mockFusionAuthClient.refreshTokenGrant('valid_refresh_token'),
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
              mockSecureStorage.read(key: 'userID'),
            ).thenAnswer((_) async => 'user123');
            when(
              mockJwtDecoder.isExpired('expired_access_token'),
            ).thenReturn(true);
            when(
              mockFusionAuthClient.refreshTokenGrant('invalid_refresh_token'),
            ).thenThrow('Refresh failed');
            when(
              mockSecureStorage.delete(key: anyNamed('key')),
            ).thenAnswer((_) async => {});

            final result = await authService.checkLoginStatus();
            async.elapse(Duration.zero); // Add this line

            expect(result, isFalse);
            verify(mockSecureStorage.read(key: 'accessToken')).called(1);
            verify(mockJwtDecoder.isExpired('expired_access_token')).called(1);
            verify(
              mockFusionAuthClient.refreshTokenGrant('invalid_refresh_token'),
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

          final result = await authService.checkLoginStatus();
          async.elapse(Duration.zero); // Add this line

          expect(result, isFalse);
          verify(mockSecureStorage.read(key: 'accessToken')).called(1);
          verifyNever(mockJwtDecoder.isExpired(any));
          verifyNever(mockFusionAuthClient.refreshTokenGrant(any));
        });
      });

      group('initiateGoogleLogin', () {
        test('initiates Google login successfully', () async {
          when(
            mockSecureStorage.write(
              key: 'code_verifier',
              value: anyNamed('value'),
            ),
          ).thenAnswer((_) async => {});

          final result = await authService.initiateGoogleLogin();
          async.elapse(Duration.zero); // Add this line

          expect(result, isTrue);
          verify(
            mockSecureStorage.write(
              key: 'code_verifier',
              value: anyNamed('value'),
            ),
          ).called(1);
        });

        test('returns false if url_launcher fails to launch', () async {
          // Override the global mock for this specific test to simulate failure
          TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
              .setMockMethodCallHandler(
                const MethodChannel('plugins.flutter.io/url_launcher'),
                (MethodCall methodCall) async {
                  if (methodCall.method == 'canLaunch') {
                    return false; // Simulate canLaunchUrl returning false
                  }
                  return null;
                },
              );

          final result = await authService.initiateGoogleLogin();
          async.elapse(Duration.zero); // Add this line

          expect(result, isFalse);
          verify(
            mockSecureStorage.write(
              key: 'code_verifier',
              value: anyNamed('value'),
            ),
          ).called(1); // Still called, but launch fails
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
        final codeVerifier = 'test_code_verifier';
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

          authService.codeVerifier = 'mock_code_verifier';
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

          // Simulate the MethodChannel call that triggers _processAuthRedirect
          await TestDefaultBinaryMessengerBinding
              .instance
              .defaultBinaryMessenger
              .handlePlatformMessage(
                'me.gurupras.liblogin',
                const StandardMethodCodec().encodeMethodCall(
                  MethodCall('handleAuthRedirect', uri.toString()),
                ),
                (ByteData? data) {},
              );

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

          await TestDefaultBinaryMessengerBinding
              .instance
              .defaultBinaryMessenger
              .handlePlatformMessage(
                'me.gurupras.liblogin',
                const StandardMethodCodec().encodeMethodCall(
                  MethodCall('handleAuthRedirect', uri.toString()),
                ),
                (ByteData? data) {},
              );
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

            authService.codeVerifier = 'mock_code_verifier';
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

            await TestDefaultBinaryMessengerBinding
                .instance
                .defaultBinaryMessenger
                .handlePlatformMessage(
                  'me.gurupras.liblogin',
                  const StandardMethodCodec().encodeMethodCall(
                    MethodCall('handleAuthRedirect', uri.toString()),
                  ),
                  (ByteData? data) {},
                );
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
