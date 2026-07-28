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
import 'package:google_sign_in/google_sign_in.dart';
import 'package:sign_in_with_apple/sign_in_with_apple.dart';
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
  AppleSignInWrapper,
  GoogleSignInWrapper,
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
      late MockAppleSignInWrapper mockAppleSignIn;
      late MockGoogleSignInWrapper mockGoogleSignIn;
      late LoginConfig config;
      late AuthService authService;

      setUp(() {
        mockSecureStorage = MockFlutterSecureStorage();
        mockHttpClient = MockClient();
        mockJwtDecoder = MockJwtDecoderWrapper();
        mockFusionAuthClient = MockFusionAuthClient();
        mockLibloginNative = MockLibloginNative();
        mockAppleSignIn = MockAppleSignInWrapper();
        mockGoogleSignIn = MockGoogleSignInWrapper();

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

        when(
          mockSecureStorage.read(key: 'idToken'),
        ).thenAnswer((_) async => null);

        authService = AuthService(
          config: config,
          secureStorage: mockSecureStorage,
          httpClient: mockHttpClient,
          jwtDecoder: mockJwtDecoder,
          fusionAuthClient: mockFusionAuthClient,
          libloginNative: mockLibloginNative,
          appleSignIn: mockAppleSignIn,
          googleSignIn: mockGoogleSignIn,
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
            idToken: 'id_token',
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
          expect(authService.currentIdToken, 'id_token');
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
            mockSecureStorage.write(key: 'idToken', value: 'id_token'),
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
            body: '{"email":"newuser","password":"newpass","clientID":"some-client-id"}',
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
        verify(mockSecureStorage.delete(key: 'idToken')).called(1);
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
          'server-side refresh: the ROTATED lastLoginCredentials is adopted + '
          'persisted (regression: refresh_token_not_found on 2nd refresh)',
          () async {
            // No OAuth refresh token → the server-side /login/refresh-tokens
            // (lastLoginCredentials) path is used.
            when(mockSecureStorage.read(key: 'accessToken'))
                .thenAnswer((_) async => 'expired_access_token');
            when(mockSecureStorage.read(key: 'refreshToken'))
                .thenAnswer((_) async => null);
            when(mockSecureStorage.read(key: 'lastLoginCredentials'))
                .thenAnswer((_) async => 'old_llc');
            when(mockSecureStorage.read(key: 'userID'))
                .thenAnswer((_) async => 'user123');
            when(mockSecureStorage.read(key: 'deviceID'))
                .thenAnswer((_) async => 'device-id');
            when(mockJwtDecoder.isExpired('expired_access_token'))
                .thenReturn(true);

            final rotated = TokenResponse(
              accessToken: 'new_access',
              expiresIn: 3600,
              tokenType: 'Bearer',
              userID: 'user123',
              refreshToken: null, // server path omits the OAuth refresh token
              lastLoginCredentials: 'NEW_llc', // ROTATED — must be used next time
            );
            when(mockFusionAuthClient.refreshTokenGrant('old_llc'))
                .thenAnswer((_) async => rotated);
            when(mockSecureStorage.write(
              key: anyNamed('key'),
              value: anyNamed('value'),
            )).thenAnswer((_) async => {});

            await authService.init();
            final result = await authService.checkLoginStatus();
            async.elapse(const Duration(hours: 1));

            expect(result, isTrue);
            verify(mockFusionAuthClient.refreshTokenGrant('old_llc')).called(1);
            // The rotated credential must be adopted in memory AND persisted so
            // the NEXT refresh doesn't re-send the consumed 'old_llc'.
            expect(authService.lastLoginCredentials, 'NEW_llc');
            verify(mockSecureStorage.write(
              key: 'lastLoginCredentials',
              value: 'NEW_llc',
            )).called(1);
          },
        );

        test(
          'returns true if access token is expired and refreshes via OAuth refresh token',
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
              mockFusionAuthClient.oauthRefreshTokenGrant('valid_refresh_token'),
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
              mockFusionAuthClient.oauthRefreshTokenGrant('valid_refresh_token'),
            ).called(1);
            verifyNever(mockFusionAuthClient.refreshTokenGrant(any));
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
          'returns true for Google OAuth cold restart: uses refresh token when no lastLoginCredentials',
          () async {
            when(
              mockSecureStorage.read(key: 'accessToken'),
            ).thenAnswer((_) async => 'expired_access_token');
            when(
              mockSecureStorage.read(key: 'refreshToken'),
            ).thenAnswer((_) async => 'google_refresh_token');
            when(
              mockSecureStorage.read(key: 'lastLoginCredentials'),
            ).thenAnswer((_) async => null);
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
              refreshToken: 'new_google_refresh',
            );
            when(
              mockFusionAuthClient.oauthRefreshTokenGrant('google_refresh_token'),
            ).thenAnswer((_) async => newTokenResponse);
            when(
              mockSecureStorage.write(
                key: anyNamed('key'),
                value: anyNamed('value'),
              ),
            ).thenAnswer((_) async => {});

            await authService.init();
            final result = await authService.checkLoginStatus();
            async.elapse(const Duration(hours: 1));

            expect(result, isTrue);
            verify(
              mockFusionAuthClient.oauthRefreshTokenGrant('google_refresh_token'),
            ).called(1);
            verifyNever(mockFusionAuthClient.refreshTokenGrant(any));
            verify(
              mockSecureStorage.write(key: 'accessToken', value: 'new_access'),
            ).called(1);
          },
        );

        test(
          'falls back to lastLoginCredentials when OAuth refresh token grant fails',
          () async {
            when(
              mockSecureStorage.read(key: 'accessToken'),
            ).thenAnswer((_) async => 'expired_access_token');
            when(
              mockSecureStorage.read(key: 'refreshToken'),
            ).thenAnswer((_) async => 'stale_refresh_token');
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
              mockFusionAuthClient.oauthRefreshTokenGrant('stale_refresh_token'),
            ).thenThrow('Refresh token expired');
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
            async.elapse(const Duration(hours: 1));

            expect(result, isTrue);
            verify(
              mockFusionAuthClient.oauthRefreshTokenGrant('stale_refresh_token'),
            ).called(1);
            verify(
              mockFusionAuthClient.refreshTokenGrant(
                'valid_last_login_credentials',
              ),
            ).called(1);
            verify(
              mockSecureStorage.write(key: 'accessToken', value: 'new_access'),
            ).called(1);
          },
        );

        test(
          'returns false if all refresh attempts fail',
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
              mockFusionAuthClient.oauthRefreshTokenGrant('invalid_refresh_token'),
            ).thenThrow('Refresh token invalid');
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
            async.elapse(Duration.zero);

            expect(result, isFalse);
            verify(mockSecureStorage.read(key: 'accessToken')).called(1);
            verify(mockJwtDecoder.isExpired('expired_access_token')).called(1);
            verify(
              mockFusionAuthClient.oauthRefreshTokenGrant('invalid_refresh_token'),
            ).called(1);
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

        test(
          'background refresh bypasses token validity check and publishes the new token',
          () async {
            // Use a token expiring in 14 min: _scheduleTokenRefresh immediately
            // calls _attemptTokenRefresh (refresh window = exp-15min is in the
            // past), bypassing the "token is still valid" short-circuit that
            // would prevent a real proactive refresh.
            final tokenExp = DateTime.now().add(const Duration(minutes: 14));

            when(
              mockSecureStorage.read(key: 'accessToken'),
            ).thenAnswer((_) async => 'nearly_expired_token');
            when(
              mockSecureStorage.read(key: 'refreshToken'),
            ).thenAnswer((_) async => 'current_refresh_token');
            when(
              mockSecureStorage.read(key: 'lastLoginCredentials'),
            ).thenAnswer((_) async => null);
            when(
              mockSecureStorage.read(key: 'userID'),
            ).thenAnswer((_) async => 'user123');
            when(
              mockSecureStorage.read(key: 'deviceID'),
            ).thenAnswer((_) async => 'device-id');
            when(
              mockJwtDecoder.isExpired('nearly_expired_token'),
            ).thenReturn(false);
            when(mockJwtDecoder.decode('nearly_expired_token')).thenReturn({
              'sub': 'user123',
              'exp': tokenExp.millisecondsSinceEpoch ~/ 1000,
            });

            final newTokenResponse = TokenResponse(
              accessToken: 'refreshed_access_token',
              expiresIn: 3600,
              tokenType: 'Bearer',
              userID: 'user123',
              refreshToken: 'new_refresh_token',
            );
            when(
              mockFusionAuthClient.oauthRefreshTokenGrant('current_refresh_token'),
            ).thenAnswer((_) async => newTokenResponse);
            when(mockJwtDecoder.decode('refreshed_access_token')).thenReturn({
              'sub': 'user123',
              'exp':
                  DateTime.now()
                      .add(const Duration(hours: 1))
                      .millisecondsSinceEpoch ~/
                  1000,
            });
            when(
              mockSecureStorage.write(
                key: anyNamed('key'),
                value: anyNamed('value'),
              ),
            ).thenAnswer((_) async => {});

            final redirectEvents = <bool>[];
            authService.authRedirectStream.listen(redirectEvents.add);
            final tokenEvents = <String>[];
            authService.accessTokenStream.listen(tokenEvents.add);

            await authService.init();
            await authService.checkLoginStatus();
            // _attemptTokenRefresh was called fire-and-forget; pump the event
            // loop so its async work (mock Future completions) finishes.
            await Future.delayed(Duration.zero);
            async.elapse(Duration.zero);

            verify(
              mockFusionAuthClient.oauthRefreshTokenGrant('current_refresh_token'),
            ).called(1);
            // The refreshed token is published so cached-token consumers (API
            // clients, socket auth) can re-arm — without this they keep using
            // the token they were handed at login and start 401ing at expiry.
            expect(tokenEvents, contains('refreshed_access_token'));
            expect(authService.currentAccessToken, 'refreshed_access_token');
            // A silent refresh is not a redirect: signalling authRedirectStream
            // here would make AuthBloc re-run AuthCheckStatus and bounce every
            // listener through AuthLoading roughly once an hour.
            expect(redirectEvents, isEmpty);
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

      group('proactive refresh self-healing retry', () {
        // Drives its own local FakeAsync so the retry/refresh Timers are
        // created in a fake zone and can be advanced deterministically. A
        // token expiring in 14 min makes _scheduleTokenRefresh fire
        // _attemptTokenRefresh immediately (refresh window exp-15min is in the
        // past), the same trick the "background refresh" test uses.
        void stubNearlyExpiredSession() {
          final tokenExp = DateTime.now().add(const Duration(minutes: 14));
          when(
            mockSecureStorage.read(key: 'accessToken'),
          ).thenAnswer((_) async => 'nearly_expired_token');
          when(
            mockSecureStorage.read(key: 'refreshToken'),
          ).thenAnswer((_) async => 'current_refresh_token');
          when(
            mockSecureStorage.read(key: 'lastLoginCredentials'),
          ).thenAnswer((_) async => null);
          when(
            mockSecureStorage.read(key: 'userID'),
          ).thenAnswer((_) async => 'user123');
          when(
            mockSecureStorage.read(key: 'deviceID'),
          ).thenAnswer((_) async => 'device-id');
          when(
            mockJwtDecoder.isExpired('nearly_expired_token'),
          ).thenReturn(false);
          when(mockJwtDecoder.decode('nearly_expired_token')).thenReturn({
            'sub': 'user123',
            'exp': tokenExp.millisecondsSinceEpoch ~/ 1000,
          });
          when(
            mockSecureStorage.write(
              key: anyNamed('key'),
              value: anyNamed('value'),
            ),
          ).thenAnswer((_) async => {});
          when(
            mockSecureStorage.delete(key: anyNamed('key')),
          ).thenAnswer((_) async => {});
        }

        test(
          'a failed refresh schedules a retry that later succeeds and '
          'publishes the new token',
          () {
            fakeAsync((fa) {
              stubNearlyExpiredSession();

              final newTokenResponse = TokenResponse(
                accessToken: 'refreshed_access_token',
                expiresIn: 3600,
                tokenType: 'Bearer',
                userID: 'user123',
                refreshToken: 'new_refresh_token',
              );
              when(mockJwtDecoder.decode('refreshed_access_token')).thenReturn({
                'sub': 'user123',
                'exp':
                    DateTime.now()
                        .add(const Duration(hours: 1))
                        .millisecondsSinceEpoch ~/
                    1000,
              });

              // First proactive attempt fails (transient); the retry succeeds.
              var calls = 0;
              when(
                mockFusionAuthClient.oauthRefreshTokenGrant(
                  'current_refresh_token',
                ),
              ).thenAnswer((_) async {
                calls++;
                if (calls == 1) {
                  throw 'transient network error';
                }
                return newTokenResponse;
              });

              final tokenEvents = <String>[];
              authService.accessTokenStream.listen(tokenEvents.add);

              authService.init();
              fa.flushMicrotasks();
              authService.checkLoginStatus();
              fa.flushMicrotasks();

              // Immediate attempt fired and failed; nothing published yet.
              expect(calls, 1);
              expect(tokenEvents, isEmpty);
              expect(authService.currentAccessToken, 'nearly_expired_token');

              // Retry is armed at the initial 30s backoff.
              fa.elapse(const Duration(seconds: 30));
              fa.flushMicrotasks();

              expect(calls, 2);
              expect(tokenEvents, contains('refreshed_access_token'));
              expect(
                authService.currentAccessToken,
                'refreshed_access_token',
              );

              authService.dispose();
            });
          },
        );

        test(
          'repeated failures keep retrying and respect the backoff cap',
          () {
            fakeAsync((fa) {
              stubNearlyExpiredSession();

              var calls = 0;
              when(
                mockFusionAuthClient.oauthRefreshTokenGrant(
                  'current_refresh_token',
                ),
              ).thenAnswer((_) async {
                calls++;
                throw 'always fails';
              });

              authService.init();
              fa.flushMicrotasks();
              authService.checkLoginStatus();
              fa.flushMicrotasks();

              // Immediate attempt (call 1), retry armed at 30s.
              expect(calls, 1);

              // Backoff escalates 30s, 60s, 120s, 240s, then caps at 5 min.
              fa.elapse(const Duration(seconds: 30));
              fa.flushMicrotasks();
              expect(calls, 2);

              fa.elapse(const Duration(seconds: 60));
              fa.flushMicrotasks();
              expect(calls, 3);

              fa.elapse(const Duration(seconds: 120));
              fa.flushMicrotasks();
              expect(calls, 4);

              fa.elapse(const Duration(seconds: 240));
              fa.flushMicrotasks();
              expect(calls, 5);

              // Now capped: the next delay is 5 min.
              fa.elapse(const Duration(minutes: 5));
              fa.flushMicrotasks();
              expect(calls, 6);

              // Cap holds — still 5 min, no faster. Just short of it: nothing.
              fa.elapse(const Duration(seconds: 299));
              fa.flushMicrotasks();
              expect(calls, 6);
              fa.elapse(const Duration(seconds: 1));
              fa.flushMicrotasks();
              expect(calls, 7);

              authService.dispose();
            });
          },
        );

        test('dispose cancels the pending retry timer', () {
          fakeAsync((fa) {
            stubNearlyExpiredSession();

            var calls = 0;
            when(
              mockFusionAuthClient.oauthRefreshTokenGrant(
                'current_refresh_token',
              ),
            ).thenAnswer((_) async {
              calls++;
              throw 'always fails';
            });

            authService.init();
            fa.flushMicrotasks();
            authService.checkLoginStatus();
            fa.flushMicrotasks();

            expect(calls, 1); // immediate attempt; retry armed at 30s

            authService.dispose();

            // No retry may fire after dispose.
            fa.elapse(const Duration(minutes: 10));
            fa.flushMicrotasks();
            expect(calls, 1);
          });
        });

        test('logout cancels the pending retry timer', () {
          fakeAsync((fa) {
            stubNearlyExpiredSession();

            var calls = 0;
            when(
              mockFusionAuthClient.oauthRefreshTokenGrant(
                'current_refresh_token',
              ),
            ).thenAnswer((_) async {
              calls++;
              throw 'always fails';
            });

            authService.init();
            fa.flushMicrotasks();
            authService.checkLoginStatus();
            fa.flushMicrotasks();

            expect(calls, 1); // immediate attempt; retry armed at 30s

            authService.logout();
            fa.flushMicrotasks();

            // No retry may fire after logout.
            fa.elapse(const Duration(minutes: 10));
            fa.flushMicrotasks();
            expect(calls, 1);

            authService.dispose();
          });
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
          final captured = verify(
            mockLibloginNative.login(
              authUri: captureAnyNamed('authUri'),
              redirectUri: config.loginRedirectURI,
            ),
          ).captured;
          expect(captured, hasLength(1));
          final Uri authUri = captured.single as Uri;
          expect(
            authUri.queryParameters['idp_hint'],
            config.googleIdentityProviderID,
          );
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

      group('initiateAppleLogin', () {
        late LoginConfig appleConfig;
        late AuthService appleAuthService;

        AuthorizationCredentialAppleID makeCredential({
          String? identityToken = 'apple_identity_token',
        }) {
          return AuthorizationCredentialAppleID(
            userIdentifier: 'apple_user_123',
            givenName: 'Jane',
            familyName: 'Doe',
            email: 'jane@example.com',
            authorizationCode: 'auth_code_abc',
            identityToken: identityToken,
            state: null,
          );
        }

        setUp(() {
          appleConfig = LoginConfig(
            loginDomain: 'example.com',
            signupOrigin: 'https://signup.example.com',
            loginTenantID: 'some-tenant-id',
            loginClientID: 'some-client-id',
            loginRedirectURI: 'https://example.com/callback',
            googleIdentityProviderID: 'google-idp',
            appleIdentityProviderID: 'apple-idp',
            appleBundleID: 'xyz.twoseven.app.flutterRemoteControl',
          );
          appleAuthService = AuthService(
            config: appleConfig,
            secureStorage: mockSecureStorage,
            httpClient: mockHttpClient,
            jwtDecoder: mockJwtDecoder,
            fusionAuthClient: mockFusionAuthClient,
            libloginNative: mockLibloginNative,
            appleSignIn: mockAppleSignIn,
            googleSignIn: mockGoogleSignIn,
          );
        });

        test(
          'calls appleIdpLogin with identity token and emits true on success',
          () async {
            when(
              mockAppleSignIn.getCredential(),
            ).thenAnswer((_) async => makeCredential());
            final tokenResponse = TokenResponse(
              accessToken: 'apple_access',
              expiresIn: 3600,
              tokenType: 'Bearer',
              userID: 'apple_user_123',
              refreshToken: 'apple_refresh',
            );
            when(
              mockFusionAuthClient.appleIdpLogin(
                identityToken: 'apple_identity_token',
                authorizationCode: 'auth_code_abc',
                identityProviderId: 'apple-idp',
                redirectUri: 'xyz.twoseven.app.flutterRemoteControl',
              ),
            ).thenAnswer((_) async => tokenResponse);
            when(mockJwtDecoder.decode('apple_access')).thenReturn({
              'sub': 'apple_user_123',
              'exp': (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600,
            });
            when(
              mockSecureStorage.write(
                key: anyNamed('key'),
                value: anyNamed('value'),
              ),
            ).thenAnswer((_) async => {});

            final redirectEvents = <bool>[];
            appleAuthService.authRedirectStream.listen(redirectEvents.add);

            final result = await appleAuthService.initiateAppleLogin();
            await Future.delayed(Duration.zero);
            async.elapse(const Duration(hours: 1));

            expect(result, isTrue);
            expect(redirectEvents, contains(true));
            verify(
              mockFusionAuthClient.appleIdpLogin(
                identityToken: 'apple_identity_token',
                authorizationCode: 'auth_code_abc',
                identityProviderId: 'apple-idp',
                redirectUri: 'xyz.twoseven.app.flutterRemoteControl',
              ),
            ).called(1);
            verify(
              mockSecureStorage.write(key: 'accessToken', value: 'apple_access'),
            ).called(1);
            verify(
              mockSecureStorage.write(
                key: 'refreshToken',
                value: 'apple_refresh',
              ),
            ).called(1);
          },
        );

        test(
          'returns false without calling idpLogin when identity token is null',
          () async {
            when(
              mockAppleSignIn.getCredential(),
            ).thenAnswer((_) async => makeCredential(identityToken: null));

            final result = await appleAuthService.initiateAppleLogin();
            async.elapse(Duration.zero);

            expect(result, isFalse);
            verifyNever(
              mockFusionAuthClient.appleIdpLogin(
                identityToken: anyNamed('identityToken'),
                authorizationCode: anyNamed('authorizationCode'),
                identityProviderId: anyNamed('identityProviderId'),
                redirectUri: anyNamed('redirectUri'),
              ),
            );
          },
        );

        test('returns false silently when user cancels', () async {
          when(mockAppleSignIn.getCredential()).thenThrow(
            SignInWithAppleAuthorizationException(
              code: AuthorizationErrorCode.canceled,
              message: 'User canceled',
            ),
          );

          final redirectEvents = <bool>[];
          appleAuthService.authRedirectStream.listen(redirectEvents.add);

          final result = await appleAuthService.initiateAppleLogin();
          async.elapse(Duration.zero);

          expect(result, isFalse);
          expect(redirectEvents, isEmpty);
          verifyNever(
            mockFusionAuthClient.appleIdpLogin(
              identityToken: anyNamed('identityToken'),
              authorizationCode: anyNamed('authorizationCode'),
              identityProviderId: anyNamed('identityProviderId'),
              redirectUri: anyNamed('redirectUri'),
            ),
          );
        });

        test(
          'returns false and emits false when FusionAuth idpLogin fails',
          () async {
            when(
              mockAppleSignIn.getCredential(),
            ).thenAnswer((_) async => makeCredential());
            when(
              mockFusionAuthClient.appleIdpLogin(
                identityToken: anyNamed('identityToken'),
                authorizationCode: anyNamed('authorizationCode'),
                identityProviderId: anyNamed('identityProviderId'),
                redirectUri: anyNamed('redirectUri'),
              ),
            ).thenThrow('IdP login failed');

            final redirectEvents = <bool>[];
            appleAuthService.authRedirectStream.listen(redirectEvents.add);

            final result = await appleAuthService.initiateAppleLogin();
            await Future.delayed(Duration.zero);
            async.elapse(Duration.zero);

            expect(result, isFalse);
            expect(redirectEvents, contains(false));
          },
        );

        test(
          'throws StateError when appleIdentityProviderID is not configured',
          () {
            expect(
              () => authService.initiateAppleLogin(),
              throwsA(isA<StateError>()),
            );
          },
        );
      });

      group('initiateGoogleNativeLogin', () {
        test(
          'calls googleIdpLogin with id token and emits true on success',
          () async {
            when(
              mockGoogleSignIn.getIdToken(),
            ).thenAnswer((_) async => 'google_id_token');
            final tokenResponse = TokenResponse(
              accessToken: 'google_access',
              expiresIn: 3600,
              tokenType: 'Bearer',
              userID: 'google_user_123',
              refreshToken: 'google_refresh',
            );
            when(
              mockFusionAuthClient.googleIdpLogin(
                idToken: 'google_id_token',
                identityProviderId: 'google-idp',
              ),
            ).thenAnswer((_) async => tokenResponse);
            when(mockJwtDecoder.decode('google_access')).thenReturn({
              'sub': 'google_user_123',
              'exp': (DateTime.now().millisecondsSinceEpoch ~/ 1000) + 3600,
            });
            when(
              mockSecureStorage.write(
                key: anyNamed('key'),
                value: anyNamed('value'),
              ),
            ).thenAnswer((_) async => {});

            final redirectEvents = <bool>[];
            authService.authRedirectStream.listen(redirectEvents.add);

            final result = await authService.initiateGoogleNativeLogin();
            await Future.delayed(Duration.zero);
            async.elapse(const Duration(hours: 1));

            expect(result, isTrue);
            expect(redirectEvents, contains(true));
            verify(
              mockFusionAuthClient.googleIdpLogin(
                idToken: 'google_id_token',
                identityProviderId: 'google-idp',
              ),
            ).called(1);
            verify(
              mockSecureStorage.write(
                key: 'accessToken',
                value: 'google_access',
              ),
            ).called(1);
            verify(
              mockSecureStorage.write(
                key: 'refreshToken',
                value: 'google_refresh',
              ),
            ).called(1);
          },
        );

        test(
          'returns false without calling idpLogin when id token is null',
          () async {
            when(mockGoogleSignIn.getIdToken()).thenAnswer((_) async => null);

            final redirectEvents = <bool>[];
            authService.authRedirectStream.listen(redirectEvents.add);

            final result = await authService.initiateGoogleNativeLogin();
            async.elapse(Duration.zero);

            expect(result, isFalse);
            expect(redirectEvents, isEmpty);
            verifyNever(
              mockFusionAuthClient.googleIdpLogin(
                idToken: anyNamed('idToken'),
                identityProviderId: anyNamed('identityProviderId'),
              ),
            );
          },
        );

        test('returns false silently when user cancels', () async {
          when(mockGoogleSignIn.getIdToken()).thenThrow(
            const GoogleSignInException(
              code: GoogleSignInExceptionCode.canceled,
              description: 'User canceled',
            ),
          );

          final redirectEvents = <bool>[];
          authService.authRedirectStream.listen(redirectEvents.add);

          final result = await authService.initiateGoogleNativeLogin();
          async.elapse(Duration.zero);

          expect(result, isFalse);
          expect(redirectEvents, isEmpty);
          verifyNever(
            mockFusionAuthClient.googleIdpLogin(
              idToken: anyNamed('idToken'),
              identityProviderId: anyNamed('identityProviderId'),
            ),
          );
        });

        test(
          'returns false and emits false when FusionAuth idpLogin fails',
          () async {
            when(
              mockGoogleSignIn.getIdToken(),
            ).thenAnswer((_) async => 'google_id_token');
            when(
              mockFusionAuthClient.googleIdpLogin(
                idToken: anyNamed('idToken'),
                identityProviderId: anyNamed('identityProviderId'),
              ),
            ).thenThrow('IdP login failed');

            final redirectEvents = <bool>[];
            authService.authRedirectStream.listen(redirectEvents.add);

            final result = await authService.initiateGoogleNativeLogin();
            await Future.delayed(Duration.zero);
            async.elapse(Duration.zero);

            expect(result, isFalse);
            expect(redirectEvents, contains(false));
          },
        );

        test(
          'returns false and emits false on non-cancel GoogleSignInException',
          () async {
            when(mockGoogleSignIn.getIdToken()).thenThrow(
              const GoogleSignInException(
                code: GoogleSignInExceptionCode.clientConfigurationError,
                description: 'Misconfigured client',
              ),
            );

            final redirectEvents = <bool>[];
            authService.authRedirectStream.listen(redirectEvents.add);

            final result = await authService.initiateGoogleNativeLogin();
            async.elapse(Duration.zero);

            expect(result, isFalse);
            expect(redirectEvents, contains(false));
            verifyNever(
              mockFusionAuthClient.googleIdpLogin(
                idToken: anyNamed('idToken'),
                identityProviderId: anyNamed('identityProviderId'),
              ),
            );
          },
        );

        test(
          'throws StateError when googleIdentityProviderID is empty',
          () {
            final emptyIdpConfig = LoginConfig(
              loginDomain: 'example.com',
              signupOrigin: 'https://signup.example.com',
              loginTenantID: 'some-tenant-id',
              loginClientID: 'some-client-id',
              loginRedirectURI: 'https://example.com/callback',
              googleIdentityProviderID: '',
            );
            final emptyIdpService = AuthService(
              config: emptyIdpConfig,
              secureStorage: mockSecureStorage,
              httpClient: mockHttpClient,
              jwtDecoder: mockJwtDecoder,
              fusionAuthClient: mockFusionAuthClient,
              libloginNative: mockLibloginNative,
              appleSignIn: mockAppleSignIn,
              googleSignIn: mockGoogleSignIn,
            );
            expect(
              () => emptyIdpService.initiateGoogleNativeLogin(),
              throwsA(isA<StateError>()),
            );
          },
        );
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
            idToken: 'id_token',
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
          expect(authService.currentIdToken, 'id_token');
          verify(
            mockFusionAuthClient.exchangeAuthorizationCode(
              'auth_code',
              'mock_code_verifier',
            ),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'accessToken', value: 'access'),
          ).called(1);
          verify(
            mockSecureStorage.write(key: 'idToken', value: 'id_token'),
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
