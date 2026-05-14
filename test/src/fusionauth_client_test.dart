import 'package:flutter_test/flutter_test.dart';
import 'package:http/http.dart' as http;
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'package:liblogin/src/fusionauth_client.dart';
import 'package:liblogin/src/login_config.dart';
import 'package:liblogin/src/auth_models.dart';
import 'dart:convert';

import 'fusionauth_client_test.mocks.dart';

@GenerateMocks([http.Client])
void main() {
  group('FusionAuthClient', () {
    late MockClient mockHttpClient;
    late LoginConfig config;
    late FusionAuthClient fusionAuthClient;

    setUp(() {
      mockHttpClient = MockClient();
      config = LoginConfig(
        loginDomain: 'example.com',
        signupOrigin: 'https://signup.example.com',
        loginTenantID: 'some-tenant-id',
        loginClientID: 'some-client-id',
        loginRedirectURI: 'https://example.com/callback',
        googleIdentityProviderID: 'google-idp',
      );
      fusionAuthClient = FusionAuthClient(
        config: config,
        httpClient: mockHttpClient,
      );
    });

    test('login returns LoginResponse on success', () async {
      final mockResponse = {
        'access_token': 'mock_access_token',
        'refresh_token': 'mock_refresh_token',
        'lastLoginCredentials': 'mock_last_login_credentials',
        'user': {'id': 'mock_user_id', 'email': 'test@example.com'},
      };

      when(
        mockHttpClient.post(
          Uri.parse('https://signup.example.com/login/login'),
          headers: anyNamed('headers'),
          body: anyNamed('body'),
        ),
      ).thenAnswer((_) async => http.Response(json.encode(mockResponse), 200));

      final loginResponse = await fusionAuthClient.login(
        username: 'test@example.com',
        password: 'password123',
      );

      expect(loginResponse, isA<LoginResponse>());
      expect(loginResponse.accessToken, 'mock_access_token');
      expect(loginResponse.refreshToken, 'mock_refresh_token');
      expect(loginResponse.lastLoginCredentials, 'mock_last_login_credentials');
      expect(loginResponse.user!['id'], 'mock_user_id');

      verify(
        mockHttpClient.post(
          Uri.parse('https://signup.example.com/login/login'),
          headers: {'content-type': 'application/json'},
          body: json.encode({
            'username': 'test@example.com',
            'password': 'password123',
            'clientID': 'some-client-id',
            'device': {},
          }),
        ),
      ).called(1);
    });

    test('login throws error on failure', () async {
      when(
        mockHttpClient.post(
          any,
          headers: anyNamed('headers'),
          body: anyNamed('body'),
        ),
      ).thenAnswer((_) async => http.Response('Error message', 400));

      expect(
        () => fusionAuthClient.login(
          username: 'test@example.com',
          password: 'password123',
        ),
        throwsA(isA<String>()),
      );
    });

    test(
      'resourceOwnerPasswordCredentialsGrant returns TokenResponse on success',
      () async {
        final mockResponse = {
          'access_token': 'mock_access_token',
          'expires_in': 3600,
          'token_type': 'Bearer',
          'userId': 'mock_user_id',
        };

        when(
          mockHttpClient.post(
            Uri.parse('https://example.com/oauth2/token'),
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer(
          (_) async => http.Response(json.encode(mockResponse), 200),
        );

        final tokenResponse = await fusionAuthClient
            .resourceOwnerPasswordCredentialsGrant(
              'test@example.com',
              'password123',
            );

        expect(tokenResponse, isA<TokenResponse>());
        expect(tokenResponse.accessToken, 'mock_access_token');
        expect(tokenResponse.expiresIn, 3600);
        expect(tokenResponse.tokenType, 'Bearer');
        expect(tokenResponse.userID, 'mock_user_id');

        verify(
          mockHttpClient.post(
            Uri.parse('https://example.com/oauth2/token'),
            headers: {'content-type': 'application/x-www-form-urlencoded'},
            body: {
              'client_id': 'some-client-id',
              'grant_type': 'password',
              'username': 'test@example.com',
              'password': 'password123',
              'scope': 'openid email offline_access',
            },
          ),
        ).called(1);
      },
    );

    test(
      'resourceOwnerPasswordCredentialsGrant throws error on failure',
      () async {
        when(
          mockHttpClient.post(
            any,
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer((_) async => http.Response('Error message', 400));

        expect(
          () => fusionAuthClient.resourceOwnerPasswordCredentialsGrant(
            'test@example.com',
            'password123',
          ),
          throwsA(isA<String>()),
        );
      },
    );

    test('refreshTokenGrant returns TokenResponse on success', () async {
      final mockResponse = {
        'access_token': 'new_mock_access_token',
        'expires_in': 3600,
        'token_type': 'Bearer',
        'userId': 'mock_user_id',
      };

      when(
        mockHttpClient.post(
          Uri.parse('https://signup.example.com/login/refresh-tokens'),
          headers: anyNamed('headers'),
          body: anyNamed('body'),
        ),
      ).thenAnswer((_) async => http.Response(json.encode(mockResponse), 200));

      final tokenResponse = await fusionAuthClient.refreshTokenGrant(
        'mock_refresh_token',
      );

      expect(tokenResponse, isA<TokenResponse>());
      expect(tokenResponse.accessToken, 'new_mock_access_token');

      verify(
        mockHttpClient.post(
          Uri.parse('https://signup.example.com/login/refresh-tokens'),
          headers: {'content-type': 'application/json'},
          body: json.encode({
            'lastLoginCredentials': 'mock_refresh_token',
            'clientID': 'some-client-id',
            'includeRefreshToken': true,
          }),
        ),
      ).called(1);
    });

    test('refreshTokenGrant throws error on failure', () async {
      when(
        mockHttpClient.post(
          any,
          headers: anyNamed('headers'),
          body: anyNamed('body'),
        ),
      ).thenAnswer((_) async => http.Response('Error message', 400));

      expect(
        () => fusionAuthClient.refreshTokenGrant('mock_refresh_token'),
        throwsA(isA<String>()),
      );
    });

    test(
      'exchangeAuthorizationCode returns TokenResponse on success',
      () async {
        final mockResponse = {
          'access_token': 'auth_code_access_token',
          'expires_in': 3600,
          'token_type': 'Bearer',
          'userId': 'auth_code_user_id',
        };

        when(
          mockHttpClient.post(
            Uri.parse('https://example.com/oauth2/token'),
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer(
          (_) async => http.Response(json.encode(mockResponse), 200),
        );

        final tokenResponse = await fusionAuthClient.exchangeAuthorizationCode(
          'mock_code',
          'mock_code_verifier',
        );

        expect(tokenResponse, isA<TokenResponse>());
        expect(tokenResponse.accessToken, 'auth_code_access_token');

        verify(
          mockHttpClient.post(
            Uri.parse('https://example.com/oauth2/token'),
            headers: {'content-type': 'application/x-www-form-urlencoded'},
            body: {
              'client_id': 'some-client-id',
              'grant_type': 'authorization_code',
              'code': 'mock_code',
              'redirect_uri': 'https://example.com/callback',
              'code_verifier': 'mock_code_verifier',
            },
          ),
        ).called(1);
      },
    );

    test('exchangeAuthorizationCode throws error on failure', () async {
      when(
        mockHttpClient.post(
          any,
          headers: anyNamed('headers'),
          body: anyNamed('body'),
        ),
      ).thenAnswer((_) async => http.Response('Error message', 400));

      expect(
        () => fusionAuthClient.exchangeAuthorizationCode(
          'mock_code',
          'mock_code_verifier',
        ),
        throwsA(isA<String>()),
      );
    });

    group('appleIdpLogin', () {
      test('returns TokenResponse on success', () async {
        final mockResponse = {
          'token': 'apple_access_token',
          'refreshToken': 'apple_refresh_token',
          'tokenType': 'Bearer',
          'expiresIn': 3600,
          'userId': 'apple_user_id',
        };

        when(
          mockHttpClient.post(
            Uri.parse('https://example.com/api/identity-provider/login'),
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer(
          (_) async => http.Response(json.encode(mockResponse), 200),
        );

        final tokenResponse = await fusionAuthClient.appleIdpLogin(
          identityToken: 'apple_identity_token',
          identityProviderId: 'apple-idp-uuid',
        );

        expect(tokenResponse.accessToken, 'apple_access_token');
        expect(tokenResponse.refreshToken, 'apple_refresh_token');
        expect(tokenResponse.tokenType, 'Bearer');
        expect(tokenResponse.expiresIn, 3600);
        expect(tokenResponse.userID, 'apple_user_id');

        verify(
          mockHttpClient.post(
            Uri.parse('https://example.com/api/identity-provider/login'),
            headers: {'content-type': 'application/json'},
            body: json.encode({
              'applicationId': 'some-client-id',
              'identityProviderId': 'apple-idp-uuid',
              'data': {'token': 'apple_identity_token'},
            }),
          ),
        ).called(1);
      });

      test('throws on non-200 response', () async {
        when(
          mockHttpClient.post(
            any,
            headers: anyNamed('headers'),
            body: anyNamed('body'),
          ),
        ).thenAnswer((_) async => http.Response('Unauthorized', 401));

        expect(
          () => fusionAuthClient.appleIdpLogin(
            identityToken: 'bad_token',
            identityProviderId: 'apple-idp-uuid',
          ),
          throwsA(isA<String>()),
        );
      });
    });
  });
}
