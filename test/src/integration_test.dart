import 'dart:io';
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

import 'integration_test.mocks.dart';

@GenerateMocks([FlutterSecureStorage])
void main() {
  HttpOverrides.global = null;
  TestWidgetsFlutterBinding.ensureInitialized();

  // Set this to false to test against a manually started backend
  const bool manageDocker = true;

  const String dockerComposePath = 'test/resources/docker-compose.yml';
  const String kickstartPath = 'test/resources/kickstart.json';
  const String signupOrigin = 'http://127.0.0.1:3117';
  const String loginDomain = 'http://127.0.0.1:3117';

  final kickstart = json.decode(File(kickstartPath).readAsStringSync());
  final variables = kickstart['variables'];
  final String tenantId = variables['defaultTenantId'];
  final String applicationId = variables['applicationId'];
  final String testUser1Email = variables['user1Email'];
  final String testUser1Password = variables['user1Password'];

  late AuthService authService;
  late MockFlutterSecureStorage mockSecureStorage;
  late Map<String, String> storage;

  Future<void> runCommand(String command, List<String> args) async {
    final result = await Process.run(command, args);
    if (result.exitCode != 0) {
      throw Exception(
        '''Command $command ${args.join(' ')} failed with exit code ${result.exitCode}
Stdout: ${result.stdout}
Stderr: ${result.stderr}''',
      );
    }
  }

  setUpAll(() async {
    HttpOverrides.global = null;

    if (manageDocker) {
      print('Starting docker-compose backend...');
      await runCommand('docker', [
        'compose',
        '-f',
        dockerComposePath,
        'up',
        '-d',
      ]);
    }

    // Wait for the backend to be healthy
    print('Waiting for backend to be healthy...');
    bool isHealthy = false;
    for (int i = 0; i < 30; i++) {
      try {
        final response = await http.get(Uri.parse('$signupOrigin/health'));
        if (response.statusCode < 500) {
          isHealthy = true;
          break;
        }
      } catch (e) {
        // Ignore errors and retry
      }
      await Future.delayed(const Duration(seconds: 1));
    }

    if (!isHealthy) {
      throw Exception('Backend failed to become healthy in time');
    }
    print('Backend is healthy.');
  });

  tearDownAll(() async {
    if (manageDocker) {
      print('Stopping docker-compose backend...');
      await runCommand('docker', ['compose', '-f', dockerComposePath, 'down']);
    }
  });

  setUp(() {
    storage = {};
    mockSecureStorage = MockFlutterSecureStorage();

    when(mockSecureStorage.read(key: anyNamed('key'))).thenAnswer((
      invocation,
    ) async {
      return storage[invocation.namedArguments[#key]];
    });

    when(
      mockSecureStorage.write(key: anyNamed('key'), value: anyNamed('value')),
    ).thenAnswer((invocation) async {
      storage[invocation.namedArguments[#key]] =
          invocation.namedArguments[#value];
    });

    when(mockSecureStorage.delete(key: anyNamed('key'))).thenAnswer((
      invocation,
    ) async {
      storage.remove(invocation.namedArguments[#key]);
    });

    final config = LoginConfig(
      loginDomain: loginDomain,
      signupOrigin: signupOrigin,
      loginTenantID: tenantId,
      loginClientID: applicationId,
      loginRedirectURI: 'me.gurupras.liblogin://callback',
      googleIdentityProviderID: 'google-idp',
    );

    // Mock MethodChannel for native plugin
    TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
        .setMockMethodCallHandler(const MethodChannel('me.gurupras.liblogin'), (
          methodCall,
        ) async {
          return null;
        });

    authService = AuthService(config: config, secureStorage: mockSecureStorage);
  });

  group('Integration Tests', () {
    test('Login with pre-configured test user', () async {
      print('Verifying pre-configured user $testUser1Email...');
      final verifyResp = await http.get(
        Uri.parse('$signupOrigin/verify/$testUser1Email'),
      );
      expect(verifyResp.statusCode, 200);

      print('Testing login with pre-configured user $testUser1Email...');
      final loginSuccess = await authService.login(
        testUser1Email,
        testUser1Password,
      );
      expect(
        loginSuccess,
        isTrue,
        reason: 'Login should succeed for pre-configured user',
      );

      expect(authService.currentAccessToken, isNotNull);
      expect(storage['accessToken'], isNotNull);
      expect(storage['refreshToken'], isNotNull);

      // Verify JWT Decoding
      print('Verifying decoded JWT...');
      final decoded = authService.decodedAccessToken;
      expect(decoded, isNotNull);
      expect(
        decoded!.sub,
        isNotNull,
        reason: 'Subject (userID) should be present',
      );
      expect(
        decoded.applicationId,
        applicationId,
        reason: 'Application ID should match',
      );

      final status = await authService.checkLoginStatus();
      expect(status, isTrue);

      await authService.logout();
      expect(authService.currentAccessToken, isNull);
    });

    test('Token Refresh flow', () async {
      print('Testing token refresh flow...');
      await authService.login(testUser1Email, testUser1Password);
      final initialAccessToken = authService.currentAccessToken;
      expect(initialAccessToken, isNotNull);
      expect(storage['lastLoginCredentials'], isNotNull);

      // Manually "expire" the access token by clearing it from memory and storage,
      // but keep the refresh token and lastLoginCredentials.
      storage.remove('accessToken');
      // We also need to clear it from the service's internal state
      // Since we can't easily do that without reflection or a setter,
      // we can recreate the service instance to simulate a fresh app start
      // where only the refresh token was persisted.

      final config = LoginConfig(
        loginDomain: loginDomain,
        signupOrigin: signupOrigin,
        loginTenantID: tenantId,
        loginClientID: applicationId,
        loginRedirectURI: 'me.gurupras.liblogin://callback',
        googleIdentityProviderID: 'google-idp',
      );

      final newAuthService = AuthService(
        config: config,
        secureStorage: mockSecureStorage,
      );

      print('Initializing newAuthService...');
      await newAuthService.init();

      print('Calling checkLoginStatus to trigger refresh...');
      final status = await newAuthService.checkLoginStatus();
      expect(
        status,
        isTrue,
        reason: 'Should have successfully refreshed the token',
      );
      expect(newAuthService.currentAccessToken, isNotNull);
      expect(
        newAuthService.currentAccessToken,
        isNot(initialAccessToken),
        reason: 'Access token should be new',
      );
      expect(storage['accessToken'], isNotNull);
    });

    test('Initialization and Device ID', () async {
      print('Testing initialization...');
      expect(storage['deviceID'], isNull);

      await authService.init();
      final deviceID = storage['deviceID'];
      expect(deviceID, isNotNull);
      expect(deviceID, isNotEmpty);

      // Re-init should keep the same ID
      await authService.init();
      expect(storage['deviceID'], deviceID);
    });

    test('Sign up and Login flow', () async {
      final String email =
          'test-${DateTime.now().millisecondsSinceEpoch}@example.com';
      const String password = 'Password123!';

      print('Testing signUp with $email...');
      // signUp will return false because it internally calls login which fails due to verification
      await authService.signUp(email, password);

      print('Verifying email $email...');
      final verifyResp = await http.get(
        Uri.parse('$signupOrigin/verify/$email'),
      );
      expect(verifyResp.statusCode, 200);

      print('Testing login after verification...');
      final loginSuccess = await authService.login(email, password);
      expect(
        loginSuccess,
        isTrue,
        reason: 'Login should succeed after verification',
      );

      // signUp calls login automatically on success, so we should have tokens
      expect(authService.currentAccessToken, isNotNull);

      print('Testing checkLoginStatus after login...');
      final status = await authService.checkLoginStatus();
      expect(status, isTrue);

      print('Testing logout after login...');
      await authService.logout();
      expect(authService.currentAccessToken, isNull);
    });

    test('Login with incorrect credentials fails', () async {
      final loginSuccess = await authService.login(
        'nonexistent@example.com',
        'wrongpassword',
      );
      expect(loginSuccess, isFalse);
    });

    test('Session Restoration (App Restart Simulation)', () async {
      print('Testing session restoration...');
      await authService.login(testUser1Email, testUser1Password);
      final initialAccessToken = authService.currentAccessToken;
      expect(initialAccessToken, isNotNull);

      // Recreate service to simulate app restart
      final config = LoginConfig(
        loginDomain: loginDomain,
        signupOrigin: signupOrigin,
        loginTenantID: tenantId,
        loginClientID: applicationId,
        loginRedirectURI: 'me.gurupras.liblogin://callback',
        googleIdentityProviderID: 'google-idp',
      );

      final restartService = AuthService(
        config: config,
        secureStorage: mockSecureStorage,
      );

      print('Calling checkLoginStatus on restarted service...');
      // init() reads from storage. If token is valid, it should restore it.
      await restartService.init();
      final status = await restartService.checkLoginStatus();

      expect(status, isTrue, reason: 'Session should be restored');
      expect(
        restartService.currentAccessToken,
        initialAccessToken,
        reason: 'Should restore the SAME access token if not expired',
      );
    });

    test('Duplicate Sign-up Handling', () async {
      print('Testing duplicate sign-up...');
      // Sign up the first time (ignore if it already exists from a previous run)
      await authService.signUp(testUser1Email, testUser1Password);

      // Attempt to sign up with the same email again
      final signUpSuccess = await authService.signUp(
        testUser1Email,
        testUser1Password,
      );
      expect(
        signUpSuccess,
        isFalse,
        reason: 'Sign up should fail for existing email',
      );
    });

    test('Password Recovery flow', () async {
      print('Testing password recovery...');
      final success = await authService.recoverPassword(testUser1Email);
      expect(
        success,
        isTrue,
        reason: 'Password recovery request should succeed for valid user',
      );

      // Test with non-existent user (FusionAuth usually returns success anyway for security, but let's check backend behavior)
      final nonExistentSuccess = await authService.recoverPassword(
        'nonexistent-recovery@example.com',
      );
      expect(
        nonExistentSuccess,
        isTrue,
        reason:
            'Backend should return success even for non-existent users to avoid email enumeration',
      );
    });
  });
}
