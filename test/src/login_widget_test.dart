import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:liblogin/liblogin.dart';
import 'package:mockito/mockito.dart';

import 'auth_bloc/auth_bloc_test.mocks.dart';

void main() {
  late MockAuthService mockAuthService;
  late AuthBloc authBloc;

  LoginConfig buildConfig({
    String? appleIdentityProviderID,
    bool useNativeGoogle = true,
  }) {
    return LoginConfig(
      loginDomain: 'example.com',
      signupOrigin: 'https://signup.example.com',
      loginTenantID: 'tenant',
      loginClientID: 'client',
      loginRedirectURI: 'app://callback',
      googleIdentityProviderID: 'google-idp',
      appleIdentityProviderID: appleIdentityProviderID,
      useNativeGoogle: useNativeGoogle,
    );
  }

  void stubAuthService({
    String? appleIdentityProviderID,
    bool useNativeGoogle = true,
  }) {
    when(
      mockAuthService.authRedirectStream,
    ).thenAnswer((_) => const Stream.empty());
    when(
      mockAuthService.accessTokenStream,
    ).thenAnswer((_) => const Stream.empty());
    when(mockAuthService.config).thenReturn(
      buildConfig(
        appleIdentityProviderID: appleIdentityProviderID,
        useNativeGoogle: useNativeGoogle,
      ),
    );
  }

  setUp(() {
    mockAuthService = MockAuthService();
    stubAuthService();
    authBloc = AuthBloc(authService: mockAuthService);
  });

  tearDown(() async {
    await authBloc.close();
  });

  Widget wrap(Widget child) {
    return MaterialApp(
      home: BlocProvider<AuthBloc>.value(value: authBloc, child: child),
    );
  }

  /// Captures the [FlutterLogin] widget and disposes the tree so flutter_login's
  /// animation timers don't leak past the test boundary.
  Future<FlutterLogin> capture(WidgetTester tester, Widget child) async {
    await tester.pumpWidget(wrap(child));
    final captured = tester.widget<FlutterLogin>(find.byType(FlutterLogin));
    await tester.pumpWidget(const SizedBox.shrink());
    // Drain any timers flutter_login scheduled during initState before the
    // tree was torn down.
    await tester.pump(const Duration(seconds: 30));
    return captured;
  }

  testWidgets(
    'renders email/password form by default and includes default Google provider',
    (tester) async {
      final flutterLogin = await capture(
        tester,
        const LoginPage(title: 'Test App'),
      );
      expect(flutterLogin.hideUserNamePasswordLogin, isFalse);
      expect(flutterLogin.loginProviders.length, 1);
      expect(flutterLogin.loginProviders.first.label, 'Google');
    },
  );

  testWidgets(
    'appends an Apple provider when appleIdentityProviderID is configured',
    (tester) async {
      stubAuthService(appleIdentityProviderID: 'apple-idp');
      final flutterLogin = await capture(
        tester,
        const LoginPage(title: 'Test App'),
      );
      expect(
        flutterLogin.loginProviders.map((p) => p.label),
        ['Google', 'Apple'],
      );
      expect(flutterLogin.loginProviders.last.button, Buttons.apple);
    },
  );

  testWidgets(
    'omits the Apple provider when appleIdentityProviderID is null',
    (tester) async {
      // Default stub from setUp already leaves appleIdentityProviderID null.
      final flutterLogin = await capture(
        tester,
        const LoginPage(title: 'Test App'),
      );
      expect(
        flutterLogin.loginProviders.any((p) => p.label == 'Apple'),
        isFalse,
      );
    },
  );

  testWidgets(
    'forwards hideUserNamePasswordLogin when enableEmailPassword is false',
    (tester) async {
      final flutterLogin = await capture(
        tester,
        LoginPage(
          title: 'Test App',
          enableEmailPassword: false,
          socialProviders: [
            LoginProvider(
              icon: Icons.login,
              label: 'Custom',
              callback: () async => null,
            ),
          ],
        ),
      );
      expect(flutterLogin.hideUserNamePasswordLogin, isTrue);
      expect(flutterLogin.loginProviders.single.label, 'Custom');
    },
  );

  testWidgets('uses caller-supplied socialProviders when provided', (
    tester,
  ) async {
    final flutterLogin = await capture(
      tester,
      LoginPage(
        title: 'Test App',
        socialProviders: [
          LoginProvider(
            icon: Icons.apple,
            label: 'Apple',
            callback: () async => null,
          ),
          LoginProvider(
            icon: Icons.code,
            label: 'GitHub',
            callback: () async => null,
          ),
        ],
      ),
    );
    expect(
      flutterLogin.loginProviders.map((p) => p.label),
      ['Apple', 'GitHub'],
    );
  });

  testWidgets('forwards termsOfService to FlutterLogin', (tester) async {
    final tos = TermOfService(id: 'tos', mandatory: true, text: 'Terms');
    final flutterLogin = await capture(
      tester,
      LoginPage(
        title: 'Test App',
        enableEmailPassword: false,
        socialProviders: [
          LoginProvider(
            icon: Icons.login,
            label: 'Provider',
            callback: () async => null,
          ),
        ],
        termsOfService: [tos],
      ),
    );
    expect(flutterLogin.termsOfService, [tos]);
  });

  testWidgets(
    'default Google provider uses native flow on mobile when useNativeGoogle is true',
    (tester) async {
      when(
        mockAuthService.initiateGoogleNativeLogin(),
      ).thenAnswer((_) async => true);
      final flutterLogin = await capture(
        tester,
        const LoginPage(title: 'Test App'),
      );
      final google = flutterLogin.loginProviders.firstWhere(
        (p) => p.label == 'Google',
      );
      await google.callback();
      verify(mockAuthService.initiateGoogleNativeLogin()).called(1);
      verifyNever(mockAuthService.initiateGoogleLogin());
    },
  );

  testWidgets(
    'default Google provider uses web flow when useNativeGoogle is false',
    (tester) async {
      stubAuthService(useNativeGoogle: false);
      when(
        mockAuthService.initiateGoogleLogin(),
      ).thenAnswer((_) async => true);
      final flutterLogin = await capture(
        tester,
        const LoginPage(title: 'Test App'),
      );
      final google = flutterLogin.loginProviders.firstWhere(
        (p) => p.label == 'Google',
      );
      await google.callback();
      verify(mockAuthService.initiateGoogleLogin()).called(1);
      verifyNever(mockAuthService.initiateGoogleNativeLogin());
    },
  );

  group('default provider callbacks report completion honestly', () {
    // flutter_login reads a null callback return as "the user is signed in" and
    // runs its post-login transition on it. These tests pin the contract that
    // keeps that transition from firing on a sign-in that has not happened.
    //
    // Widget tests report a mobile defaultTargetPlatform, so the default stub
    // (useNativeGoogle: true) exercises the native path; the web path has to be
    // opted into explicitly.

    Future<LoginProvider> providerNamed(
      WidgetTester tester,
      String label,
    ) async {
      final flutterLogin = await capture(
        tester,
        const LoginPage(title: 'Test App'),
      );
      return flutterLogin.loginProviders.firstWhere((p) => p.label == label);
    }

    testWidgets('the native Google button may animate — it resolves in-callback', (
      tester,
    ) async {
      final google = await providerNamed(tester, 'Google');
      expect(google.animated, isTrue);
    });

    testWidgets('the web Google button does not animate — it resolves out of band', (
      tester,
    ) async {
      stubAuthService(useNativeGoogle: false);
      final google = await providerNamed(tester, 'Google');
      expect(google.animated, isFalse);
    });

    testWidgets('native Google reports no error when sign-in succeeds', (
      tester,
    ) async {
      when(
        mockAuthService.initiateGoogleNativeLogin(),
      ).thenAnswer((_) async => true);
      final google = await providerNamed(tester, 'Google');
      expect(await google.callback(), isNull);
    });

    testWidgets('native Google reports failure — silently — when cancelled', (
      tester,
    ) async {
      when(
        mockAuthService.initiateGoogleNativeLogin(),
      ).thenAnswer((_) async => false);
      final google = await providerNamed(tester, 'Google');
      final error = await google.callback();
      // Non-null so flutter_login does not animate the user into the app...
      expect(error, isNotNull);
      // ...but excluded so a deliberate cancel does not raise a toast.
      expect(google.errorsToExcludeFromErrorMessage, contains(error));
    });

    testWidgets('web Google reports no error once the browser is launched', (
      tester,
    ) async {
      stubAuthService(useNativeGoogle: false);
      when(mockAuthService.initiateGoogleLogin()).thenAnswer((_) async => true);
      final google = await providerNamed(tester, 'Google');
      expect(await google.callback(), isNull);
    });

    testWidgets('web Google surfaces an error when the browser cannot launch', (
      tester,
    ) async {
      stubAuthService(useNativeGoogle: false);
      when(mockAuthService.initiateGoogleLogin()).thenAnswer((_) async => false);
      final google = await providerNamed(tester, 'Google');
      final error = await google.callback();
      expect(error, isNotNull);
      // A genuine failure the user must see, so it is not suppressed.
      expect(google.errorsToExcludeFromErrorMessage, isNot(contains(error)));
    });

    testWidgets('Apple reports no error when sign-in succeeds', (tester) async {
      stubAuthService(appleIdentityProviderID: 'apple-idp');
      when(mockAuthService.initiateAppleLogin()).thenAnswer((_) async => true);
      final apple = await providerNamed(tester, 'Apple');
      expect(await apple.callback(), isNull);
    });

    testWidgets('Apple reports failure — silently — when cancelled', (
      tester,
    ) async {
      stubAuthService(appleIdentityProviderID: 'apple-idp');
      when(mockAuthService.initiateAppleLogin()).thenAnswer((_) async => false);
      final apple = await providerNamed(tester, 'Apple');
      final error = await apple.callback();
      expect(error, isNotNull);
      expect(apple.errorsToExcludeFromErrorMessage, contains(error));
    });
  });

  test(
    'asserts that an explicitly empty socialProviders list is rejected when '
    'email/password is disabled',
    () {
      expect(
        () => LoginPage(
          enableEmailPassword: false,
          socialProviders: const [],
        ),
        throwsA(isA<AssertionError>()),
      );
    },
  );

  test(
    'allows a null socialProviders with email/password disabled — the default '
    'providers are non-empty, so the page is still reachable',
    () {
      expect(() => LoginPage(enableEmailPassword: false), returnsNormally);
    },
  );

  testWidgets(
    'falls back to the default providers when email/password is disabled and '
    'no socialProviders are given',
    (tester) async {
      stubAuthService(appleIdentityProviderID: 'apple-idp');
      final flutterLogin = await capture(
        tester,
        const LoginPage(title: 'Test App', enableEmailPassword: false),
      );
      expect(flutterLogin.hideUserNamePasswordLogin, isTrue);
      expect(
        flutterLogin.loginProviders.map((p) => p.label),
        ['Google', 'Apple'],
      );
    },
  );
}
