import 'dart:async';
import 'package:bloc_test/bloc_test.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';
import 'package:liblogin/src/auth_service.dart';
import 'package:liblogin/src/auth_models.dart';

import 'auth_bloc_test.mocks.dart';

@GenerateMocks([AuthService])
void main() {
  group('AuthBloc', () {
    late MockAuthService mockAuthService;
    late StreamController<String> accessTokenController;
    late StreamController<SignInResult> signInResultController;

    setUp(() {
      mockAuthService = MockAuthService();
      signInResultController = StreamController<SignInResult>.broadcast();
      when(mockAuthService.signInResults)
          .thenAnswer((_) => signInResultController.stream);
      accessTokenController = StreamController<String>.broadcast();
      when(mockAuthService.accessTokenStream)
          .thenAnswer((_) => accessTokenController.stream);
    });

    tearDown(() async {
      await accessTokenController.close();
      await signInResultController.close();
    });

    final mockDecodedToken = DecodedAccessToken(sub: 'test_sub');

    blocTest<AuthBloc, AuthState>(
      'emits [AuthInitial] when nothing is added',
      build: () => AuthBloc(authService: mockAuthService),
      expect: () => [],
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthUnauthenticated] when AuthLogout is successful',
      build: () {
        when(mockAuthService.logout()).thenAnswer((_) async => {});
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthLogout()),
      expect: () => [AuthUnauthenticated()],
      verify: (_) {
        verify(mockAuthService.logout()).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthAuthenticated] when AuthCheckStatus is authenticated',
      build: () {
        when(mockAuthService.checkLoginStatus()).thenAnswer((_) async => true);
        when(mockAuthService.currentAccessToken)
            .thenReturn('mock_access_token');
        when(mockAuthService.currentIdToken).thenReturn('mock_id_token');
        when(mockAuthService.decodedAccessToken).thenReturn(mockDecodedToken);
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthCheckStatus()),
      expect: () => [
        AuthLoading(),
        AuthAuthenticated(
          accessToken: 'mock_access_token',
          idToken: 'mock_id_token',
          decodedAccessToken: mockDecodedToken,
        )
      ],
      verify: (_) {
        verify(mockAuthService.checkLoginStatus()).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'offlineFirst: a stored session is authenticated with no status check',
      build: () {
        when(mockAuthService.restoreSession()).thenAnswer((_) async => true);
        when(mockAuthService.currentAccessToken).thenReturn('expired_token');
        when(mockAuthService.currentIdToken).thenReturn(null);
        when(mockAuthService.decodedAccessToken).thenReturn(mockDecodedToken);
        return AuthBloc(authService: mockAuthService, offlineFirst: true);
      },
      act: (bloc) => bloc.add(AuthCheckStatus()),
      expect: () => [
        AuthLoading(),
        AuthAuthenticated(
          accessToken: 'expired_token',
          decodedAccessToken: mockDecodedToken,
        ),
      ],
      verify: (_) {
        verifyNever(mockAuthService.checkLoginStatus());
      },
    );

    blocTest<AuthBloc, AuthState>(
      'offlineFirst: nothing stored is unauthenticated',
      build: () {
        when(mockAuthService.restoreSession()).thenAnswer((_) async => false);
        return AuthBloc(authService: mockAuthService, offlineFirst: true);
      },
      act: (bloc) => bloc.add(AuthCheckStatus()),
      expect: () => [AuthLoading(), AuthUnauthenticated()],
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthUnauthenticated] when AuthCheckStatus is unauthenticated',
      build: () {
        when(mockAuthService.checkLoginStatus()).thenAnswer((_) async => false);
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthCheckStatus()),
      expect: () => [AuthLoading(), AuthUnauthenticated()],
      verify: (_) {
        verify(mockAuthService.checkLoginStatus()).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'checks the session when a sign-in succeeds',
      build: () {
        when(mockAuthService.checkLoginStatus())
            .thenAnswer((_) async => true); // Mock for AuthCheckStatus
        when(mockAuthService.currentAccessToken)
            .thenReturn('mock_access_token');
        when(mockAuthService.currentIdToken).thenReturn('mock_id_token');
        when(mockAuthService.decodedAccessToken).thenReturn(mockDecodedToken);
        return AuthBloc(authService: mockAuthService);
      },
      act: (_) => signInResultController.add(const SignInSucceeded()),
      expect: () => [
        AuthLoading(),
        AuthAuthenticated(
          accessToken: 'mock_access_token',
          idToken: 'mock_id_token',
          decodedAccessToken: mockDecodedToken,
        )
      ],
      verify: (_) {
        verify(mockAuthService.checkLoginStatus()).called(1);
      },
    );

    // A failed attempt is not a change of session. Emitting AuthError here
    // would read as "signed out" to a consumer, and a signed-in user would be
    // thrown back to the start as if they had logged out.
    blocTest<AuthBloc, AuthState>(
      'leaves the session untouched when a sign-in fails',
      build: () => AuthBloc(authService: mockAuthService),
      seed: () => AuthUnauthenticated(),
      act: (_) => signInResultController
          .add(const SignInFailed("Couldn't sign in. Try again.")),
      expect: () => [],
      verify: (_) {
        verifyNever(mockAuthService.checkLoginStatus());
      },
    );

    blocTest<AuthBloc, AuthState>(
      'leaves the session untouched when a sign-in is cancelled',
      build: () => AuthBloc(authService: mockAuthService),
      seed: () => AuthUnauthenticated(),
      act: (_) => signInResultController.add(const SignInCancelled()),
      expect: () => [],
      verify: (_) {
        verifyNever(mockAuthService.checkLoginStatus());
      },
    );

    // Regression: AuthService refreshes the access token silently on a timer
    // ahead of expiry. Before this, the refreshed token never left the service —
    // the bloc kept advertising the token emitted at login, so consumers that
    // cached it (API clients, socket auth) went on using an expired token and
    // every authenticated request started failing with 401.
    blocTest<AuthBloc, AuthState>(
      're-emits AuthAuthenticated with the new token when accessTokenStream emits',
      build: () {
        when(mockAuthService.currentAccessToken)
            .thenReturn('refreshed_access_token');
        when(mockAuthService.currentIdToken)
            .thenReturn('refreshed_id_token');
        when(mockAuthService.decodedAccessToken).thenReturn(mockDecodedToken);
        return AuthBloc(authService: mockAuthService);
      },
      act: (_) => accessTokenController.add('refreshed_access_token'),
      // No AuthLoading: a background refresh must not bounce the app back
      // through a loading state.
      expect: () => [
        AuthAuthenticated(
          accessToken: 'refreshed_access_token',
          idToken: 'refreshed_id_token',
          decodedAccessToken: mockDecodedToken,
        )
      ],
      verify: (_) {
        // Straight from the service's current token — no storage round-trip.
        verifyNever(mockAuthService.checkLoginStatus());
      },
    );

    blocTest<AuthBloc, AuthState>(
      'ignores accessTokenStream emissions once the token is gone',
      build: () {
        when(mockAuthService.currentAccessToken).thenReturn(null);
        when(mockAuthService.decodedAccessToken).thenReturn(null);
        return AuthBloc(authService: mockAuthService);
      },
      act: (_) => accessTokenController.add('stale_token'),
      expect: () => [],
    );
  });
}
