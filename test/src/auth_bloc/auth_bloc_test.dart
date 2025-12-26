import 'dart:async';
import 'package:bloc_test/bloc_test.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/annotations.dart';
import 'package:mockito/mockito.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';
import 'package:liblogin/src/auth_service.dart';

import 'auth_bloc_test.mocks.dart';

@GenerateMocks([AuthService])
void main() {
  group('AuthBloc', () {
    late MockAuthService mockAuthService;

    setUp(() {
      mockAuthService = MockAuthService();
      when(mockAuthService.authRedirectStream).thenAnswer((_) => Stream.empty());
    });

    blocTest<AuthBloc, AuthState>(
      'emits [AuthInitial] when nothing is added',
      build: () => AuthBloc(authService: mockAuthService),
      expect: () => [],
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthAuthenticated] when AuthLogin is successful',
      build: () {
        when(mockAuthService.login('test@example.com', 'password'))
            .thenAnswer((_) async => true);
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthLogin(username: 'test@example.com', password: 'password')),
      expect: () => [AuthLoading(), AuthAuthenticated()],
      verify: (_) {
        verify(mockAuthService.login('test@example.com', 'password')).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthError] when AuthLogin fails',
      build: () {
        when(mockAuthService.login('test@example.com', 'wrong_password'))
            .thenAnswer((_) async => false);
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthLogin(username: 'test@example.com', password: 'wrong_password')),
      expect: () => [AuthLoading(), AuthError(message: 'Login failed')],
      verify: (_) {
        verify(mockAuthService.login('test@example.com', 'wrong_password')).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthError] when AuthLogin throws an exception',
      build: () {
        when(mockAuthService.login(any, any))
            .thenThrow(Exception('Network error'));
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthLogin(username: 'test@example.com', password: 'password')),
      expect: () => [AuthLoading(), AuthError(message: 'Exception: Network error')],
      verify: (_) {
        verify(mockAuthService.login('test@example.com', 'password')).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthAuthenticated] when AuthSignUp is successful',
      build: () {
        when(mockAuthService.signUp('new@example.com', 'new_password'))
            .thenAnswer((_) async => true);
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthSignUp(username: 'new@example.com', password: 'new_password')),
      expect: () => [AuthLoading(), AuthAuthenticated()],
      verify: (_) {
        verify(mockAuthService.signUp('new@example.com', 'new_password')).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthError] when AuthSignUp fails',
      build: () {
        when(mockAuthService.signUp('new@example.com', 'new_password'))
            .thenAnswer((_) async => false);
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthSignUp(username: 'new@example.com', password: 'new_password')),
      expect: () => [AuthLoading(), AuthError(message: 'Sign up failed')],
      verify: (_) {
        verify(mockAuthService.signUp('new@example.com', 'new_password')).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthRecoverPasswordSuccess] when AuthRecoverPassword is successful',
      build: () {
        when(mockAuthService.recoverPassword('recover@example.com'))
            .thenAnswer((_) async => true);
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthRecoverPassword(email: 'recover@example.com')),
      expect: () => [AuthLoading(), AuthRecoverPasswordSuccess()],
      verify: (_) {
        verify(mockAuthService.recoverPassword('recover@example.com')).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'emits [AuthLoading, AuthError] when AuthRecoverPassword fails',
      build: () {
        when(mockAuthService.recoverPassword('recover@example.com'))
            .thenAnswer((_) async => false);
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthRecoverPassword(email: 'recover@example.com')),
      expect: () => [AuthLoading(), AuthError(message: 'Password recovery failed')],
      verify: (_) {
        verify(mockAuthService.recoverPassword('recover@example.com')).called(1);
      },
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
        return AuthBloc(authService: mockAuthService);
      },
      act: (bloc) => bloc.add(AuthCheckStatus()),
      expect: () => [AuthLoading(), AuthAuthenticated()],
      verify: (_) {
        verify(mockAuthService.checkLoginStatus()).called(1);
      },
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
      'adds AuthCheckStatus when authRedirectStream emits true',
      build: () {
        final authRedirectController = StreamController<bool>();
        when(mockAuthService.authRedirectStream).thenAnswer((_) => authRedirectController.stream);
        when(mockAuthService.checkLoginStatus()).thenAnswer((_) async => true); // Mock for AuthCheckStatus
        final bloc = AuthBloc(authService: mockAuthService);
        authRedirectController.add(true);
        return bloc;
      },
      expect: () => [AuthLoading(), AuthAuthenticated()],
      verify: (_) {
        verify(mockAuthService.checkLoginStatus()).called(1);
      },
    );

    blocTest<AuthBloc, AuthState>(
      'does not add AuthCheckStatus when authRedirectStream emits false',
      build: () {
        final authRedirectController = StreamController<bool>();
        when(mockAuthService.authRedirectStream).thenAnswer((_) => authRedirectController.stream);
        when(mockAuthService.checkLoginStatus()).thenAnswer((_) async => true); // Mock for AuthCheckStatus
        final bloc = AuthBloc(authService: mockAuthService);
        authRedirectController.add(false);
        return bloc;
      },
      expect: () => [], // No state changes expected
      verify: (_) {
        verifyNever(mockAuthService.checkLoginStatus());
      },
    );
  });
}
