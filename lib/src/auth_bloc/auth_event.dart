part of 'auth_bloc.dart';

abstract class AuthEvent {}

class AuthLogin extends AuthEvent {
  final String username;
  final String password;

  AuthLogin({required this.username, required this.password});
}

class AuthSignUp extends AuthEvent {
  final String username;
  final String password;

  AuthSignUp({required this.username, required this.password});
}

class AuthRecoverPassword extends AuthEvent {
  final String email;

  AuthRecoverPassword({required this.email});
}

class AuthLogout extends AuthEvent {}

class AuthCheckStatus extends AuthEvent {}

/// Internal — dispatched when [AuthService.accessTokenStream] emits a new
/// access token (login, signup, IdP exchange, or a silent background refresh).
/// Makes the bloc re-emit [AuthAuthenticated] carrying the current token so
/// consumers that cache it stay in step.
class AuthTokenRefreshed extends AuthEvent {}
