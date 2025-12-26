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
