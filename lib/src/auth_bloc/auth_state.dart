part of 'auth_bloc.dart';

abstract class AuthState extends Equatable {
  @override
  List<Object?> get props => [];
}

class AuthInitial extends AuthState {}

class AuthLoading extends AuthState {}

class AuthAuthenticated extends AuthState {
  final String accessToken;
  final String? idToken;
  final DecodedAccessToken decodedAccessToken;

  AuthAuthenticated({
    required this.accessToken,
    this.idToken,
    required this.decodedAccessToken,
  });

  @override
  List<Object?> get props => [accessToken, idToken, decodedAccessToken];
}

class AuthUnauthenticated extends AuthState {}

class AuthError extends AuthState {
  final String message;

  AuthError({required this.message});

  @override
  List<Object> get props => [message];
}

class AuthRecoverPasswordSuccess extends AuthState {}
