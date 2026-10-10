part of 'auth_bloc.dart';

/// Session events only. A sign-in attempt is not one: it runs through
/// [AuthService] and reaches the bloc as [SignInSucceeded] on
/// [AuthService.signInResults]. A failed or cancelled attempt leaves the
/// session exactly as it was.
abstract class AuthEvent {}

class AuthLogout extends AuthEvent {}

class AuthCheckStatus extends AuthEvent {}

/// Internal — dispatched when [AuthService.accessTokenStream] emits a new
/// access token (login, signup, IdP exchange, or a silent background refresh).
/// Makes the bloc re-emit [AuthAuthenticated] carrying the current token so
/// consumers that cache it stay in step.
class AuthTokenRefreshed extends AuthEvent {}
