import 'dart:async';

import 'package:bloc/bloc.dart';
import 'package:liblogin/src/auth_service.dart';
import 'package:liblogin/src/auth_models.dart';
import 'package:equatable/equatable.dart';

part 'auth_event.dart';
part 'auth_state.dart';

class AuthBloc extends Bloc<AuthEvent, AuthState> {
  final AuthService authService;

  StreamSubscription<SignInResult>? _signInResultSubscription;
  StreamSubscription<String>? _accessTokenSubscription;

  AuthBloc({required this.authService}) : super(AuthInitial()) {
    // Only a success changes the session. A failed or cancelled attempt is
    // shown on the login page and must not move the session state, or a
    // consumer that treats AuthError as "signed out" reacts as if it were a
    // logout.
    _signInResultSubscription = authService.signInResults.listen((result) {
      if (result is SignInSucceeded) {
        add(AuthCheckStatus());
      }
    });

    // Keep the emitted AuthAuthenticated in step with the service's current
    // token. AuthService refreshes silently on a timer ahead of expiry; without
    // this the bloc keeps advertising the token it emitted at login, and every
    // consumer that cached that token starts getting 401s once it expires.
    _accessTokenSubscription = authService.accessTokenStream.listen((_) {
      add(AuthTokenRefreshed());
    });

    on<AuthTokenRefreshed>((event, emit) {
      // Deliberately no AuthLoading — a silent background refresh must not
      // knock the app back into a loading state. AuthAuthenticated compares by
      // props (accessToken included), so an unchanged token is a no-op emit.
      final token = authService.currentAccessToken;
      final decoded = authService.decodedAccessToken;
      if (token == null || decoded == null) return;
      emit(AuthAuthenticated(
        accessToken: token,
        idToken: authService.currentIdToken,
        decodedAccessToken: decoded,
      ));
    });

    on<AuthLogout>((event, emit) async {
      try {
        await authService.logout();
        emit(AuthUnauthenticated());
      } catch (e) {
        emit(AuthError(message: e.toString()));
      }
    });

    on<AuthCheckStatus>((event, emit) async {
      try {
        emit(AuthLoading());
        final isAuthenticated = await authService.checkLoginStatus();
        if (isAuthenticated && authService.currentAccessToken != null) {
          emit(AuthAuthenticated(
            accessToken: authService.currentAccessToken!,
            idToken: authService.currentIdToken,
            decodedAccessToken: authService.decodedAccessToken!,
          ));
        } else {
          emit(AuthUnauthenticated());
        }
      } catch (e) {
        emit(AuthError(message: e.toString()));
      }
    });
  }

  @override
  Future<void> close() async {
    await _signInResultSubscription?.cancel();
    await _accessTokenSubscription?.cancel();
    authService.dispose();
    return super.close();
  }
}
