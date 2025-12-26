import 'package:bloc/bloc.dart';
import 'package:liblogin/src/auth_service.dart';
import 'package:equatable/equatable.dart'; // Added equatable import

part 'auth_event.dart';
part 'auth_state.dart';

class AuthBloc extends Bloc<AuthEvent, AuthState> {
  final AuthService authService;

  AuthBloc({required this.authService}) : super(AuthInitial()) {
    authService.authRedirectStream.listen((success) {
      if (success) {
        add(AuthCheckStatus());
      }
    });
    on<AuthLogin>((event, emit) async {
      try {
        emit(AuthLoading());
        final success = await authService.login(event.username, event.password);
        if (success && authService.currentAccessToken != null) {
          emit(AuthAuthenticated(accessToken: authService.currentAccessToken!));
        } else {
          emit(AuthError(message: 'Login failed'));
        }
      } catch (e) {
        emit(AuthError(message: e.toString()));
      }
    });

    on<AuthSignUp>((event, emit) async {
      try {
        emit(AuthLoading());
        final success = await authService.signUp(
          event.username,
          event.password,
        );
        if (success && authService.currentAccessToken != null) {
          emit(AuthAuthenticated(accessToken: authService.currentAccessToken!));
        } else {
          emit(AuthError(message: 'Sign up failed'));
        }
      } catch (e) {
        emit(AuthError(message: e.toString()));
      }
    });

    on<AuthRecoverPassword>((event, emit) async {
      try {
        emit(AuthLoading());
        final success = await authService.recoverPassword(event.email);
        if (success) {
          emit(AuthRecoverPasswordSuccess());
        } else {
          emit(AuthError(message: 'Password recovery failed'));
        }
      } catch (e) {
        emit(AuthError(message: e.toString()));
      }
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
          emit(AuthAuthenticated(accessToken: authService.currentAccessToken!));
        } else {
          emit(AuthUnauthenticated());
        }
      } catch (e) {
        emit(AuthError(message: e.toString()));
      }
    });
  }

  @override
  Future<void> close() {
    authService.dispose();
    return super.close();
  }
}
