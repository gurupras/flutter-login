import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:flutter_vector_icons/flutter_vector_icons.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';
import 'package:liblogin/src/auth_service.dart';

class LoginPage extends StatelessWidget {
  final OnLoginSuccess? onLoginSuccess;
  final OnLoginError? onLoginFailure;

  const LoginPage({super.key, this.onLoginSuccess, this.onLoginFailure});

  @override
  Widget build(BuildContext context) {
    return BlocListener<AuthBloc, AuthState>(
      listener: (context, state) {
        if (state is AuthAuthenticated) {
          onLoginSuccess?.call(state.accessToken);
        } else if (state is AuthError) {
          onLoginFailure?.call(state.message);
        }
      },
      child: FlutterLogin(
        title: 'Filemingo', // This can be made configurable if needed
        onLogin: (loginData) async {
          BlocProvider.of<AuthBloc>(context).add(
            AuthLogin(username: loginData.name, password: loginData.password),
          );
          return null; // Handled by BlocListener
        },
        onSignup: (signupData) async {
          BlocProvider.of<AuthBloc>(context).add(
            AuthSignUp(
              username: signupData.name!,
              password: signupData.password!,
            ),
          );
          return null; // Handled by BlocListener
        },
        onRecoverPassword: (email) async {
          BlocProvider.of<AuthBloc>(context).add(AuthRecoverPassword(email: email));
          return null; // Handled by BlocListener
        },
        loginProviders: [
          LoginProvider(
            icon: FontAwesome.google,
            label: 'Google',
            callback: () async {
              final authService = RepositoryProvider.of<AuthService>(context);
              final success = await authService.initiateGoogleLogin();
              if (!success) {
                onLoginFailure?.call('Failed to initiate Google login');
              }
              return null; // Handled by BlocListener
            },
          ),
        ],
        // Removed onSubmitAnimationCompleted as it's now handled by callbacks
      ),
    );
  }
}
