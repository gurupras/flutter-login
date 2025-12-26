import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:flutter_vector_icons/flutter_vector_icons.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';
import 'package:liblogin/src/auth_service.dart';

class LoginPage extends StatelessWidget {
  final ValueChanged<String>? onLoginSuccess;
  final ValueChanged<String>? onLoginFailure;

  const LoginPage({super.key, this.onLoginSuccess, this.onLoginFailure});

  @override
  Widget build(BuildContext context) {
    return FlutterLogin(
      title: 'Filemingo', // This can be made configurable if needed
      onLogin: (loginData) async {
        final authBloc = BlocProvider.of<AuthBloc>(context);
        authBloc.add(
          AuthLogin(username: loginData.name, password: loginData.password),
        );
        final authState = await authBloc.stream.firstWhere(
          (state) => state is AuthAuthenticated || state is AuthError,
        );
        if (authState is AuthAuthenticated) {
          onLoginSuccess?.call(loginData.name); // Call success callback
          return null;
        } else if (authState is AuthError) {
          onLoginFailure?.call(authState.message); // Call failure callback
          return authState.message;
        }
        onLoginFailure?.call(
          'An unknown error occurred',
        ); // Call failure callback
        return 'An unknown error occurred';
      },
      onSignup: (signupData) async {
        final authBloc = BlocProvider.of<AuthBloc>(context);
        authBloc.add(
          AuthSignUp(
            username: signupData.name!,
            password: signupData.password!,
          ),
        );
        final authState = await authBloc.stream.firstWhere(
          (state) => state is AuthAuthenticated || state is AuthError,
        );
        if (authState is AuthAuthenticated) {
          onLoginSuccess?.call(signupData.name!); // Call success callback
          return null;
        } else if (authState is AuthError) {
          onLoginFailure?.call(authState.message); // Call failure callback
          return authState.message;
        }
        onLoginFailure?.call(
          'An unknown error occurred',
        ); // Call failure callback
        return 'An unknown error occurred';
      },
      onRecoverPassword: (email) async {
        final authBloc = BlocProvider.of<AuthBloc>(context);
        authBloc.add(AuthRecoverPassword(email: email));
        final authState = await authBloc.stream.firstWhere(
          (state) => state is AuthRecoverPasswordSuccess || state is AuthError,
        );
        if (authState is AuthError) {
          onLoginFailure?.call(authState.message); // Call failure callback
          return authState.message;
        }
        return null;
      },
      loginProviders: [
        LoginProvider(
          icon: FontAwesome.google,
          label: 'Google',
          callback: () async {
            final authService = RepositoryProvider.of<AuthService>(context);
            final success = await authService.initiateGoogleLogin();
            if (success) {
              // Google login initiated, waiting for redirect.
              // The actual success/failure will be handled by the authRedirectStream listener
              // in AuthService, which will then trigger AuthCheckStatus.
              // The LoginPage's BlocBuilder will then react to AuthAuthenticated/AuthError.
              return null;
            } else {
              onLoginFailure?.call(
                'Failed to initiate Google login',
              ); // Call failure callback
              return 'Failed to initiate Google login';
            }
          },
        ),
      ],
      // Removed onSubmitAnimationCompleted as it's now handled by callbacks
    );
  }
}
