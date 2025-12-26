import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:flutter_vector_icons/flutter_vector_icons.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';
import 'package:liblogin/src/auth_service.dart';

class LoginPage extends StatelessWidget {
  const LoginPage({super.key});

  @override
  Widget build(BuildContext context) {
    return BlocListener<AuthBloc, AuthState>(
      listener: (context, state) {
        // The parent widget should listen to AuthBloc states for success/failure
        // No direct callbacks from LoginPage
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
                // The parent widget should listen to AuthBloc states for success/failure
                // No direct callbacks from LoginPage
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
