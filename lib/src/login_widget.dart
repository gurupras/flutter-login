import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:flutter_vector_icons/flutter_vector_icons.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';
import 'package:liblogin/src/auth_service.dart';

class LoginPage extends StatelessWidget {
  final String title;

  const LoginPage({super.key, this.title = 'App'});

  @override
  Widget build(BuildContext context) {
    return BlocListener<AuthBloc, AuthState>(
      listener: (context, state) {
        // Parent listens for auth success/failure
      },
      child: FlutterLogin(
        title: title,
        onLogin: (loginData) async {
          context.read<AuthBloc>().add(
            AuthLogin(username: loginData.name, password: loginData.password),
          );
          return null;
        },
        onSignup: (signupData) async {
          context.read<AuthBloc>().add(
            AuthSignUp(
              username: signupData.name!,
              password: signupData.password!,
            ),
          );
          return null;
        },
        onRecoverPassword: (email) async {
          context.read<AuthBloc>().add(AuthRecoverPassword(email: email));
          return null;
        },
        loginProviders: [
          LoginProvider(
            icon: FontAwesome.google,
            label: 'Google',
            callback: () async {
              final authService = context.read<AuthService>();
              final success = await authService.initiateGoogleLogin();
              if (!success) {
                // Parent handles error via Bloc
              }
              return null;
            },
          ),
        ],
      ),
    );
  }
}
