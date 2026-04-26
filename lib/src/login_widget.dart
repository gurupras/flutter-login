import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:flutter_vector_icons/flutter_vector_icons.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';
import 'package:liblogin/src/auth_service.dart';

class LoginPage extends StatelessWidget {
  final String title;
  final bool enableEmailPassword;
  final List<LoginProvider>? socialProviders;
  final List<TermOfService> termsOfService;

  const LoginPage({
    super.key,
    this.title = 'App',
    this.enableEmailPassword = true,
    this.socialProviders,
    this.termsOfService = const <TermOfService>[],
  }) : assert(
         enableEmailPassword ||
             (socialProviders != null && socialProviders.length > 0),
         'socialProviders must be non-empty when enableEmailPassword is false.',
       );

  List<LoginProvider> _resolveProviders(BuildContext context) {
    if (socialProviders != null) return socialProviders!;
    return [
      LoginProvider(
        icon: FontAwesome.google,
        label: 'Google',
        callback: () async {
          final authService = context.read<AuthService>();
          await authService.initiateGoogleLogin();
          return null;
        },
      ),
    ];
  }

  @override
  Widget build(BuildContext context) {
    return BlocListener<AuthBloc, AuthState>(
      listener: (context, state) {
        if (state is AuthError) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text(state.message),
              backgroundColor: Theme.of(context).colorScheme.error,
            ),
          );
        }
      },
      child: FlutterLogin(
        title: title,
        hideUserNamePasswordLogin: !enableEmailPassword,
        loginProviders: _resolveProviders(context),
        termsOfService: termsOfService,
        onLogin: (loginData) async {
          final bloc = context.read<AuthBloc>();
          final completer = Completer<String?>();

          late StreamSubscription subscription;
          subscription = bloc.stream.listen((state) {
            if (state is AuthAuthenticated) {
              completer.complete(null);
              subscription.cancel();
            } else if (state is AuthError) {
              completer.complete(state.message);
              subscription.cancel();
            }
          });

          bloc.add(
            AuthLogin(username: loginData.name, password: loginData.password),
          );

          return completer.future;
        },
        onSignup: (signupData) async {
          final bloc = context.read<AuthBloc>();
          final completer = Completer<String?>();

          late StreamSubscription subscription;
          subscription = bloc.stream.listen((state) {
            if (state is AuthAuthenticated) {
              completer.complete(null);
              subscription.cancel();
            } else if (state is AuthError) {
              completer.complete(state.message);
              subscription.cancel();
            }
          });

          bloc.add(
            AuthSignUp(
              username: signupData.name!,
              password: signupData.password!,
            ),
          );

          return completer.future;
        },
        onRecoverPassword: (email) async {
          final bloc = context.read<AuthBloc>();
          final completer = Completer<String?>();

          late StreamSubscription subscription;
          subscription = bloc.stream.listen((state) {
            if (state is AuthRecoverPasswordSuccess) {
              completer.complete(null);
              subscription.cancel();
            } else if (state is AuthError) {
              completer.complete(state.message);
              subscription.cancel();
            }
          });

          bloc.add(AuthRecoverPassword(email: email));

          return completer.future;
        },
      ),
    );
  }
}
