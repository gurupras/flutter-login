import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:flutter_vector_icons/flutter_vector_icons.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';

class LoginPage extends StatelessWidget {
  final String title;
  final bool enableEmailPassword;
  final List<LoginProvider>? socialProviders;
  final List<TermOfService> termsOfService;

  /// Forwarded to [FlutterLogin.logo]. Accepts an asset path [String] or an
  /// [ImageProvider]; null hides the logo (FlutterLogin's default).
  final Object? logo;

  /// Forwarded to [FlutterLogin.messages]. Lets consumers customise prompt
  /// strings such as the "Or sign in with..." providers title.
  final LoginMessages? messages;

  /// Forwarded to [FlutterLogin.theme].
  final LoginTheme? theme;

  /// Forwarded to [FlutterLogin.headerWidget] — rendered above the auth card.
  final Widget? headerWidget;

  /// Forwarded to [FlutterLogin.footer] — rendered below the auth card.
  final String? footer;

  /// Forwarded to [FlutterLogin.hideProvidersTitle].
  final bool hideProvidersTitle;

  const LoginPage({
    super.key,
    this.title = 'App',
    this.enableEmailPassword = true,
    this.socialProviders,
    this.termsOfService = const <TermOfService>[],
    this.logo,
    this.messages,
    this.theme,
    this.headerWidget,
    this.footer,
    this.hideProvidersTitle = false,
  }) : assert(
         enableEmailPassword ||
             (socialProviders != null && socialProviders.length > 0),
         'socialProviders must be non-empty when enableEmailPassword is false.',
       ),
       assert(
         logo == null || logo is String || logo is ImageProvider,
         'logo must be a String (asset path) or an ImageProvider.',
       );

  List<LoginProvider> _resolveProviders(BuildContext context) {
    if (socialProviders != null) return socialProviders!;
    // AuthBloc is the canonical provider downstream consumers register, and
    // it holds an [AuthService] reference. Route through it so we don't
    // assume an independent Provider<AuthService> exists in the widget tree.
    final authService = context.read<AuthBloc>().authService;
    final providers = <LoginProvider>[
      LoginProvider(
        icon: FontAwesome.google,
        label: 'Google',
        callback: () async {
          await authService.initiateGoogleLogin();
          return null;
        },
      ),
    ];
    if (authService.config.appleIdentityProviderID != null) {
      providers.add(
        LoginProvider(
          button: Buttons.apple,
          label: 'Apple',
          callback: () async {
            await authService.initiateAppleLogin();
            return null;
          },
        ),
      );
    }
    return providers;
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
        logo: logo,
        messages: messages,
        theme: theme,
        headerWidget: headerWidget,
        footer: footer,
        hideProvidersTitle: hideProvidersTitle,
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
