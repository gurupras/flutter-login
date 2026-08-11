import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:flutter_vector_icons/flutter_vector_icons.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';

/// Returned by a social-provider callback when sign-in did not complete — the
/// user dismissed the provider sheet, or the provider itself failed.
///
/// flutter_login treats a `null` return as "the user is now signed in" and runs
/// its post-login transition on the strength of it. Returning this sentinel
/// instead keeps that transition from firing, while
/// [LoginProvider.errorsToExcludeFromErrorMessage] suppresses the error toast
/// so a deliberate cancel stays silent.
const String _signInNotCompleted = 'liblogin:sign-in-not-completed';

/// Shown when the external browser could not be launched for the web OAuth
/// flow. Unlike [_signInNotCompleted] this is a genuine failure the user needs
/// to see, so it is not excluded from the error toast.
const String _couldNotOpenSignIn = 'Could not open the sign-in page.';

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
         // A null [socialProviders] means "use the built-in defaults", which
         // always include Google, so it can never strand the user on a login
         // page with no way in. Only an explicitly empty list can do that, and
         // that is what this guards against — requiring non-null here would
         // force callers who just want the defaults to restate them.
         // ignore: prefer_is_not_empty — `isNotEmpty` is not const-evaluable,
         // and this assert runs in a const constructor.
         enableEmailPassword ||
             socialProviders == null ||
             socialProviders.length > 0,
         'socialProviders must be non-empty when email/password login is '
         'disabled. Pass null to use the default providers instead.',
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
    // Prefer the native google_sign_in sheet on iOS/Android; fall back to the
    // web OAuth flow everywhere else (web/desktop) or when the consumer opts
    // out via LoginConfig.useNativeGoogle. Resolved out here rather than inside
    // the callback because it also decides whether the button may animate.
    final useNativeGoogle =
        authService.config.useNativeGoogle &&
        !kIsWeb &&
        (defaultTargetPlatform == TargetPlatform.iOS ||
            defaultTargetPlatform == TargetPlatform.android);
    final providers = <LoginProvider>[
      LoginProvider(
        icon: FontAwesome.google,
        label: 'Google',
        // The native sheet resolves fully inside the callback, so success there
        // is real and flutter_login's post-login transition is truthful.
        //
        // The web flow is not: it hands off to an external browser and returns
        // as soon as that browser has launched, with the outcome only arriving
        // later via [AuthService.authRedirectStream]. No point in that callback
        // can report success honestly, so the button stays unanimated —
        // flutter_login runs its transition off a successful callback, and
        // running it there would walk the user into the app before they had
        // signed in.
        animated: useNativeGoogle,
        errorsToExcludeFromErrorMessage: const [_signInNotCompleted],
        callback: () async {
          if (useNativeGoogle) {
            final signedIn = await authService.initiateGoogleNativeLogin();
            return signedIn ? null : _signInNotCompleted;
          }
          final launched = await authService.initiateGoogleLogin();
          return launched ? null : _couldNotOpenSignIn;
        },
      ),
    ];
    if (authService.config.appleIdentityProviderID != null) {
      providers.add(
        LoginProvider(
          button: Buttons.apple,
          label: 'Apple',
          // Sign in with Apple is native and resolves fully inside the
          // callback, so success here is real and the post-login transition is
          // truthful. A cancelled or failed attempt must still report failure
          // rather than null, or flutter_login animates away regardless.
          errorsToExcludeFromErrorMessage: const [_signInNotCompleted],
          callback: () async {
            final signedIn = await authService.initiateAppleLogin();
            return signedIn ? null : _signInNotCompleted;
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
