import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_login/flutter_login.dart';
import 'package:liblogin/src/auth_bloc/auth_bloc.dart';
import 'package:liblogin/src/auth_models.dart';
import 'package:liblogin/src/auth_service.dart';

/// Returned by a social-provider callback when the user cancelled.
///
/// flutter_login reads `null` as "signed in" and any other string as an error
/// to show, so a cancel needs a string of its own that
/// [LoginProvider.errorsToExcludeFromErrorMessage] keeps silent.
const String _signInCancelled = 'liblogin:sign-in-cancelled';

/// Shown when the external browser could not be launched for the web OAuth
/// flow.
const String _couldNotOpenSignIn = "Couldn't open the sign-in page. Try again.";

/// What a flutter_login callback returns for a finished attempt: null for
/// success, the failure message to show, or the silent cancel marker.
String? _formReply(SignInResult result) => switch (result) {
  SignInSucceeded() => null,
  SignInCancelled() => _signInCancelled,
  SignInFailed(:final message) => message,
};

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
        // A full Google row keeps the brand and action together; native-only
        // animation preserves the upstream web-flow completion behavior.
        button: Buttons.google,
        label: 'Continue with Google',
        animated: useNativeGoogle,
        errorsToExcludeFromErrorMessage: const [_signInCancelled],
        callback: () async {
          if (useNativeGoogle) {
            return _formReply(await authService.initiateGoogleNativeLogin());
          }
          // The browser flow finishes later; its outcome is shown by
          // _RedirectFailureMessenger, not through this return value.
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
          errorsToExcludeFromErrorMessage: const [_signInCancelled],
          callback: () async =>
              _formReply(await authService.initiateAppleLogin()),
        ),
      );
    }
    return providers;
  }

  @override
  Widget build(BuildContext context) {
    final authService = context.read<AuthBloc>().authService;
    return _RedirectFailureMessenger(
      authService: authService,
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
        // Each attempt resolves inside its callback, so flutter_login shows a
        // failure in its own error banner. The session state is untouched
        // unless the attempt succeeds.
        onLogin: (loginData) async => _formReply(
          await authService.login(loginData.name, loginData.password),
        ),
        onSignup: (signupData) async => _formReply(
          await authService.signUp(signupData.name!, signupData.password!),
        ),
        onRecoverPassword: authService.recoverPassword,
      ),
    );
  }
}

/// Shows a failed browser sign-in. That flow returns to the app through a
/// redirect long after the Google button's callback has finished, so no
/// flutter_login callback is left to report it.
class _RedirectFailureMessenger extends StatefulWidget {
  final AuthService authService;
  final Widget child;

  const _RedirectFailureMessenger({
    required this.authService,
    required this.child,
  });

  @override
  State<_RedirectFailureMessenger> createState() =>
      _RedirectFailureMessengerState();
}

class _RedirectFailureMessengerState extends State<_RedirectFailureMessenger> {
  StreamSubscription<SignInResult>? _subscription;

  @override
  void initState() {
    super.initState();
    _subscribe();
  }

  @override
  void didUpdateWidget(_RedirectFailureMessenger oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.authService != widget.authService) {
      _subscription?.cancel();
      _subscribe();
    }
  }

  void _subscribe() {
    _subscription = widget.authService.signInResults.listen((result) {
      if (result is! SignInFailed || !mounted) return;
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(result.message),
          backgroundColor: Theme.of(context).colorScheme.error,
        ),
      );
    });
  }

  @override
  void dispose() {
    _subscription?.cancel();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) => widget.child;
}
