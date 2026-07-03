import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_vector_icons/flutter_vector_icons.dart';
import 'package:liblogin/liblogin.dart';
import 'package:widgetbook/widgetbook.dart';

void main() {
  runApp(const LibloginWidgetbook());
}

/// A demo [LoginConfig]. The values are illustrative — the widgetbook never
/// hits the network, it only renders the [LoginPage] chrome. `appleBundleID`
/// and `appleIdentityProviderID` are the only knobs that change which built-in
/// providers the default resolver renders.
LoginConfig demoConfig({
  String? appleIdentityProviderID,
  String? appleBundleID,
  bool useNativeGoogle = true,
}) {
  return LoginConfig(
    loginDomain: 'https://auth.twoseven.xyz',
    signupOrigin: 'https://twoseven.xyz',
    loginTenantID: '676c7011-741e-4145-bcb8-b8bd12ba1ee3',
    loginClientID: 'ac6ab5ba-3bf2-4f87-a95d-cccf8424844f',
    loginRedirectURI: 'xyz.twoseven.app.flutterRemoteControl://callback',
    googleIdentityProviderID: '82339786-3dff-42a6-aac6-1f1ceecb6c46',
    googleServerClientId: 'demo-web-client-id.apps.googleusercontent.com',
    appleIdentityProviderID: appleIdentityProviderID,
    appleBundleID: appleBundleID,
    useNativeGoogle: useNativeGoogle,
  );
}

/// Owns a real [AuthService] + [AuthBloc] for a preview so [LoginPage] can read
/// them from the tree. Nothing here performs I/O on build — the social
/// callbacks are inert in the widgetbook. Disposed when the use case changes.
class LibloginPreview extends StatefulWidget {
  const LibloginPreview({
    super.key,
    required this.config,
    required this.child,
  });

  final LoginConfig config;
  final Widget child;

  @override
  State<LibloginPreview> createState() => _LibloginPreviewState();
}

class _LibloginPreviewState extends State<LibloginPreview> {
  late AuthService _authService;
  late AuthBloc _authBloc;

  @override
  void initState() {
    super.initState();
    _build();
  }

  @override
  void didUpdateWidget(covariant LibloginPreview oldWidget) {
    super.didUpdateWidget(oldWidget);
    // Rebuild the service/bloc when a knob changes the config identity.
    if (!identical(oldWidget.config, widget.config)) {
      _authBloc.close();
      _authService.dispose();
      _build();
    }
  }

  void _build() {
    _authService = AuthService(config: widget.config);
    _authBloc = AuthBloc(authService: _authService);
  }

  @override
  void dispose() {
    _authBloc.close();
    _authService.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return BlocProvider<AuthBloc>.value(value: _authBloc, child: widget.child);
  }
}

// ---------------------------------------------------------------------------
// Use cases
// ---------------------------------------------------------------------------

/// Email/password + a single Google provider — the library default. Google has
/// no [LoginProvider.button], so flutter_login renders it as a compact icon in
/// the providers row rather than a full-width button.
Widget emailWithSingleSocial(BuildContext context) {
  return LibloginPreview(
    config: demoConfig(),
    child: const LoginPage(title: 'Email + 1 social (Google icon)'),
  );
}

/// Email/password + Google (icon) and Apple (full-width button). Setting
/// [LoginConfig.appleIdentityProviderID] makes the default resolver append the
/// Apple provider, which uses `Buttons.apple` and therefore renders long-form.
Widget emailWithMultipleSocial(BuildContext context) {
  return LibloginPreview(
    config: demoConfig(
      appleIdentityProviderID: 'c1763265-fa18-4aab-bb53-69fe78ac0e6f',
      appleBundleID: 'xyz.twoseven.app.flutterRemoteControl',
    ),
    child: const LoginPage(title: 'Email + Google & Apple'),
  );
}

/// Email/password + several providers rendered as **icons** (no [button] set),
/// so flutter_login lays them out as a compact icon row instead of stacked
/// long-form buttons.
Widget emailWithSocialIcons(BuildContext context) {
  return LibloginPreview(
    config: demoConfig(),
    child: LoginPage(
      title: 'Email + social icons',
      socialProviders: [
        LoginProvider(
          icon: FontAwesome.google,
          label: 'Google',
          callback: () async => null,
        ),
        LoginProvider(
          icon: FontAwesome.github,
          label: 'GitHub',
          callback: () async => null,
        ),
        LoginProvider(
          icon: FontAwesome.apple,
          label: 'Apple',
          callback: () async => null,
        ),
      ],
    ),
  );
}

/// Email/password + the same providers rendered as **long-form buttons** by
/// giving each a [LoginProvider.button] (a `Buttons` value). Contrast with
/// [emailWithSocialIcons] to see the icon-row vs. button-column difference.
Widget emailWithSocialButtons(BuildContext context) {
  return LibloginPreview(
    config: demoConfig(),
    child: LoginPage(
      title: 'Email + long-form buttons',
      socialProviders: [
        LoginProvider(
          button: Buttons.google,
          label: 'Sign in with Google',
          callback: () async => null,
        ),
        LoginProvider(
          button: Buttons.apple,
          label: 'Sign in with Apple',
          callback: () async => null,
        ),
      ],
    ),
  );
}

/// Email/password with **no** social providers. Passing an empty
/// `socialProviders` list bypasses the default resolver entirely.
Widget emailOnly(BuildContext context) {
  return LibloginPreview(
    config: demoConfig(),
    child: const LoginPage(
      title: 'Email only',
      socialProviders: [],
    ),
  );
}

/// Social only (email/password hidden) with Google (icon) + Apple (button),
/// resolved from config.
Widget socialOnlyMultiple(BuildContext context) {
  return LibloginPreview(
    config: demoConfig(
      appleIdentityProviderID: 'c1763265-fa18-4aab-bb53-69fe78ac0e6f',
      appleBundleID: 'xyz.twoseven.app.flutterRemoteControl',
    ),
    child: LoginPage(
      title: 'Social only — Google & Apple',
      enableEmailPassword: false,
      socialProviders: [
        LoginProvider(
          button: Buttons.google,
          label: 'Sign in with Google',
          callback: () async => null,
        ),
        LoginProvider(
          button: Buttons.apple,
          label: 'Sign in with Apple',
          callback: () async => null,
        ),
      ],
    ),
  );
}

/// Social only with a single Google icon provider.
Widget socialOnlySingleIcon(BuildContext context) {
  return LibloginPreview(
    config: demoConfig(),
    child: LoginPage(
      title: 'Social only — single Google',
      enableEmailPassword: false,
      socialProviders: [
        LoginProvider(
          icon: FontAwesome.google,
          label: 'Google',
          callback: () async => null,
        ),
      ],
    ),
  );
}

class LibloginWidgetbook extends StatelessWidget {
  const LibloginWidgetbook({super.key});

  @override
  Widget build(BuildContext context) {
    return Widgetbook.material(
      addons: [
        MaterialThemeAddon(
          themes: [
            WidgetbookTheme(name: 'Light', data: ThemeData.light()),
            WidgetbookTheme(name: 'Dark', data: ThemeData.dark()),
          ],
        ),
        TextScaleAddon(min: 1.0, max: 2.0, initialScale: 1.0),
        InspectorAddon(),
      ],
      directories: [
        WidgetbookComponent(
          name: 'LoginPage — with email/password',
          isInitiallyExpanded: true,
          useCases: [
            WidgetbookUseCase(
              name: 'Email + 1 social (Google icon)',
              builder: emailWithSingleSocial,
            ),
            WidgetbookUseCase(
              name: 'Email + multiple social (Google + Apple)',
              builder: emailWithMultipleSocial,
            ),
            WidgetbookUseCase(
              name: 'Email + social as icons',
              builder: emailWithSocialIcons,
            ),
            WidgetbookUseCase(
              name: 'Email + social as long-form buttons',
              builder: emailWithSocialButtons,
            ),
            WidgetbookUseCase(
              name: 'Email only (no social)',
              builder: emailOnly,
            ),
          ],
        ),
        WidgetbookComponent(
          name: 'LoginPage — social only',
          useCases: [
            WidgetbookUseCase(
              name: 'Social only — Google & Apple',
              builder: socialOnlyMultiple,
            ),
            WidgetbookUseCase(
              name: 'Social only — single Google icon',
              builder: socialOnlySingleIcon,
            ),
          ],
        ),
      ],
    );
  }
}
