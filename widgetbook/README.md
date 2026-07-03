# liblogin widgetbook

A [Widgetbook](https://widgetbook.io) app for previewing the different
`LoginPage` configurations that `liblogin` exposes — without wiring up a real
FusionAuth backend. Nothing here performs network I/O; the social-button
callbacks are inert.

## Run it

```bash
cd widgetbook
flutter pub get
flutter run            # any device, or:
flutter run -d chrome  # in a browser
```

Use the left-hand navigation to switch between use cases, and the toolbar
add-ons to toggle light/dark theme and text scaling.

## Use cases

**LoginPage — with email/password**

| Use case | What it shows |
| --- | --- |
| Email + 1 social (Google icon) | The library default: email/password plus the built-in Google provider, rendered as a compact **icon** (Google has no `button`, so flutter_login puts it in the icon row). |
| Email + multiple social (Google + Apple) | Setting `appleIdentityProviderID` appends the Apple provider, which uses `Buttons.apple` and renders as a full-width **long-form button** above the Google icon. |
| Email + social as icons | Several providers with only `icon:` set → compact **icon row**. |
| Email + social as long-form buttons | The same providers with `button:` set → stacked **long-form buttons**. Contrast with the icons case. |
| Email only (no social) | Passing an empty `socialProviders` list hides all providers. |

**LoginPage — social only**

| Use case | What it shows |
| --- | --- |
| Social only — Google & Apple | `enableEmailPassword: false` with two long-form buttons. |
| Social only — single Google icon | `enableEmailPassword: false` with one icon provider. |

## Icon vs. long-form button

flutter_login decides layout per provider:

- `LoginProvider(icon: ...)` (no `button`) → compact icon in a centered row.
- `LoginProvider(button: Buttons.x)` → full-width labelled button in a column.

The built-in Google provider uses `icon`, the built-in Apple provider uses
`button`, which is why they render differently in the default configuration.
