# Owner-run Search Console consent

Run this helper on the same POSIX machine as the owner's ordinary browser. A
remote browser cannot reach its loopback callback without a deliberately
configured tunnel. The helper does not retrieve saved clients or grants from
OpenBao. Use the original Desktop-application JSON downloaded from your Google
Cloud project; a Web client is not accepted.

Create a private directory outside every Git checkout with mode 0700. Store the
Desktop-client JSON there with mode 0600. Use canonical absolute paths without
symlinks for the input and a new output file. Set CLIENT_JSON and GRANT_OUTPUT
to those paths. Choose CLOUD_PROJECT, GOOGLE_ACCOUNT and SEARCH_DOMAIN explicitly;
the helper checks the downloaded project's ID, verifies the actual consenting
identity and confines its allocation to the specified domain.

Prepare isolated dependencies in the source checkout:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-bootstrap.lock
.venv/bin/python authorize_search_console.py \
  --client-json "$CLIENT_JSON" \
  --cloud-project "$CLOUD_PROJECT" \
  --account "$GOOGLE_ACCOUNT" \
  --domain "$SEARCH_DOMAIN" \
  --output "$GRANT_OUTPUT"
```

The helper opens Google; the owner selects the intended account and completes
consent. It requests only openid, userinfo.email and webmasters.readonly, checks
returned scope evidence, requires a fresh offline grant and verifies the email.
OAuth values and provider errors are suppressed. A new mode-0600 record is saved
only after these checks; existing files are never overwritten. On failure,
report the safe phase/category, not raw provider responses.

Enable Search Console API in the selected cloud project and ensure the
consenting account has the required property access. Consent-screen app branding
is shared at the project level and may differ from the Desktop-client label.
See Google's [OAuth Desktop flow](https://developers.google.com/identity/protocols/oauth2/native-app)
and [branding guidance](https://developers.google.com/identity/siwg/best-practices).
The helper does not change project roles, API enablement or consent-screen status.

Open the saved record privately and enter its complete JSON in OpenBao at your
chosen project/credential path. Tell agents only that the grant is saved. Refresh
the catalog and run sites_list for that credential. Select the actual property,
then add its exact property string to the private _google_search_console object.
Alternatively, supply --property during consent if the exact verified property
is already known. Other reads require the pinned property.

Search Console inspection reports stored index state; it does not perform a
live-page test, expose Security Issues or clear a security warning. Use the
Search Console UI for those tasks. Keep all consent files and private operating
instructions outside the repository.
