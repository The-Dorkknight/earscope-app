# Publishing: GitHub, signing and releases

## 1. One-time GitHub setup

1. Create an account at https://github.com.
2. **Keep your email private.** Every commit records an email address, and it
   is public on GitHub. Go to *Settings → Emails*, tick **Keep my email
   addresses private**, and copy the `…@users.noreply.github.com` address shown.
   Then run:
   ```sh
   git config --global user.name  "Matthew Armstrong"
   git config --global user.email "12345678+you@users.noreply.github.com"
   ```
3. Install the GitHub CLI from https://cli.github.com and log in:
   ```sh
   gh auth login
   ```

## 2. Publish this project

The folder already contains a git repository with the first commit and a
`v1.0.0` tag. From inside it:

```sh
git config user.email "12345678+The-Dorkknight@users.noreply.github.com"   # your no-reply address, from step 1
git commit --amend --reset-author --no-edit
git tag -f v1.0.0
gh repo create ear-violator-4000 --public --source=. --push
git push origin v1.0.0
```

(The first commit was made with a placeholder no-reply address. The two middle
commands swap in yours before anything is pushed.)

Keep the repo name `ear-violator-4000` unless you also change it in
`pyproject.toml`. The web page works out its links from the address it's
served from, so it copes either way.

GitHub starts building the APK straight away. Watch it on the repo's
**Actions** tab. When it finishes, the APK is under the run's **Artifacts**
section.

## 3. Turn on the project page

The `docs/` folder is a ready-made web page. To publish it for free with
GitHub Pages, run:

```sh
gh api -X POST repos/{owner}/ear-violator-4000/pages -f "source[branch]=main" -f "source[path]=/docs"
```

Or on the website: *Settings → Pages → Build and deployment*, choose
**Deploy from a branch**, pick **main** and **/docs**, then **Save**.

After a minute it's live at `https://The-Dorkknight.github.io/ear-violator-4000/`.
Share that link.

### Adding your photos

Put your own photos in `docs/images/` with these exact names, then commit and
push:

| File | What |
|---|---|
| `unit.jpg` | The scope itself |
| `unit-2.jpg` | Another angle, such as the tip and light ring |
| `real-feed.jpg` | A screenshot of the viewer showing a real picture |

The **Hardware** section of the page appears automatically once at least one
of these exists, and stays hidden until then. Photos from phones can be
large, so resizing them to about 1600 px wide first keeps the page quick.

Phone photos can include your location in hidden EXIF data. Strip it before
uploading: on Linux, `exiftool -all= unit.jpg`, or re-save the image from an
image editor with metadata turned off.

The GUI screenshots in `docs/images/gui-*.webp` use a test pattern. Replace
them with your own screenshots if you like.

## 4. Create your signing key (do this before your first public release)

Android only lets an update install over an older version if both are signed
with the same key. Without your own key, each GitHub build is signed with a
random throwaway key, and users would have to uninstall before every update.

Create a key once. `keytool` comes with any Java 17 install, including the one
Briefcase downloaded if you built locally.

```sh
keytool -genkeypair -v -keystore earscope-release.jks -alias earscope \
        -keyalg RSA -keysize 4096 -validity 10000
```

Pick a strong password. **Back up `earscope-release.jks` and the password
somewhere safe, such as a password manager.** If you lose either, you can never
ship an update that installs over the existing app. The `.gitignore` already
stops `.jks` files from being committed.

Give the key to GitHub as encrypted secrets:

```sh
# macOS / Linux
base64 < earscope-release.jks | tr -d '\n' | gh secret set ANDROID_KEYSTORE_BASE64
# Windows PowerShell
[Convert]::ToBase64String([IO.File]::ReadAllBytes("earscope-release.jks")) | gh secret set ANDROID_KEYSTORE_BASE64

gh secret set ANDROID_KEYSTORE_PASSWORD   # paste the keystore password
gh secret set ANDROID_KEY_ALIAS           # type: earscope
gh secret set ANDROID_KEY_PASSWORD        # paste the key password (usually the same)
```

From then on, builds produce a properly signed `EarViolator4000-x.y.z.apk` instead of
a `-debug` one.

## 5. Make a release

```sh
git tag v1.0.0
git push origin v1.0.0
```

The workflow sets the app version from the tag, builds and signs the APK, and
publishes a **Release** with the APK and `SHA256SUMS.txt` attached. It also
writes release notes from your commits.

For the next version, commit your changes, then tag `v1.0.1`, `v1.1.0` and so
on. Tags must go up: Android refuses to install a lower version over a higher
one.

## If a build fails

Open the failed run on the **Actions** tab and expand the red step. You can
re-run a build without pushing anything using **Run workflow** on the Actions
tab.
