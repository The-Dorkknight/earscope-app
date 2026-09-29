# Required Notice: Copyright (c) 2026 Matthew Armstrong (https://github.com/The-Dorkknight)
# Licensed under the PolyForm Noncommercial License 1.0.0 (see LICENSE). No warranty.
"""
Tmu Ear Violator 4000 Streamer - Android wrapper around ne3web.py.

Starts the camera receiver and the local web server inside the app, then
shows the viewer in a built-in WebView. Nothing leaves the phone: the only
network traffic is UDP to the scope (192.168.169.1) and HTTP on 127.0.0.1.
"""
import os
import threading

import toga
from toga.style import Pack

from . import ne3web

try:  # Only present when running on Android (Chaquopy)
    from java import jclass
    ANDROID = True
except ImportError:
    ANDROID = False


# ---------------------------------------------------------------------------
# Android helpers
# ---------------------------------------------------------------------------
def make_wifi_binder(activity):
    """Return a hook that pins a socket to the WiFi network.

    Phones often send traffic over mobile data when the connected WiFi has
    no internet (the scope's doesn't). Binding just our UDP socket to the
    WiFi network fixes that without touching anything else on the phone.
    """
    Context = jclass("android.content.Context")
    Caps = jclass("android.net.NetworkCapabilities")
    PFD = jclass("android.os.ParcelFileDescriptor")
    cm = activity.getSystemService(Context.CONNECTIVITY_SERVICE)

    def bind(sock):
        """Returns a status line for the app's Log panel."""
        for net in cm.getAllNetworks():
            caps = cm.getNetworkCapabilities(net)
            if caps is not None and caps.hasTransport(Caps.TRANSPORT_WIFI):
                pfd = PFD.fromFd(sock.fileno())  # dup of our socket's fd
                try:
                    net.bindSocket(pfd.getFileDescriptor())
                finally:
                    pfd.close()
                return "camera traffic pinned to WiFi"
        return "no WiFi network found - is the phone connected to HNDEC-xxxx?"
    return bind


def make_gallery_saver(activity):
    """Save captures into Pictures/EarViolator4000 and Movies/EarViolator4000 via MediaStore.

    MediaStore needs no storage permission on Android 10+.
    """
    ContentValues = jclass("android.content.ContentValues")
    Images = jclass("android.provider.MediaStore$Images$Media")
    Video = jclass("android.provider.MediaStore$Video$Media")
    resolver = activity.getContentResolver()

    def save(name, mime, data):
        if mime.startswith("image/"):
            coll, folder = Images.EXTERNAL_CONTENT_URI, "Pictures/EarViolator4000"
        else:
            coll, folder = Video.EXTERNAL_CONTENT_URI, "Movies/EarViolator4000"
        values = ContentValues()
        values.put("_display_name", name)
        values.put("mime_type", mime)
        values.put("relative_path", folder)
        uri = resolver.insert(coll, values)
        if uri is None:
            raise OSError("could not create gallery entry")
        out = resolver.openOutputStream(uri)
        try:
            out.write(data)
        finally:
            out.close()
        return folder
    return save


def desktop_saver(name, mime, data):
    """Fallback when run on a computer with `briefcase dev`."""
    folder = os.path.join(os.path.expanduser("~"), "Pictures", "EarViolator4000")
    os.makedirs(folder, exist_ok=True)
    with open(os.path.join(folder, name), "wb") as f:
        f.write(data)
    return folder


def make_immersive(activity):
    """Return fn(on) that hides/shows the status and navigation bars.

    Called from the web server thread, so the work is posted to the UI thread.
    Every step is wrapped: a failure only means fullscreen keeps the bars.
    """
    from java import dynamic_proxy
    Runnable = jclass("java.lang.Runnable")

    def apply(on):
        win = activity.getWindow()
        try:  # modern API (androidx.core, bundled with Material Components)
            WindowCompat = jclass("androidx.core.view.WindowCompat")
            Ctl = jclass("androidx.core.view.WindowInsetsControllerCompat")
            Insets = jclass("androidx.core.view.WindowInsetsCompat$Type")
            ctl = WindowCompat.getInsetsController(win, win.getDecorView())
            if on:
                ctl.setSystemBarsBehavior(Ctl.BEHAVIOR_SHOW_TRANSIENT_BARS_BY_SWIPE)
                ctl.hide(Insets.systemBars())
            else:
                ctl.show(Insets.systemBars())
        except Exception:
            View = jclass("android.view.View")   # older fallback
            flags = (View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY | View.SYSTEM_UI_FLAG_FULLSCREEN
                     | View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_LAYOUT_STABLE
                     | View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN
                     | View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION) if on else 0
            win.getDecorView().setSystemUiVisibility(flags)

    class Task(dynamic_proxy(Runnable)):
        def __init__(self, on):
            super().__init__()
            self.on = on

        def run(self):
            try:
                apply(self.on)
            except Exception as e:  # never let an exception reach Java
                ne3web.log(f"[app] fullscreen failed: {e}")

    return lambda on: activity.runOnUiThread(Task(on))


def hide_title_bar(activity):
    """The logo in the page replaces the app's title bar."""
    bar = activity.getSupportActionBar()
    if bar is not None:
        bar.hide()


def keep_screen_on(activity):
    WM = jclass("android.view.WindowManager$LayoutParams")
    activity.getWindow().addFlags(WM.FLAG_KEEP_SCREEN_ON)


# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------
class EarScope(toga.App):
    def startup(self):
        hook, saver, immersive = None, desktop_saver, None
        if ANDROID:
            activity = self._impl.native
            for setup in (keep_screen_on,):
                try:
                    setup(activity)
                except Exception as e:
                    ne3web.log(f"[app] {setup.__name__} failed: {e}")
            try:
                hook = make_wifi_binder(activity)
            except Exception as e:
                ne3web.log(f"[app] WiFi binding unavailable: {e}")
            try:
                saver = make_gallery_saver(activity)
            except Exception as e:
                ne3web.log(f"[app] gallery saving unavailable: {e}")
            try:
                immersive = make_immersive(activity)
            except Exception as e:
                ne3web.log(f"[app] fullscreen unavailable: {e}")

        self.cam = ne3web.Camera(None, 8800, 36000, socket_hook=hook)  # auto-detect NE3 or NE7
        self.cam.start()

        # Port 0 = let the OS pick a free local port; only reachable on-device.
        server = ne3web.make_server(self.cam, "127.0.0.1", 0, saver=saver, app_mode=True,
                                    immersive=immersive)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        port = server.server_address[1]

        self.main_window = toga.MainWindow(title=self.formal_name)
        self.main_window.content = toga.WebView(
            url=f"http://127.0.0.1:{port}/", style=Pack(flex=1)
        )
        self.main_window.show()
        if ANDROID:
            try:
                hide_title_bar(self._impl.native)
            except Exception as e:
                ne3web.log(f"[app] couldn't hide title bar: {e}")


def main():
    return EarScope()
