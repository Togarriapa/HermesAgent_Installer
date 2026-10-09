"""Pinned dependency-light Xpra client asset manifest."""
from urllib.parse import unquote

CLIENT_ASSETS = frozenset({
    "/client/index.html", "/client/bootstrap.html", "/client/favicon.png", "/client/favicon.ico",
    "/client/css/client.css", "/client/css/connect.css", "/client/css/icon.css",
    "/client/css/menu-skin.css", "/client/css/menu.css", "/client/css/simple-keyboard.css",
    "/client/css/slick.css", "/client/css/spinner.css",
    "/client/icons/authentication.png", "/client/icons/close.png", "/client/icons/default_cursor.png",
    "/client/icons/empty.png", "/client/icons/eye-slash.png", "/client/icons/eye.png",
    "/client/icons/fullscreen.png", "/client/icons/maximize.png", "/client/icons/minimize.png",
    "/client/icons/noicon.png", "/client/icons/unfullscreen.png", "/client/icons/xpra-logo.png",
    "/client/icons/materialicons-regular.ttf", "/client/icons/materialicons-regular.woff",
    "/client/icons/materialicons-regular.woff2",
    *{"/client/js/" + name for name in (
        "Client.js", "Constants.js", "DecodeWorker.js", "ImageDecoder.js", "Keycodes.js",
        "MediaSourceUtil.js", "Menu.js", "MenuCustom.js", "Notifications.js",
        "OffscreenDecodeWorker.js", "OffscreenDecodeWorkerHelper.js", "Protocol.js",
        "RgbHelpers.js", "Utilities.js", "VideoDecoder.js", "WebTransport.js", "Window.js",
        "lib/FileSaver.js", "lib/StreamSaver.js", "lib/aurora/aac.js", "lib/aurora/aurora-xpra.js",
        "lib/aurora/aurora.js", "lib/aurora/flac.js", "lib/aurora/mp3.js",
        "lib/brotli_decode.js", "lib/detect-zoom.js", "lib/hmac.js",
        "lib/jquery-transform-draggable.js", "lib/jquery-ui.js", "lib/jquery.ba-throttle-debounce.js",
        "lib/jquery.js", "lib/lz4.js", "lib/rencode.js", "lib/simple-keyboard.js", "lib/slick.js",
        "lib/web-streams-ponyfill.es6.js",
    )}
})


def canonical_asset(raw: str) -> str:
    path = raw.split("?", 1)[0]
    if (not path.startswith("/") or "\\" in path or unquote(path) != path
            or unquote(unquote(path)) != path
            or any(segment in {".", ".."} for segment in path.split("/"))):
        raise ValueError("non-canonical asset path")
    if path not in CLIENT_ASSETS:
        raise ValueError("asset is outside the pinned Xpra client manifest")
    return path
