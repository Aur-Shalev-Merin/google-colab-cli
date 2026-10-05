# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import codecs
import json
import logging
import os
import signal
import sys
import threading
import time
from urllib.parse import urlparse

if sys.platform == "win32":
    import ctypes
    import msvcrt

    termios = tty = None
else:
    import termios
    import tty

import websocket

from colab_cli.state import SessionState

logger = logging.getLogger(__name__)

# Global flag to stop the read thread when the websocket closes
_is_running = False
_last_error = None

# When stdin is piped and reaches EOF, we send "exit\n" to the remote shell and
# then wait this many seconds for any remaining output (the shell's goodbye,
# tmux teardown messages, etc.) to flush before closing the websocket from the
# client side. Empirically 0.5s is enough for the typical /colab/tty backend
# wrapped in tmux + bash; bumping it just delays exit, lowering it risks
# truncating tail output.
PIPED_EOF_GRACE_SECONDS = 0.5


def on_message(ws, message):
    """Callback for when a message is received from the server."""
    try:
        data = json.loads(message)
        if "data" in data:
            # The backend sends raw ANSI escape sequences and string content.
            # We write it directly to stdout buffer to avoid python print() formatting.
            sys.stdout.buffer.write(data["data"].encode("utf-8"))
            sys.stdout.buffer.flush()
    except Exception as e:
        logger.debug(f"Error parsing message: {e}")


def on_error(ws, error):
    """Callback for when a websocket error occurs."""
    global _last_error
    _last_error = error
    logger.error(f"WebSocket Error: {error}")


def on_close(ws, close_status_code, close_msg):
    """Callback for when the websocket is closed."""
    global _is_running
    _is_running = False


def send_terminal_size(ws):
    """Sends the current terminal size to the remote backend."""
    try:
        size = os.get_terminal_size()
        payload = json.dumps({"cols": size.columns, "rows": size.lines})
        ws.send(payload)
    except Exception as e:
        logger.debug(f"Failed to send terminal size: {e}")


def _raw_console_reader():
    """Returns a callable reading keystrokes from an interactive stdin.

    On Windows, text-mode ``sys.stdin`` translates newlines and holds back a
    lone ``\\r`` (Enter) until the next key arrives to see whether ``\\n``
    follows, so Enter would reach the remote shell one keystroke late. There we
    read the console's raw bytes and decode them ourselves; elsewhere stdin
    does no translation and ``read(1)`` is fine.
    """
    if sys.platform != "win32":
        return lambda: sys.stdin.read(1)

    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

    def read():
        while True:
            data = sys.stdin.buffer.read1(1024)
            if not data:
                return ""
            text = decoder.decode(data)
            if text:  # empty while a multi-byte character is incomplete
                return text

    return read


def on_open(ws):
    """Callback for when the websocket connection is opened."""
    global _is_running
    _is_running = True

    # Send initial terminal size
    send_terminal_size(ws)

    # Setup the background thread to read from stdin
    def read_stdin():
        is_tty = sys.stdin.isatty()
        read_char = _raw_console_reader() if is_tty else lambda: sys.stdin.read(1)
        while _is_running:
            try:
                # Read a single character (or escape sequence byte)
                char = read_char()
                if not char:
                    if not is_tty:
                        # Piped input has reached EOF. The remote /colab/tty
                        # endpoint wraps bash in tmux which intercepts \x04
                        # (Ctrl-D) as a literal character, so it never exits.
                        # Instead send "exit\n" so bash voluntarily terminates,
                        # wait a short grace period for the shell's goodbye
                        # output to drain back to us, then close the websocket
                        # ourselves to guarantee the client unblocks.
                        try:
                            ws.send(json.dumps({"data": "exit\n"}))
                        except Exception:
                            pass
                        time.sleep(PIPED_EOF_GRACE_SECONDS)
                        try:
                            ws.close()
                        except Exception:
                            pass
                    break
                ws.send(json.dumps({"data": char}))
            except Exception:
                break

    thread = threading.Thread(target=read_stdin, daemon=True)
    thread.start()


# Windows console mode flags (see SetConsoleMode docs).
_ENABLE_PROCESSED_INPUT = 0x0001
_ENABLE_LINE_INPUT = 0x0002
_ENABLE_ECHO_INPUT = 0x0004
_ENABLE_VIRTUAL_TERMINAL_INPUT = 0x0200
_ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004


def _enter_raw_mode_windows(fd):
    """Puts the Windows console into a raw, VT-sequence mode.

    Disables line buffering, echo and Ctrl-C processing on stdin (so keys,
    including Ctrl-C, are forwarded to the remote shell) and enables VT input
    so arrow keys arrive as ANSI escape sequences, matching what a POSIX raw
    tty would deliver. Enables VT processing on stdout so the remote shell's
    ANSI output renders. Returns a callable that restores the original modes.
    """
    kernel32 = ctypes.windll.kernel32
    in_handle = msvcrt.get_osfhandle(fd)
    out_handle = msvcrt.get_osfhandle(sys.stdout.fileno())

    old_in, old_out = ctypes.c_uint32(), ctypes.c_uint32()
    kernel32.GetConsoleMode(in_handle, ctypes.byref(old_in))
    has_out = kernel32.GetConsoleMode(out_handle, ctypes.byref(old_out))

    raw_in = old_in.value & ~(
        _ENABLE_PROCESSED_INPUT | _ENABLE_LINE_INPUT | _ENABLE_ECHO_INPUT
    )
    kernel32.SetConsoleMode(in_handle, raw_in | _ENABLE_VIRTUAL_TERMINAL_INPUT)
    if has_out:
        kernel32.SetConsoleMode(
            out_handle, old_out.value | _ENABLE_VIRTUAL_TERMINAL_PROCESSING
        )

    def restore():
        kernel32.SetConsoleMode(in_handle, old_in.value)
        if has_out:
            kernel32.SetConsoleMode(out_handle, old_out.value)

    return restore


def _enter_raw_mode(fd, on_resize):
    """Switches the local terminal to raw mode; returns a restore callable."""
    if sys.platform == "win32":
        # Windows has no SIGWINCH; the initial size sent on open is used.
        return _enter_raw_mode_windows(fd)

    old_settings = termios.tcgetattr(fd)
    tty.setraw(fd, termios.TCSANOW)
    signal.signal(signal.SIGWINCH, on_resize)

    def restore():
        termios.tcsetattr(fd, termios.TCSANOW, old_settings)
        signal.signal(signal.SIGWINCH, signal.SIG_DFL)

    return restore


def connect_console(session: SessionState):
    """
    Connects to the Colab TTY endpoint and sets up a raw terminal session.
    """
    global _is_running, _last_error
    _last_error = None

    # Construct the WebSocket URL from the base URL
    parsed = urlparse(session.url)
    ws_scheme = "wss" if parsed.scheme == "https" else "ws"
    ws_url = f"{ws_scheme}://{parsed.netloc}/colab/tty?colab-runtime-proxy-token={session.token}"

    is_tty = sys.stdin.isatty()
    fd = sys.stdin.fileno() if is_tty else None
    restore_terminal = None

    ws = websocket.WebSocketApp(
        url=ws_url,
        on_open=on_open,
        on_message=on_message,
        on_error=on_error,
        on_close=on_close,
    )

    def handle_sigwinch(signum, frame):
        """Handle window resize events."""
        if _is_running:
            send_terminal_size(ws)

    try:
        if is_tty:
            restore_terminal = _enter_raw_mode(fd, handle_sigwinch)

        # This is a blocking call until the connection is closed
        ws.run_forever()

        if _last_error:
            # Re-raise or wrap terminal errors
            err_msg = str(_last_error)
            if "404" in err_msg or "401" in err_msg:
                # We raise a standard exception that the caller can recognize
                raise RuntimeError(f"Connection failed: {err_msg}")
    finally:
        if restore_terminal:
            # Always ensure the terminal is restored to its original state
            restore_terminal()
        print("\r\nConnection closed.")
