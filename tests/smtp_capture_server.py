import json
import re
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


captured_otps: dict[str, str] = {}
capture_lock = threading.Lock()


class SmtpHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        recipient = ""
        message_lines: list[str] = []
        receiving_data = False
        self.wfile.write(b"220 localhost test SMTP\r\n")

        while line_bytes := self.rfile.readline():
            line = line_bytes.decode("utf-8", errors="replace").rstrip("\r\n")

            if receiving_data:
                if line == ".":
                    message = "\n".join(message_lines)
                    match = re.search(
                        r"(?:verification|password recovery) code is (\d{6})",
                        message,
                        re.IGNORECASE
                    )

                    if recipient and match:
                        with capture_lock:
                            captured_otps[recipient.lower()] = match.group(1)

                    receiving_data = False
                    message_lines.clear()
                    self.wfile.write(b"250 Message accepted\r\n")
                else:
                    message_lines.append(line)

                continue

            command = line.upper()

            if command.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250 localhost\r\n")
            elif command.startswith("MAIL FROM:"):
                self.wfile.write(b"250 OK\r\n")
            elif command.startswith("RCPT TO:"):
                recipient = line.split(":", 1)[1].strip().strip("<>")
                self.wfile.write(b"250 OK\r\n")
            elif command == "DATA":
                receiving_data = True
                self.wfile.write(b"354 End data with <CR><LF>.<CR><LF>\r\n")
            elif command == "QUIT":
                self.wfile.write(b"221 Bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")


class OtpHttpHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)

        if parsed_url.path != "/otp":
            self.send_error(404)
            return

        email = parse_qs(parsed_url.query).get("email", [""])[0].lower()

        with capture_lock:
            otp = captured_otps.pop(email, None)

        if otp is None:
            self.send_error(404)
            return

        body = json.dumps({"otp": otp}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


def main() -> None:
    smtp_server = socketserver.ThreadingTCPServer(
        ("127.0.0.1", 8025),
        SmtpHandler
    )
    smtp_server.daemon_threads = True
    smtp_thread = threading.Thread(
        target=smtp_server.serve_forever,
        daemon=True
    )
    smtp_thread.start()

    try:
        ThreadingHTTPServer(
            ("127.0.0.1", 8026),
            OtpHttpHandler
        ).serve_forever()
    finally:
        smtp_server.shutdown()
        smtp_server.server_close()


if __name__ == "__main__":
    main()
