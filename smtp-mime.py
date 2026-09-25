import argparse
import os
import sys
import smtplib
import getpass
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from email.utils import formatdate
from pathlib import Path

class _Verbose:
    def _init_verbose(self, verbose):
        self.verbose = verbose
        self._in_data = False

    def putcmd(self, cmd, args=""):
        if self.verbose and not self._in_data:
            cmd_s = cmd.decode('ascii', 'replace') if isinstance(cmd, (bytes, bytearray)) else str(cmd)
            args_s = args.decode('ascii', 'replace') if isinstance(args, (bytes, bytearray)) else str(args)
            line = f"{cmd_s} {args_s}".strip()
            if cmd_s.upper() == "AUTH" and args_s:
                line = f"AUTH {args_s.split()[0]} ****"
            print(f">>> {line}")
        super().putcmd(cmd, args)

    def getreply(self):
        code, msg = super().getreply()
        if self.verbose:
            msg_display = (msg.decode('utf-8', 'replace')
                           if isinstance(msg, (bytes, bytearray))
                           else str(msg))
            for line in msg_display.splitlines():
                print(f"<<< {line}")
        if code == 354:
            self._in_data = True
        elif self._in_data and code == 250:
            self._in_data = False
        return code, msg


class VerboseSMTP(_Verbose, smtplib.SMTP):
    def __init__(self, *args, verbose=False, **kwargs):
        self._init_verbose(verbose)
        super().__init__(*args, **kwargs)


class VerboseSMTP_SSL(_Verbose, smtplib.SMTP_SSL):
    def __init__(self, *args, verbose=False, **kwargs):
        self._init_verbose(verbose)
        super().__init__(*args, **kwargs)

class SMTPClient:
    def __init__(self, server, port, allow_ssl=False, use_auth=False, verbose=False):
        self.server = server
        self.port = port
        self.allow_ssl = allow_ssl
        self.use_auth = use_auth
        self.verbose = verbose
        self.smtp = None
        self.size_limit = None

    def log(self, message):
        if self.verbose:
            print(message)

    def _check(self, code, expected, stage):
        if code != expected:
            raise smtplib.SMTPException(f"{stage} failed: code={code}")

    def connect(self):
        try:
            if self.allow_ssl and self.port == 465:
                context = ssl.create_default_context()
                if self.verbose:
                    self.smtp = VerboseSMTP_SSL(self.server, self.port,
                                                context=context, verbose=True)
                else:
                    self.smtp = smtplib.SMTP_SSL(self.server, self.port,
                                                 context=context)
                self.log(f"Connected via implicit SSL to {self.server}:{self.port}")
            else:
                if self.verbose:
                    self.smtp = VerboseSMTP(self.server, self.port, verbose=True)
                else:
                    self.smtp = smtplib.SMTP(self.server, self.port)
                self.log(f"Connected to {self.server}:{self.port}")

            code, msg = self.smtp.ehlo()
            self._check(code, 250, "EHLO")

            if (not isinstance(self.smtp, smtplib.SMTP_SSL)
                    and self.smtp.has_extn('starttls')):
                if self.allow_ssl:
                    self.log("STARTTLS supported, upgrading...")
                    context = ssl.create_default_context()
                    code, msg = self.smtp.starttls(context=context)
                    self._check(code, 220, "STARTTLS")
                    code, msg = self.smtp.ehlo()
                    self._check(code, 250, "EHLO after STARTTLS")
                else:
                    self.log("STARTTLS available but not requested (use --ssl)")

            exts = self.smtp.esmtp_features
            if self.smtp.has_extn('pipelining'):
                self.log("ESMTP: PIPELINING supported")
            if self.smtp.has_extn('size'):
                limit = exts.get('size', '?')
                self.log(f"ESMTP: SIZE limit = {limit}")
                self.size_limit = int(limit) if str(limit).isdigit() else None
            else:
                self.size_limit = None

            if self.use_auth:
                if not self.smtp.has_extn('auth'):
                    self.log("Server does not advertise AUTH")
                if not isinstance(self.smtp, smtplib.SMTP_SSL) and not self.smtp.sock_is_encrypted():
                    print("Refusing to authenticate over an unencrypted "
                          "connection. Use --ssl or configure STARTTLS.",
                          file=sys.stderr)
                    return False
                user = input("Username: ")
                pwd = getpass.getpass("Password: ")
                self.smtp.login(user, pwd)
                self.log("Authentication successful")

            return True

        except smtplib.SMTPAuthenticationError as e:
            print(f"Auth error: {e}", file=sys.stderr)
            return False
        except Exception as e:
            print(f"Connection error: {e}", file=sys.stderr)
            return False

    def send_message(self, from_addr, to_addr, message):
        try:
            raw = message.as_string()

            if self.size_limit:
                size = len(raw.encode('utf-8'))
                if size > self.size_limit:
                    print(f"Message too large ({size} > {self.size_limit})",
                          file=sys.stderr)
                    return False

            mail_options = []
            if self.smtp.has_extn('pipelining'):
                mail_options.append('PIPELINING')

            refused = self.smtp.sendmail(from_addr, [to_addr], raw,
                                         mail_options=mail_options)
            if refused:
                self.log(f"Refused recipients: {refused}")
                return False
            self.log("Message sent successfully")
            return True

        except Exception as e:
            print(f"Send error: {e}", file=sys.stderr)
            return False

    def disconnect(self):
        if self.smtp:
            try:
                self.smtp.quit()
            except Exception:
                pass

def _sock_is_encrypted(self):
    return isinstance(self.sock, ssl.SSLSocket)

smtplib.SMTP.sock_is_encrypted = _sock_is_encrypted

def create_message(from_addr, to_addr, subject, images):
    msg = MIMEMultipart()
    msg['From'] = from_addr
    msg['To'] = to_addr
    msg['Subject'] = subject
    msg['Date'] = formatdate(localtime=True)

    text = f"Hello!\n\n{len(images)} image(s) attached.\n\nEnjoy!"
    msg.attach(MIMEText(text, 'plain', 'utf-8'))

    mime_map = {
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
        '.png': 'image/png', '.gif': 'image/gif',
        '.bmp': 'image/bmp', '.tiff': 'image/tiff',
        '.tif': 'image/tiff', '.webp': 'image/webp',
    }

    for image_path in images:
        try:
            data = Path(image_path).read_bytes()
            ext = Path(image_path).suffix.lower()
            mime_type = mime_map.get(ext, 'application/octet-stream')

            main, sub = mime_type.split('/', 1)
            part = MIMEBase(main, sub)
            part.set_payload(data)
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                'attachment',
                filename=os.path.basename(image_path)
            )
            msg.attach(part)
            print(f"Attached: {os.path.basename(image_path)}")
        except Exception as e:
            print(f"Error attaching {image_path}: {e}", file=sys.stderr)

    return msg


def find_images(directory):
    exts = {'.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.tif', '.webp'}
    out = []
    try:
        for name in os.listdir(directory):
            p = os.path.join(directory, name)
            if os.path.isfile(p) and Path(p).suffix.lower() in exts:
                out.append(p)
    except OSError as e:
        print(f"Error reading directory: {e}", file=sys.stderr)
    return out


def parse_server(s):
    if ':' in s:
        host, port = s.rsplit(':', 1)
        return host, int(port)
    return s, 25


def main():
    p = argparse.ArgumentParser(
        description='Send all images from a directory as email attachments',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''Examples:
  %(prog)s -s smtp.example.com -t user@example.com -f me@example.com
  %(prog)s -s smtp.example.com:587 -t user@example.com --ssl --auth -d pictures
'''
    )
    p.add_argument('--ssl', action='store_true',
                   help='Allow SSL/TLS (STARTTLS) if supported by server (default: off)')
    p.add_argument('-s', '--server', required=True,
                   help='SMTP server as address[:port] (default port: 25)')
    p.add_argument('-t', '--to', required=True, help='Recipient address')
    p.add_argument('-f', '--from', dest='from_addr', default='<>',
                   help='Sender address (default: <>)')
    p.add_argument('--subject', default='Happy Pictures',
                   help='Email subject (default: "Happy Pictures")')
    p.add_argument('--auth', action='store_true',
                   help='Prompt for authentication (default: off)')
    p.add_argument('-v', '--verbose', action='store_true',
                   help='Show SMTP protocol (commands and replies; body hidden)')
    p.add_argument('-d', '--directory', default=os.getcwd(),
                   help='Directory with images (default: current)')
    args = p.parse_args()

    if not os.path.isdir(args.directory):
        print(f"Error: directory '{args.directory}' does not exist", file=sys.stderr)
        sys.exit(1)

    images = find_images(args.directory)
    if not images:
        print(f"No images in '{args.directory}'", file=sys.stderr)
        sys.exit(1)
    print(f"Found {len(images)} image(s) in '{args.directory}'")

    host, port = parse_server(args.server)

    print("Creating message...")
    msg = create_message(args.from_addr, args.to, args.subject, images)

    print(f"Connecting to {host}:{port}...")
    client = SMTPClient(host, port, allow_ssl=args.ssl,
                        use_auth=args.auth, verbose=args.verbose)
    if not client.connect():
        sys.exit(1)

    try:
        print("Sending message...")
        if client.send_message(args.from_addr, args.to, msg):
            print(f"Email sent successfully to {args.to}")
        else:
            print("Failed to send email", file=sys.stderr)
            sys.exit(1)
    finally:
        client.disconnect()


if __name__ == '__main__':
    main()