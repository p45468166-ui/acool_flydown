import argparse
import json
import sys

from hongguo_frida import HongguoFridaRunner


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--package", default="com.phoenix.read")
    parser.add_argument("--device", default=None, help="usb 或 remote:host:port")
    parser.add_argument("--spawn", action="store_true")
    args = parser.parse_args()

    def on_url(payload):
        sys.stdout.write(json.dumps(payload, ensure_ascii=False) + "\n")
        sys.stdout.flush()

    runner = HongguoFridaRunner(
        on_url=on_url,
        package_name=args.package,
        device_hint=args.device,
        spawn=args.spawn,
    )

    try:
        runner.start()
    except KeyboardInterrupt:
        pass
    finally:
        runner.stop()


if __name__ == "__main__":
    main()

