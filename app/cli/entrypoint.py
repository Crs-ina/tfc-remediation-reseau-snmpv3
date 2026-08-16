import sys

from app import create_app
from app.cli.okapi import okapi_cli


def main() -> None:
    app = create_app()

    with app.app_context():
        okapi_cli.main(
            args=sys.argv[1:],
            prog_name="okapi",
            standalone_mode=True,
        )


if __name__ == "__main__":
    main()
