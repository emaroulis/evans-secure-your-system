"""Entry point: opens the window by default, or runs in the terminal with --cli."""
import sys

from .cli import build_parser, main as cli_main


def main():
    args = build_parser().parse_args()
    if args.cli:
        sys.exit(cli_main(args))
    try:
        from .gui import launch
    except ImportError as e:  # tkinter missing (some Linux installs)
        print(f"The graphical window could not start ({e}).\n"
              "Install tkinter (e.g. 'sudo apt install python3-tk') or run with --cli.\n")
        sys.exit(cli_main(args))
    launch(args)


if __name__ == "__main__":
    main()
