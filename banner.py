from rich.console import Console
from rich.text import Text


def show_logo() -> None:
    console = Console()

    logo = [
        r" ____    ___    __   ",
        r"|  _ \  / _ \  / /_  ",
        r"| | | || | | || '_ \ ",
        r"| |_| || |_| || (_) |",
        r"|____/  \___/  \___/ ",
    ]

    width = max(len(line) for line in logo)

    console.print()
    for line in logo:
        console.print(Text(line.center(width), style="bold red"))

    console.print(Text("D06 IDS".center(width), style="bold cyan"))
    console.print(Text("Domoa Alfatlawi".center(width), style="white"))
    console.print(Text("System Active".center(width), style="green"))
    console.print()


if __name__ == "__main__":
    show_logo()
