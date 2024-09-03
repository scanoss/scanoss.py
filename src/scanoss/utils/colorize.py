from enum import Enum


class Color(Enum):
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"


def colorize(text: str, color: str) -> str:
    if color not in Color.__members__:
        raise KeyError(
            f"Invalid color '{color}'. Valid colors are: {', '.join(Color._member_names_)}"
        )
    return f"{Color[color].value}{text}{Color.RESET.value}"
