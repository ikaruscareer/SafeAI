import os


def process_data(data):
    """Process data and write to file."""
    result = data.upper()
    path = os.path.join("/tmp", "output.txt")
    with open(path, "w") as f:
        f.write(result)
    return path
