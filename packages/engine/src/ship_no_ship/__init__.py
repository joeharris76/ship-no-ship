from importlib.metadata import PackageNotFoundError, version

DISTRIBUTION = "ship-no-ship"

try:
    __version__ = version(DISTRIBUTION)
except PackageNotFoundError:
    __version__ = "0+unknown"
