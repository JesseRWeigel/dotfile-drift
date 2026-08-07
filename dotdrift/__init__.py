"""dotdrift: a three-way dotfile drift detector that does not quote your secrets.

The package is stdlib only. Every module here is importable without side effects.
"""

__version__ = "0.1.0"

# Exit codes used by the CLI. `check` returns DRIFT when it found something the
# user should look at, which is what makes it usable from a weekly cron hook.
EXIT_OK = 0
EXIT_DRIFT = 1
EXIT_ERROR = 2
