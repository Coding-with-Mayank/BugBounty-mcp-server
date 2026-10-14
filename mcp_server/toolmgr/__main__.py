import sys

from ..cliutil import run_cli
from .cli import main

# run_cli (not a bare sys.exit(main())) so `... | head` ends quietly — see cliutil.
sys.exit(run_cli(main))
