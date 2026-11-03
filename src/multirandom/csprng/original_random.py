"""
Project: https://pypi.org/project/multirandom/
Repo: https://github.com/BlackCatOfficialytb/multirandom
License: Apache 2.0
Module: multirandom.csprng.original_random
Description:
Passthrough for Python's built-in random module (`from random import *`), kept
so the csprng package can be imported wholesale when bundling "everything
random". The Mersenne Twister behind it is NOT cryptographically secure.
"""
from random import *
