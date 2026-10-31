"""`origin.services.shamir` re-exports `prism.trust.shamir`: one Shamir k-of-n implementation.

The key oracle (`services.key_oracle`) splits and combines with it, and so does Mantle's threshold
master-key store, so the arithmetic lives once, in prism's trust floor. The `sys.modules` entry is
rebound rather than star-imported, as `origin.key_manager` explains: the two names are then one
module object, and `split`, `combine` and `Share` resolve through either.
"""
import sys

from prism.trust import shamir as _real

sys.modules[__name__] = _real
