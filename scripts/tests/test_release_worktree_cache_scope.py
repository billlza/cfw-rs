from __future__ import annotations

import unittest

from scripts.release_secret_material_blocker import (
    ReleaseWorktreeCacheScopeError,
    ReleaseWorktreeCacheScopeReceipt,
    StablePathIdentity,
    canonical_scope_receipt_bytes,
    parse_scope_receipt,
)


def _receipt() -> ReleaseWorktreeCacheScopeReceipt:
    return ReleaseWorktreeCacheScopeReceipt(
        build="40026",
        worktree_path="/release/target/release-worktrees/40026",
        head="8de7baa6757136510c7f749e15b3869c792fb722",
        admin=StablePathIdentity(device=1, inode=2),
        worktree=StablePathIdentity(device=1, inode=3),
        marker=StablePathIdentity(device=1, inode=4),
        target=StablePathIdentity(device=1, inode=5),
    )


class ReleaseWorktreeCacheScopeTests(unittest.TestCase):
    def test_canonical_receipt_round_trips(self) -> None:
        receipt = _receipt()
        data = canonical_scope_receipt_bytes(receipt)
        self.assertEqual(parse_scope_receipt(data), receipt)
        self.assertTrue(data.endswith(b"\n"))

    def test_noncanonical_or_duplicate_json_is_rejected(self) -> None:
        canonical = canonical_scope_receipt_bytes(_receipt())
        with self.assertRaisesRegex(
            ReleaseWorktreeCacheScopeError, "not in canonical form"
        ):
            parse_scope_receipt(b" " + canonical)
        duplicate = canonical.replace(
            b'{"adminIdentity":', b'{"build":"40026","adminIdentity":', 1
        )
        with self.assertRaisesRegex(
            ReleaseWorktreeCacheScopeError, "duplicate key"
        ):
            parse_scope_receipt(duplicate)

    def test_boolean_or_nonpositive_identity_is_rejected(self) -> None:
        with self.assertRaisesRegex(
            ReleaseWorktreeCacheScopeError, "path identity is invalid"
        ):
            StablePathIdentity(device=True, inode=2)
        with self.assertRaisesRegex(
            ReleaseWorktreeCacheScopeError, "path identity is invalid"
        ):
            StablePathIdentity(device=1, inode=0)

    def test_excessively_nested_json_is_a_typed_error(self) -> None:
        nested = (b"[" * 1_000) + b"0" + (b"]" * 1_000)
        with self.assertRaises(ReleaseWorktreeCacheScopeError):
            parse_scope_receipt(nested)


if __name__ == "__main__":
    unittest.main()
