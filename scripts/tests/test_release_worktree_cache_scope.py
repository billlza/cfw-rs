from __future__ import annotations

import unittest
from dataclasses import replace

from scripts.release_secret_material_blocker import (
    ReleaseWorktreeCacheRecoveryReceipt,
    ReleaseWorktreeCacheScopeError,
    ReleaseWorktreeCacheScopeReceipt,
    StablePathIdentity,
    canonical_scope_receipt_bytes,
    canonical_scope_recovery_bytes,
    parse_scope_receipt,
    parse_scope_recovery,
)


def _receipt() -> ReleaseWorktreeCacheScopeReceipt:
    return ReleaseWorktreeCacheScopeReceipt(
        build="40028",
        worktree_path="/release/target/release-worktrees/40028",
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
            b'{"adminIdentity":', b'{"build":"40028","adminIdentity":', 1
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


class ReleaseWorktreeCacheRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original = _receipt()
        self.recovered = replace(
            self.original,
            **{
                field: replace(getattr(self.original, field), device=7)
                for field in ("admin", "worktree", "marker", "target")
            },
        )

    def test_device_only_recovery_round_trips_and_retains_original(self) -> None:
        recovery = ReleaseWorktreeCacheRecoveryReceipt(self.original, self.recovered)
        data = canonical_scope_recovery_bytes(recovery)
        self.assertEqual(parse_scope_recovery(data), recovery)
        self.assertEqual(recovery.original, _receipt())

    def test_each_inode_is_immutable(self) -> None:
        for field in ("admin", "worktree", "marker", "target"):
            with self.subTest(field=field):
                changed = replace(
                    self.recovered,
                    **{field: replace(getattr(self.recovered, field), inode=900)},
                )
                with self.assertRaisesRegex(
                    ReleaseWorktreeCacheScopeError, "cannot change an inode"
                ):
                    ReleaseWorktreeCacheRecoveryReceipt(self.original, changed)

    def test_build_path_and_head_are_immutable(self) -> None:
        for field, value in (
            ("build", "40029"),
            ("worktree_path", "/another/40028"),
            ("head", "0" * 40),
        ):
            with self.subTest(field=field), self.assertRaisesRegex(
                ReleaseWorktreeCacheScopeError, "cannot change build, path or HEAD"
            ):
                ReleaseWorktreeCacheRecoveryReceipt(
                    self.original, replace(self.recovered, **{field: value})
                )

    def test_filesystem_split_and_merge_are_rejected(self) -> None:
        split = replace(self.recovered, target=replace(self.recovered.target, device=8))
        merge_origin = replace(
            self.original, target=replace(self.original.target, device=2)
        )
        for original, recovered in (
            (self.original, split),
            (merge_origin, self.recovered),
        ):
            with self.subTest(original=original), self.assertRaisesRegex(
                ReleaseWorktreeCacheScopeError, "mapping is not one-to-one"
            ):
                ReleaseWorktreeCacheRecoveryReceipt(original, recovered)

    def test_multiple_filesystems_can_be_reassigned_without_merging(self) -> None:
        original = replace(self.original, target=replace(self.original.target, device=2))
        recovered = replace(self.recovered, target=replace(self.recovered.target, device=8))
        receipt = ReleaseWorktreeCacheRecoveryReceipt(original, recovered)
        self.assertEqual(parse_scope_recovery(canonical_scope_recovery_bytes(receipt)), receipt)

    def test_unchanged_identity_does_not_create_a_recovery(self) -> None:
        with self.assertRaisesRegex(
            ReleaseWorktreeCacheScopeError, "requires a device reassignment"
        ):
            ReleaseWorktreeCacheRecoveryReceipt(self.original, self.original)

    def test_recovery_rejects_duplicate_noncanonical_and_unknown_fields(self) -> None:
        data = canonical_scope_recovery_bytes(
            ReleaseWorktreeCacheRecoveryReceipt(self.original, self.recovered)
        )
        for malformed in (
            b" " + data,
            data.replace(b'{"original":', b'{"extra":0,"original":', 1),
            data.replace(b'{"original":', b'{"original":null,"original":', 1),
            data.replace(b'"device":7', b'"device":true', 1),
            data.replace(b'cache-recovery-v1', b'cache-recovery-v2'),
            b"[" * 1_000 + b"0" + b"]" * 1_000,
        ):
            with self.subTest(data=malformed[:80]), self.assertRaises(
                ReleaseWorktreeCacheScopeError
            ):
                parse_scope_recovery(malformed)


if __name__ == "__main__":
    unittest.main()
