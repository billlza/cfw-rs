# Build 40072 retirement

Build 40072 was frozen, signed, notarized, stapled and installed. Its source is
`97efe9a9bf3d29bbe6cdddd77df64cba18b8f3f7` and its installed signed application
tree is `5951216697f671fc241605cb97b895e5ad8a668ca6601c92ab2efdaa5173beb1`.
That exact installed identity was independently rehashed before preparation.

The requested internationalization adds Simplified Chinese, Traditional Chinese,
English and Japanese UI/native menu resources and persisted language selection.
These product changes require successor 40073. This is not an evidence retry or
a defect claim against 40072. Its source, application, notarization and install
journals remain unchanged. No public release has occurred.

40072 is retired as `retired_product_change_after_install_before_ga_runtime_acceptance`.
40073 remains unconsumed until durable candidate freeze. Pre-freeze failures
retain the same build and a new attempt identity.

Settings schema 1 is read without rewriting; the first preference save writes
schema 2. Installation preserves an exact private backup of the old preference
file so a rollback to 40072 can restore its compatible settings.
