import CFWSharedProtocol
import Darwin
import Foundation
import Security
import Testing

import struct CryptoKit.SHA256

@testable import CFWGlobalAuthority

// Recovery from a journal image: only the committed high water; an empty store;
// truncation, corruption, reordering and rollback quarantined; and the
// canonical schema.
@Test func recoveryRejectsQuarantineOutsideTheDurableCleanupTransition() throws {
  for state in [AuthorityState.recovering, .quarantined] {
    let image = try journalImage([
      committedState(revision: 1, state: state, transition: .ready)
    ])
    #expect(AuthorityJournalRecoveryReducer.recover(image).posture == .quarantined(.invalidState))
  }
}

@Test func recoveryReconstructsOnlyCommittedHighWaterAndStartsRecovering() throws {
  let first = try committedState(revision: 1)
  let active = try committedState(
    revision: 2, state: .active, transition: .ready)
  let recovery = AuthorityJournalRecoveryReducer.recover(
    try journalImage([first, active]))

  #expect(recovery.committedState == active)
  #expect(recovery.head?.sequence == 2)
  #expect(recovery.posture == .recovering(.reattestOwner))
  #expect(!recovery.permitsStart)
}

@Test func emptyStoreDoesNotInventReplayStateOrPermitStart() {
  let recovery = AuthorityJournalRecoveryReducer.recover(
    AuthorityJournalImage(journal: nil, head: nil))
  #expect(recovery.committedState == nil)
  #expect(recovery.posture == .recovering(.verifyOff))
  #expect(!recovery.permitsStart)
}

@Test func truncationCorruptionAndReorderingAlwaysQuarantine() throws {
  let first = try committedState(revision: 1)
  let second = try committedState(revision: 2)
  let image = try journalImage([first, second])
  let journal = try #require(image.journal)

  let truncated = AuthorityJournalImage(
    journal: journal.dropLast(), head: image.head)
  #expect(
    isQuarantined(
      AuthorityJournalRecoveryReducer.recover(truncated), reason: .truncated))

  var corrupted = journal
  corrupted[corrupted.index(before: corrupted.endIndex)] ^= 0xff
  #expect(
    isQuarantined(
      AuthorityJournalRecoveryReducer.recover(
        AuthorityJournalImage(journal: corrupted, head: image.head))))

  let decoded = try AuthorityJournalCodec.decodeRecords(journal)
  let firstEnd = try #require(decoded.first?.endOffset)
  let reorderedData =
    journal.subdata(in: firstEnd..<journal.count)
    + journal.subdata(in: 0..<firstEnd)
  #expect(
    isQuarantined(
      AuthorityJournalRecoveryReducer.recover(
        AuthorityJournalImage(journal: reorderedData, head: image.head))))
}

@Test func rolledBackOrTrailingHeadNeverResetsPermissively() throws {
  let firstImage = try journalImage([committedState(revision: 1)])
  let firstHead = try AuthorityJournalCodec.decodeHead(try #require(firstImage.head))
  let secondImage = try journalImage([
    committedState(revision: 1), committedState(revision: 2),
  ])
  let secondHead = try AuthorityJournalCodec.decodeHead(try #require(secondImage.head))

  let rolledBack = AuthorityJournalRecoveryReducer.recover(
    firstImage, minimumHead: secondHead)
  #expect(isQuarantined(rolledBack, reason: .rollback))
  #expect(rolledBack.committedState == nil)

  let trailing = AuthorityJournalRecoveryReducer.recover(
    AuthorityJournalImage(
      journal: secondImage.journal,
      head: try AuthorityJournalCodec.encodeHead(firstHead)
    ))
  #expect(isQuarantined(trailing, reason: .trailingData))
  #expect(!trailing.permitsStart)
}

@Test func unknownCanonicalRecordFieldIsRejected() throws {
  let state = try committedState(revision: 1)
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
  let canonical = try encoder.encode(state)
  var object = try #require(
    JSONSerialization.jsonObject(with: canonical) as? [String: Any])
  object["future_field"] = 1
  let unknownPayload = try JSONSerialization.data(
    withJSONObject: object,
    options: [.sortedKeys, .withoutEscapingSlashes]
  )
  let framed = try frameForTesting(
    payload: unknownPayload,
    sequence: 1,
    previous: AuthorityJournalCodec.zeroDigest
  )
  let head = try AuthorityJournalHead(
    sequence: 1,
    committedLength: UInt64(framed.frame.count),
    recordSHA256: framed.digest
  )
  let recovery = AuthorityJournalRecoveryReducer.recover(
    AuthorityJournalImage(
      journal: framed.frame,
      head: try AuthorityJournalCodec.encodeHead(head)
    ))
  #expect(isQuarantined(recovery, reason: .noncanonicalRecord))
}

@Test func journalSchemaCannotSerializeTicketsSecretsOrConfigurationBytes() throws {
  let image = try journalImage([
    committedState(revision: 1, state: .preparing, transition: .prepare)
  ])
  let bytes = try #require(image.journal)
  let text = String(decoding: bytes, as: UTF8.self)
  #expect(!text.contains("ticket"))
  #expect(!text.contains("secret"))
  #expect(!text.contains("credential"))
  #expect(!text.contains("configuration_bytes"))
}
