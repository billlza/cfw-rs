import CFWAdversarialFixtureSupport

@main
private enum Main {
  static func main() async {
    await AdversarialFixtureMain.run(
      fixtureID: .rootOwnedAuthorityJournalSnapshot,
      allowedCases: [
        .replayCursorRollback, .authorityJournalTruncation,
        .authorityJournalTamper, .authorityJournalSymlink,
      ])
  }
}
