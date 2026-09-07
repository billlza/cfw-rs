import CFWAdversarialFixtureSupport

@main
private enum Main {
  static func main() async {
    await AdversarialFixtureMain.run(
      fixtureID: .rootOwnedSecretCanaryScanner,
      allowedCases: [
        .secretExtractionLogs, .secretExtractionPreferences,
        .secretExtractionJournal, .secretExtractionCrashRecords,
        .secretExtractionSnapshots, .secretExtractionEvidence,
      ])
  }
}
