import CFWAdversarialFixtureSupport

@main
private enum Main {
  static func main() async {
    await AdversarialFixtureMain.run(
      fixtureID: .signedOwnerLiveness,
      allowedCases: [.heartbeatLoss, .lateCallback])
  }
}
