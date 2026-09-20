import CFWAdversarialFixtureSupport

@main
private enum Main {
  static func main() async {
    await AdversarialFixtureMain.run(
      fixtureID: .boundedAuthorityLoad,
      allowedCases: [.requestFlood, .inFlightSaturation, .eventQueueSaturation])
  }
}
