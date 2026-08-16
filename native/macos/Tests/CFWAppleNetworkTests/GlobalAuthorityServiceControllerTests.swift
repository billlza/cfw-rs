import Foundation
import Testing

@testable import CFWAppleNetwork

private final class FakeAuthorityDaemonService: GlobalAuthorityDaemonServicing,
  @unchecked Sendable
{
  private(set) var registerCalls = 0
  var statuses: [GlobalAuthorityRegistrationStatus]
  var registerError: (any Error)?

  init(_ statuses: [GlobalAuthorityRegistrationStatus], registerError: (any Error)? = nil) {
    self.statuses = statuses
    self.registerError = registerError
  }

  var registrationStatus: GlobalAuthorityRegistrationStatus {
    statuses.count > 1 ? statuses.removeFirst() : statuses[0]
  }

  func register() throws {
    registerCalls += 1
    if let registerError { throw registerError }
  }
}

private enum FakeRegistrationError: Error { case denied }

@Test func authorityRegistrationIsIdempotentWhenAlreadyEnabled() throws {
  let service = FakeAuthorityDaemonService([.enabled])
  try SMGlobalAuthorityServiceController(service: service).ensureRegistered()
  #expect(service.registerCalls == 0)
}

@Test func authorityRegistrationUsesDaemonServiceAndRequiresEnabledResult() throws {
  let service = FakeAuthorityDaemonService([.notRegistered, .enabled])
  let controller = SMGlobalAuthorityServiceController(service: service)
  try controller.ensureRegistered()
  #expect(service.registerCalls == 1)
  #expect(controller.registrationStatus() == .enabled)
}

@Test func authorityRegistrationRepairsNotFoundServiceRecord() throws {
  let service = FakeAuthorityDaemonService([.notFound, .enabled])
  let controller = SMGlobalAuthorityServiceController(service: service)
  try controller.ensureRegistered()
  #expect(service.registerCalls == 1)
  #expect(controller.registrationStatus() == .enabled)
}

@Test func authorityRegistrationMapsApprovalAbsenceAndFailureToStableErrors() {
  let cases: [(FakeAuthorityDaemonService, GlobalAuthorityRegistrationError)] = [
    (FakeAuthorityDaemonService([.requiresApproval]), .approvalRequired),
    (FakeAuthorityDaemonService([.notFound]), .serviceNotFound),
    (
      FakeAuthorityDaemonService([.notRegistered], registerError: FakeRegistrationError.denied),
      .registrationFailed
    ),
    (FakeAuthorityDaemonService([.notRegistered]), .registrationFailed),
  ]
  for (service, expected) in cases {
    #expect(throws: expected) {
      try SMGlobalAuthorityServiceController(service: service).ensureRegistered()
    }
  }
}
