# GA build 40049 retirement

Build 40049 is classified as
`retired_product_change_notarization_outcome_unknown`. Its frozen application
and nested code were signed. Apple submission
`6ddaf650-3af8-465c-881f-d5a6fe9830e8` remained In Progress after the upload
command failed. Preserve that submission, archive, signing records and recovery
journal; they are neither a rejection nor a successful notarization.

The application was not installed or publicly released. Build 40048 remains
the installed predecessor. An isolated production-runtime test with the full
imported profile forwarded real HTTPS requests on separate loopback ports;
this did not test installed System Proxy or TUN activation.

40050 corrects cleanup when an external proxy has replaced or disabled the
owned listener. Stored and effective settings must agree before the ownership
journal can be released; unresolved endpoints remain errors. It also adds an
explicit service-retirement operation for a dead Authority, inactive TUN and
disabled system proxy switches. That operation unregisters only the current
application's services and preserves the pending recovery journals. It returns
no Off attestation.

These changes alter application code. Build 40049 must not be rebuilt or
re-signed with them. Neither the failed upload nor the repaired test-fixture
race alone requires a new build.
