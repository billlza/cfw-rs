// Live stream bindings across restarts: provenance that rotates, a start that
// a pause supersedes, and events buffered from an earlier runtime.
import assert from "node:assert/strict";
import test from "node:test";
import {
  RUNNING_ENGINE, activeStreamBindings, appModule, deferred, emit, invocationDetails, listeners,
  responses, runtime, startStreamFixture, state, streamBindingFor, streamEvent, waitForInvocation,
} from "./support/render-harness.mjs";

test("same-runtime stop and restart rotates provenance and rejects every old envelope", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalConnectionPaused = state.connectionPaused;
  const originalLogsPaused = state.logsPaused;
  const originalLogs = [...state.logs];

  try {
    state.connectionPaused = false;
    state.logsPaused = false;
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    const oldConnections = structuredClone(runtime.connectionsLiveStream.binding);
    const oldLogs = structuredClone(runtime.logLiveStream.binding);
    assert.ok(oldConnections);
    assert.ok(oldLogs);

    await appModule.handleAction("toggle-connection-stream");
    await appModule.handleAction("toggle-log-stream");
    assert.equal(state.connectionPaused, true);
    assert.equal(state.logsPaused, true);
    assert.equal(runtime.connectionsLiveStream.binding, null);
    assert.equal(runtime.logLiveStream.binding, null);

    await appModule.handleAction("toggle-connection-stream");
    await appModule.handleAction("toggle-log-stream");
    const newConnections = structuredClone(runtime.connectionsLiveStream.binding);
    const newLogs = structuredClone(runtime.logLiveStream.binding);
    assert.ok(newConnections.stream_id > oldConnections.stream_id);
    assert.ok(newLogs.stream_id > oldLogs.stream_id);
    assert.deepEqual(newConnections.runtime, oldConnections.runtime);
    assert.deepEqual(newLogs.runtime, oldLogs.runtime);

    state.connections = [];
    await emit("cfw://connections-snapshot", {
      provenance: oldConnections,
      payload: {
        upload: 1,
        download: 1,
        connections: [{
          id: "old-same-runtime-connection",
          upload: 1,
          download: 1,
          start: "2026-01-01T00:00:00Z",
          chains: ["OLD"],
          rule: "MATCH",
          metadata: { host: "old.example" },
        }],
      },
    });
    await emit("cfw://log-lines", {
      provenance: oldLogs,
      payload: [{
        time: "12:00:00",
        level: "info",
        source: "old-stream",
        message: "old same-runtime log",
        fields: [],
      }],
    });
    await emit("cfw://stream-error", {
      provenance: oldConnections,
      payload: {
        stream: "connections",
        message: "old same-runtime stream error",
        level: "warning",
      },
    });
    assert.equal(state.connections.some(({ id }) => id === "old-same-runtime-connection"), false);
    assert.equal(state.logs.some(({ message }) => message === "old same-runtime log"), false);
    assert.equal(state.logs.some(({ message }) => message === "old same-runtime stream error"), false);

    await emit("cfw://connections-snapshot", {
      provenance: newConnections,
      payload: {
        upload: 2,
        download: 2,
        connections: [{
          id: "new-same-runtime-connection",
          upload: 2,
          download: 2,
          start: "2026-01-01T00:00:01Z",
          chains: ["NEW"],
          rule: "MATCH",
          metadata: { host: "new.example" },
        }],
      },
    });
    await emit("cfw://log-lines", {
      provenance: newLogs,
      payload: [{
        time: "12:00:01",
        level: "info",
        source: "new-stream",
        message: "new same-runtime log",
        fields: [],
      }],
    });
    assert.deepEqual(state.connections.map(({ id }) => id), ["new-same-runtime-connection"]);
    assert.equal(state.logs.some(({ message }) => message === "new same-runtime log"), true);
  } finally {
    state.connectionPaused = originalConnectionPaused;
    state.logsPaused = originalLogsPaused;
    state.logs = originalLogs;
    responses.engine_snapshot = originalEngine;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
  }
});

test("a start response superseded by pause cannot republish a running binding", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalStart = responses.start_connections_stream;
  const originalConnectionPaused = state.connectionPaused;
  const originalLogs = [...state.logs];
  const delayedStart = deferred();
  let resumeAction = null;
  let pauseAction = null;

  try {
    state.connectionPaused = false;
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    await appModule.handleAction("toggle-connection-stream");
    assert.equal(state.connectionPaused, true);
    assert.equal(runtime.connectionsLiveStream.binding, null);

    const delayedBinding = startStreamFixture("connections", RUNNING_ENGINE);
    responses.start_connections_stream = delayedStart.promise;
    const startCalls = invocationDetails.filter(({ command }) => (
      command === "start_connections_stream"
    )).length;

    resumeAction = appModule.handleAction("toggle-connection-stream");
    await waitForInvocation("start_connections_stream", startCalls);
    assert.equal(state.connectionPaused, false);
    pauseAction = appModule.handleAction("toggle-connection-stream");
    assert.equal(state.connectionPaused, true, "pause supersedes the in-flight start immediately");

    delayedStart.resolve(delayedBinding);
    await Promise.all([resumeAction, pauseAction]);
    assert.equal(runtime.connectionsLiveStream.binding, null);
    assert.equal(activeStreamBindings.has("connections"), false);

    state.connections = [];
    await emit("cfw://connections-snapshot", {
      provenance: delayedBinding,
      payload: {
        upload: 1,
        download: 1,
        connections: [{
          id: "superseded-start-connection",
          upload: 1,
          download: 1,
          start: "2026-01-01T00:00:00Z",
          chains: ["STALE"],
          rule: "MATCH",
          metadata: { host: "stale-start.example" },
        }],
      },
    });
    assert.deepEqual(state.connections, []);

    responses.start_connections_stream = originalStart;
    await appModule.handleAction("toggle-connection-stream");
    const resumedBinding = runtime.connectionsLiveStream.binding;
    assert.ok(resumedBinding.stream_id > delayedBinding.stream_id);
    assert.equal(state.connectionPaused, false);
  } finally {
    delayedStart.resolve(startStreamFixture("connections", RUNNING_ENGINE));
    if (resumeAction) await resumeAction.catch(() => {});
    if (pauseAction) await pauseAction.catch(() => {});
    responses.start_connections_stream = originalStart;
    state.connectionPaused = originalConnectionPaused;
    state.logs = originalLogs;
    responses.engine_snapshot = originalEngine;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
  }
});

test("runtime A buffered stream events cannot be accepted after runtime B is bound", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalConnectionPaused = state.connectionPaused;
  const originalLogsPaused = state.logsPaused;
  const runtimeB = {
    ...RUNNING_ENGINE,
    snapshot: {
      ...RUNNING_ENGINE.snapshot,
      generation: 4,
      config_digest: "digest-b",
      state: {
        state: "proxy_active",
        runtime: {
          ...RUNNING_ENGINE.snapshot.state.runtime,
          context: {
            ...RUNNING_ENGINE.snapshot.state.runtime.context,
            config_epoch: 2,
            generation: 4,
          },
          config_digest: "digest-b",
        },
      },
    },
  };
  const delayedConnection = {
    upload: 1,
    download: 2,
    connections: [{
      id: "runtime-a-delayed",
      upload: 1,
      download: 2,
      start: "2026-01-01T00:00:00Z",
      chains: ["A"],
      rule: "MATCH",
      metadata: { host: "a-delayed.example" },
    }],
  };
  const liveConnection = {
    upload: 3,
    download: 4,
    connections: [{
      id: "runtime-b-live",
      upload: 3,
      download: 4,
      start: "2026-01-01T00:00:01Z",
      chains: ["B"],
      rule: "MATCH",
      metadata: { host: "b-live.example" },
    }],
  };

  try {
    state.connectionPaused = false;
    state.logsPaused = false;
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    const bindingA = streamBindingFor("connections", RUNNING_ENGINE);

    responses.engine_snapshot = runtimeB;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    const bindingB = streamBindingFor("connections", runtimeB);
    assert.notDeepEqual(bindingA, bindingB);
    state.connections = [];

    await emit("cfw://connections-snapshot", {
      provenance: bindingA,
      payload: delayedConnection,
    });
    await emit("cfw://log-lines", streamEvent("request-logs", [{
      time: "12:00:00",
      level: "info",
      source: "runtime-a",
      message: "runtime A delayed log",
      fields: [],
    }], RUNNING_ENGINE));
    await emit("cfw://stream-error", streamEvent("connections", {
      stream: "connections",
      message: "runtime A delayed error",
      level: "warning",
    }, RUNNING_ENGINE));

    assert.equal(state.connections.some(({ id }) => id === "runtime-a-delayed"), false);
    assert.equal(state.logs.some(({ message }) => message === "runtime A delayed log"), false);
    assert.equal(state.logs.some(({ message }) => message === "runtime A delayed error"), false);

    await emit("cfw://connections-snapshot", {
      provenance: bindingB,
      payload: liveConnection,
    });
    await emit("cfw://log-lines", streamEvent("request-logs", [{
      time: "12:00:01",
      level: "info",
      source: "runtime-b",
      message: "runtime B live log",
      fields: [],
    }], runtimeB));

    assert.deepEqual(state.connections.map(({ id }) => id), ["runtime-b-live"]);
    assert.equal(state.logs.some(({ message }) => message === "runtime B live log"), true);
  } finally {
    state.connectionPaused = originalConnectionPaused;
    state.logsPaused = originalLogsPaused;
    responses.engine_snapshot = originalEngine;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
  }
});

test("a delayed runtime A pause stays serialized across same-runtime refresh and runtime B", async () => {
  const originalEngine = responses.engine_snapshot;
  const originalStop = responses.stop_connections_stream;
  const originalConnectionPaused = state.connectionPaused;
  const delayedStop = deferred();
  let pauseAction = null;
  let sameRuntimeRefresh = null;
  let runtimeTransition = null;
  let resumeAction = null;
  const runtimeB = {
    ...RUNNING_ENGINE,
    snapshot: {
      ...RUNNING_ENGINE.snapshot,
      generation: 5,
      config_digest: "digest-pause-b",
      state: {
        state: "proxy_active",
        runtime: {
          ...RUNNING_ENGINE.snapshot.state.runtime,
          context: {
            ...RUNNING_ENGINE.snapshot.state.runtime.context,
            config_epoch: 3,
            generation: 5,
          },
          config_digest: "digest-pause-b",
        },
      },
    },
  };

  try {
    state.connectionPaused = false;
    responses.engine_snapshot = RUNNING_ENGINE;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
    const bindingA = streamBindingFor("connections", RUNNING_ENGINE);
    const stopCalls = invocationDetails.filter(({ command }) => (
      command === "stop_connections_stream"
    )).length;
    const startCalls = invocationDetails.filter(({ command }) => (
      command === "start_connections_stream"
    )).length;
    responses.stop_connections_stream = delayedStop.promise;

    pauseAction = appModule.handleAction("toggle-connection-stream");
    await waitForInvocation("stop_connections_stream", stopCalls);
    assert.equal(state.connectionPaused, true, "pause intent must publish before native completion");
    assert.deepEqual(
      invocationDetails.filter(({ command }) => command === "stop_connections_stream").at(-1)?.args,
      { expected: bindingA },
    );

    const engineCalls = invocationDetails.filter(({ command }) => command === "engine_snapshot").length;
    sameRuntimeRefresh = listeners.get("cfw://engine-event")?.({
      event: "cfw://engine-event",
      payload: { type: "snapshot_changed" },
    });
    await waitForInvocation("engine_snapshot", engineCalls);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(
      invocationDetails.filter(({ command }) => command === "start_connections_stream").length,
      startCalls,
      "a same-runtime refresh must respect the already-published pause intent",
    );

    responses.engine_snapshot = runtimeB;
    runtimeTransition = listeners.get("cfw://engine-event")?.({
      event: "cfw://engine-event",
      payload: { type: "snapshot_changed" },
    });
    await waitForInvocation("engine_snapshot", engineCalls + 1);
    await new Promise((resolve) => setTimeout(resolve, 20));
    assert.equal(
      invocationDetails.filter(({ command }) => command === "start_connections_stream").length,
      startCalls,
      "the pause intent must remain in force when runtime B becomes active",
    );

    delayedStop.resolve(null);
    await Promise.all([pauseAction, sameRuntimeRefresh, runtimeTransition]);
    assert.equal(state.connectionPaused, true);

    resumeAction = appModule.handleAction("toggle-connection-stream");
    await resumeAction;
    assert.equal(state.connectionPaused, false);
    assert.equal(
      invocationDetails.filter(({ command }) => command === "start_connections_stream").length,
      startCalls + 1,
      "resuming must start exactly one stream bound to runtime B",
    );

    state.connections = [];
    await emit("cfw://connections-snapshot", {
      provenance: bindingA,
      payload: { upload: 1, download: 1, connections: [] },
    });
    await emit("cfw://connections-snapshot", streamEvent("connections", {
      upload: 2,
      download: 2,
      connections: [{
        id: "runtime-b-after-stale-stop",
        upload: 2,
        download: 2,
        start: "2026-01-01T00:00:02Z",
        chains: ["B"],
        rule: "MATCH",
        metadata: { host: "runtime-b.example" },
      }],
    }, runtimeB));
    assert.deepEqual(state.connections.map(({ id }) => id), ["runtime-b-after-stale-stop"]);
  } finally {
    delayedStop.resolve(null);
    if (pauseAction) await pauseAction.catch(() => {});
    if (sameRuntimeRefresh) await sameRuntimeRefresh.catch(() => {});
    if (runtimeTransition) await runtimeTransition.catch(() => {});
    if (resumeAction) await resumeAction.catch(() => {});
    responses.stop_connections_stream = originalStop;
    state.connectionPaused = originalConnectionPaused;
    responses.engine_snapshot = originalEngine;
    await emit("cfw://engine-event", { type: "snapshot_changed" });
  }
});
