export const sessionClaimHeader = "X-Qodo-Viewer-Session";

export function takeLauncherToken(windowObject = globalThis.window) {
  const token = windowObject.name;
  windowObject.name = "";
  return /^[0-9a-f]{64}$/.test(token) ? token : "";
}

export async function claimViewerSession(
  token,
  fetchImplementation = globalThis.fetch,
  origin = globalThis.location.origin,
) {
  const response = await fetchImplementation(new URL("/api/session", origin), {
    method: "POST",
    credentials: "same-origin",
    headers: {
      [sessionClaimHeader]: token,
    },
  });
  if (!response.ok) {
    const error = new Error(`${response.status} ${response.statusText}`);
    error.status = response.status;
    throw error;
  }
}

export async function initializeClaimedViewer(
  session,
  initialize,
  claimImplementation = claimViewerSession,
) {
  if (!session.sessionClaimed) {
    await claimImplementation(session.accessToken);
    session.sessionClaimed = true;
  }
  await initialize();
}
