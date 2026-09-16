export const sessionClaimHeader = "X-Qodo-Viewer-Session";

export function takeLauncherToken(windowObject = globalThis.window) {
  const nameToken = windowObject.name;
  const fragmentToken = windowObject.location?.hash?.replace(/^#/, "") || "";
  windowObject.name = "";
  if (windowObject.location?.hash && windowObject.history?.replaceState) {
    windowObject.history.replaceState(
      null,
      "",
      `${windowObject.location.pathname}${windowObject.location.search}`,
    );
  }
  if (/^[0-9a-f]{64}$/.test(nameToken)) {
    return nameToken;
  }
  return /^[0-9a-f]{64}$/.test(fragmentToken) ? fragmentToken : "";
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
