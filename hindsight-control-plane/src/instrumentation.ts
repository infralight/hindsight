/**
 * Next.js instrumentation file - runs exactly once at server startup.
 * https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 */
export async function register() {
  const dataplaneUrl = process.env.HINDSIGHT_CP_DATAPLANE_API_URL || "http://localhost:8888";
  const apiKey = process.env.HINDSIGHT_CP_DATAPLANE_API_KEY || "";

  console.log(`[Control Plane] Connecting to dataplane at: ${dataplaneUrl}`);

  // fork(rbac): per-user sessions; every dataplane call is made as the signed-in user.
  if (process.env.HINDSIGHT_CP_AUTH_MODE === "rbac") {
    if (process.env.NEXT_RUNTIME !== "nodejs") return;
    const { installDataplaneAuth } = await import("@/lib/auth/dataplane-auth");
    const { USER_SESSION_COOKIE, openSession, sessionSecret } =
      await import("@/lib/auth/user-session");
    const secret = sessionSecret();
    if (!secret) {
      console.error(
        "[Control Plane] HINDSIGHT_CP_SESSION_SECRET (32+ chars) is required in rbac mode"
      );
      return;
    }
    installDataplaneAuth(dataplaneUrl, async () => {
      try {
        const { cookies } = await import("next/headers");
        return await openSession((await cookies()).get(USER_SESSION_COOKIE)?.value, secret);
      } catch {
        return null; // outside a request: no user
      }
    });
    console.log("[Control Plane] Per-user authentication (rbac mode)");
    return;
  }

  if (apiKey) {
    console.log("[Control Plane] Using API key authentication");
  } else {
    console.log("[Control Plane] No API key configured (public access)");
  }
}
