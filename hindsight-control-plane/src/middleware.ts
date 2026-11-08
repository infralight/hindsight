import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { localizeApiErrorPayload } from "@/lib/i18n/api-errors";
import createIntlMiddleware from "next-intl/middleware";

import {
  ACCESS_KEY_COOKIE,
  SESSION_REQUIRED_HEADER,
  sessionCookieOptions,
  verifySessionToken,
} from "@/lib/auth/session";
import { oidcConfig, refreshIdToken } from "@/lib/auth/oidc";
import {
  USER_SESSION_COOKIE,
  USER_SESSION_MAX_AGE_SECONDS,
  isRbacAuthMode,
  openSession,
  sealSession,
  sessionSecret,
  type UserSession,
} from "@/lib/auth/user-session";
import { sanitizeReturnTo, stripBasePath, withBasePath } from "@/lib/base-path";
import { routing } from "@/i18n/routing";

// Routes that don't require authentication
const PUBLIC_PATTERNS = [
  "/login",
  "/api/auth/",
  "/api/health",
  "/api/version",
  "/logo.png",
  "/favicon",
  "/_next",
  "/fonts",
  "/static",
];

const intlMiddleware = createIntlMiddleware(routing);

// fork(rbac): seconds before an ID token's expiry at which it is refreshed.
const REFRESH_LEEWAY_SECONDS = 60;

/** fork(rbac): the signed-in user's session, refreshing an expiring ID token; null = signed out. */
async function currentSession(
  request: NextRequest,
  secret: string
): Promise<{ session: UserSession | null; resealed?: string }> {
  const session = await openSession(request.cookies.get(USER_SESSION_COOKIE)?.value, secret);
  if (!session || session.kind !== "oidc") return { session };
  if (session.credExp - REFRESH_LEEWAY_SECONDS > Math.floor(Date.now() / 1000)) return { session };
  const cfg = oidcConfig();
  if (!cfg || !session.refresh) return { session: null };
  try {
    const tokens = await refreshIdToken(cfg, session.refresh);
    const refreshed: UserSession = {
      ...session,
      cred: tokens.idToken,
      refresh: tokens.refresh ?? session.refresh,
      credExp: tokens.exp,
    };
    return { session: refreshed, resealed: await sealSession(refreshed, secret) };
  } catch {
    return { session: null };
  }
}

/** fork(rbac): per-user sessions instead of the shared access key. */
async function rbacMiddleware(request: NextRequest, appPathname: string) {
  const isApi = appPathname.startsWith("/api/");
  const isPublic = PUBLIC_PATTERNS.some((pattern) => appPathname.startsWith(pattern));
  const isLogin = appPathname === "/login";
  const secret = sessionSecret();
  if (!secret) {
    if (isPublic) return isApi ? NextResponse.next() : intlMiddleware(request);
    return isApi
      ? NextResponse.json(
          { error: "HINDSIGHT_CP_SESSION_SECRET is not configured" },
          { status: 500 }
        )
      : NextResponse.redirect(new URL(withBasePath("/login?error=config"), request.url));
  }
  if (isPublic && !isLogin) return isApi ? NextResponse.next() : intlMiddleware(request);

  const { session, resealed } = await currentSession(request, secret);
  if (resealed) {
    // The route handler reads the session from this request: hand it the refreshed one too.
    request.cookies.set(USER_SESSION_COOKIE, resealed);
  }

  let response: NextResponse;
  if (isLogin && session) {
    const target = sanitizeReturnTo(request.nextUrl.searchParams.get("returnTo"));
    response = NextResponse.redirect(new URL(withBasePath(target), request.url));
  } else if (isLogin) {
    return intlMiddleware(request);
  } else if (!session && isApi) {
    return NextResponse.json(
      localizeApiErrorPayload(request, {
        error: "Unauthorized",
        errorKey: "api.errors.auth.unauthorized",
      }),
      { status: 401, headers: { [SESSION_REQUIRED_HEADER]: "1" } }
    );
  } else if (!session) {
    const loginUrl = new URL(withBasePath("/login"), request.url);
    loginUrl.searchParams.set("returnTo", appPathname);
    return NextResponse.redirect(loginUrl);
  } else {
    response = isApi
      ? NextResponse.next({ request: { headers: request.headers } })
      : intlMiddleware(request);
  }
  if (resealed) {
    response.cookies.set({
      name: USER_SESSION_COOKIE,
      value: resealed,
      ...sessionCookieOptions(request),
      maxAge: USER_SESSION_MAX_AGE_SECONDS,
    });
  }
  return response;
}

export async function middleware(request: NextRequest) {
  if (isRbacAuthMode()) return rbacMiddleware(request, stripBasePath(request.nextUrl.pathname));

  const accessKey = process.env.HINDSIGHT_CP_ACCESS_KEY;
  const { pathname } = request.nextUrl;
  const appPathname = stripBasePath(pathname);

  // API routes are not locale-prefixed — handle auth directly without i18n routing.
  if (appPathname.startsWith("/api/")) {
    if (!accessKey) {
      return NextResponse.next();
    }

    const isPublic = PUBLIC_PATTERNS.some((pattern) => appPathname.startsWith(pattern));
    if (isPublic) {
      return NextResponse.next();
    }

    const sessionCookie = request.cookies.get(ACCESS_KEY_COOKIE)?.value;
    const isAuthenticated = await verifySessionToken(sessionCookie, accessKey);

    if (!isAuthenticated) {
      return NextResponse.json(
        localizeApiErrorPayload(request, {
          error: "Unauthorized",
          errorKey: "api.errors.auth.unauthorized",
        }),
        // The header tells the browser this 401 is about its own session, so only
        // this one sends it to the login form. A 401 forwarded from the dataplane
        // can't be fixed by re-entering the UI key.
        { status: 401, headers: { [SESSION_REQUIRED_HEADER]: "1" } }
      );
    }

    return NextResponse.next();
  }

  // Page routes: enforce auth first, then delegate to the i18n middleware for
  // locale negotiation and rewriting. With localePrefix "never" the locale is
  // never in the path, so appPathname is already the canonical route.
  if (accessKey) {
    const isPublic = PUBLIC_PATTERNS.some((pattern) => appPathname.startsWith(pattern));
    const isLogin = appPathname === "/login";

    if (!isPublic || isLogin) {
      const sessionCookie = request.cookies.get(ACCESS_KEY_COOKIE)?.value;
      const isAuthenticated = await verifySessionToken(sessionCookie, accessKey);

      if (isLogin) {
        // Already signed in: skip the key form and continue where the link pointed.
        if (isAuthenticated) {
          const target = sanitizeReturnTo(request.nextUrl.searchParams.get("returnTo"));
          return NextResponse.redirect(new URL(withBasePath(target), request.url));
        }
      } else if (!isAuthenticated) {
        // Next.js middleware redirects do not automatically inherit next.config basePath.
        // Prefix the target explicitly, but keep returnTo as the app-relative path so
        // client-side router.push() does not double-prefix after login.
        const loginUrl = new URL(withBasePath("/login"), request.url);
        loginUrl.searchParams.set("returnTo", appPathname);
        return NextResponse.redirect(loginUrl);
      }
    }
  }

  return intlMiddleware(request);
}

export const config = {
  // Match all paths except Next.js internals and static assets.
  // - Use an explicit file extension allowlist instead of .*\..* so that
  //   dynamic segments containing dots (e.g. bank IDs like
  //   "SX.Products.GovComply.Build") still get the i18n locale rewrite.
  matcher:
    "/((?!_next|_vercel|.*\\.(?:png|jpe?g|gif|svg|webp|ico|css|js|map|woff2?|ttf|eot|txt|xml|json)$).*)",
};
