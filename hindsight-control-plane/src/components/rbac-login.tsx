"use client";

/**
 * fork(rbac): the sign-in card for per-user sessions — company SSO first, a personal
 * API token as the fallback (and the only option where SSO is not configured).
 */

import { FormEvent, useState } from "react";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { withBasePath } from "@/lib/base-path";

interface RbacLoginProps {
  google: boolean;
  tokenLogin: boolean;
  returnTo: string;
  error: string | null;
}

function GoogleMark() {
  return (
    <svg viewBox="0 0 48 48" className="h-4 w-4" aria-hidden="true">
      <path
        fill="#FFC107"
        d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.3 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 12.9 4 4 12.9 4 24s8.9 20 20 20 20-8.9 20-20c0-1.3-.1-2.3-.4-3.5z"
      />
      <path
        fill="#FF3D00"
        d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3.1l5.7-5.7C34 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"
      />
      <path
        fill="#4CAF50"
        d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.3 0-9.7-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"
      />
      <path
        fill="#1976D2"
        d="M43.6 20.5H42V20H24v8h11.3c-.8 2.2-2.2 4.2-4.1 5.6l6.2 5.2C37 39.2 44 34 44 24c0-1.3-.1-2.3-.4-3.5z"
      />
    </svg>
  );
}

export function RbacLogin({ google, tokenLogin, returnTo, error }: RbacLoginProps) {
  const t = useTranslations("login");
  const [token, setToken] = useState("");
  const [tokenError, setTokenError] = useState("");
  const [loading, setLoading] = useState(false);

  const initialError =
    error === "sso"
      ? t("ssoFailed")
      : error === "config" || (!google && !tokenLogin)
        ? t("configError")
        : "";

  async function signInWithToken(e: FormEvent) {
    e.preventDefault();
    setTokenError("");
    setLoading(true);
    try {
      const res = await fetch(withBasePath("/api/auth/token-login"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      if (res.ok) {
        window.location.href = withBasePath(returnTo);
        return;
      }
      setTokenError(res.status === 401 ? t("invalidToken") : t("connectFailed"));
    } catch {
      setTokenError(t("connectFailed"));
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      {initialError && <p className="text-sm text-red-600 dark:text-red-400">{initialError}</p>}

      {google && (
        <Button asChild variant="outline" className="w-full gap-2">
          <a href={withBasePath(`/api/auth/oidc/start?returnTo=${encodeURIComponent(returnTo)}`)}>
            <GoogleMark />
            {t("signInWithGoogle")}
          </a>
        </Button>
      )}

      {google && tokenLogin && (
        <div className="flex items-center gap-3 text-xs text-muted-foreground">
          <div className="h-px flex-1 bg-border" />
          {t("orUseToken")}
          <div className="h-px flex-1 bg-border" />
        </div>
      )}

      {tokenLogin && (
        <form onSubmit={signInWithToken} className="space-y-3">
          <Input
            id="api-token"
            type="password"
            placeholder={t("tokenPlaceholder")}
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="off"
          />
          {tokenError && <p className="text-sm text-red-600 dark:text-red-400">{tokenError}</p>}
          <Button
            type="submit"
            variant={google ? "secondary" : "default"}
            className="w-full"
            disabled={loading || !token}
          >
            {loading ? t("signingIn") : t("signInWithToken")}
          </Button>
        </form>
      )}
    </div>
  );
}
