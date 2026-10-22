"use client";

/**
 * fork(rbac): the sign-in options for per-user sessions — company SSO first, a
 * personal or service-account API token as the fallback (and the only option
 * where SSO is not configured).
 */

import { FormEvent, useState } from "react";
import { useTranslations } from "next-intl";
import { ChevronDown, KeyRound } from "lucide-react";
import { SecretField } from "@/components/login/secret-field";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { withBasePath } from "@/lib/base-path";

interface RbacLoginProps {
  google: boolean;
  tokenLogin: boolean;
  returnTo: string;
  error: string | null;
}

function GoogleMark() {
  return (
    <svg viewBox="0 0 48 48" className="h-[18px] w-[18px]" aria-hidden="true">
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
  const [redirecting, setRedirecting] = useState(false);
  // With SSO on, the token form is the secondary path: one click away, not in the way.
  const [tokenOpen, setTokenOpen] = useState(!google);

  const pageError =
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
        body: JSON.stringify({ token: token.trim() }),
      });
      if (res.ok) {
        window.location.href = withBasePath(returnTo);
        return;
      }
      setTokenError(res.status === 401 ? t("invalidToken") : t("connectFailed"));
    } catch {
      setTokenError(t("connectFailed"));
    }
    setLoading(false);
  }

  return (
    <div className="space-y-6">
      {pageError && (
        <div
          role="alert"
          className="rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-700 dark:text-red-300"
        >
          {pageError}
        </div>
      )}

      {google && (
        <a
          href={withBasePath(`/api/auth/oidc/start?returnTo=${encodeURIComponent(returnTo)}`)}
          onClick={() => setRedirecting(true)}
          aria-busy={redirecting}
          className="flex h-11 w-full cursor-pointer items-center justify-center gap-3 rounded-md border border-[#747775] bg-white px-4 text-sm font-medium text-[#1F1F1F] shadow-sm transition-colors hover:bg-[#F7F8F8] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 dark:border-[#8E918F] dark:bg-[#131314] dark:text-[#E3E3E3] dark:hover:bg-[#1F1F20]"
        >
          {redirecting ? <Spinner size="sm" /> : <GoogleMark />}
          {t("signInWithGoogle")}
        </a>
      )}

      {google && tokenLogin && (
        <button
          type="button"
          onClick={() => setTokenOpen((open) => !open)}
          aria-expanded={tokenOpen}
          aria-controls="token-signin"
          className="flex w-full cursor-pointer items-center gap-3 rounded-md text-xs font-medium text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          <span className="h-px flex-1 bg-border" />
          <span className="flex items-center gap-1.5">
            <KeyRound aria-hidden className="h-3.5 w-3.5" />
            {t("orUseToken")}
            <ChevronDown
              aria-hidden
              className={`h-3.5 w-3.5 transition-transform duration-200 ${tokenOpen ? "rotate-180" : ""}`}
            />
          </span>
          <span className="h-px flex-1 bg-border" />
        </button>
      )}

      {tokenLogin && tokenOpen && (
        <form
          id="token-signin"
          onSubmit={signInWithToken}
          className="space-y-4 animate-soft-fade-in"
          noValidate
        >
          <SecretField
            id="api-token"
            label={t("tokenLabel")}
            value={token}
            onChange={(value) => {
              setToken(value);
              if (tokenError) setTokenError("");
            }}
            placeholder={t("tokenPlaceholder")}
            help={t("tokenHelp")}
            error={tokenError}
            autoFocus={!google}
          />
          <Button
            type="submit"
            variant={google ? "outline" : "gradient"}
            className="h-11 w-full gap-2"
            disabled={loading || !token.trim()}
            aria-busy={loading}
          >
            {loading && <Spinner size="sm" />}
            {loading ? t("signingIn") : t("signInWithToken")}
          </Button>
        </form>
      )}
    </div>
  );
}
