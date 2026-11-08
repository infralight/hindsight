"use client";

import { Suspense, useState, FormEvent, useEffect } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { useTranslations } from "next-intl";
import { Button } from "@/components/ui/button";
import { sanitizeReturnTo, withBasePath } from "@/lib/base-path";
import { LoginShell } from "@/components/login/login-shell";
import { RbacLogin } from "@/components/login/rbac-login";
import { SecretField } from "@/components/login/secret-field";
import { Spinner } from "@/components/ui/spinner";

// fork(rbac): which sign-in the server offers (per-user SSO/token, or the shared key).
interface AuthConfig {
  mode: "rbac" | "access_key" | "none";
  google?: boolean;
  tokenLogin?: boolean;
}

function LoginForm() {
  const t = useTranslations("login");
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();

  // Validate returnTo to prevent open-redirect via crafted login links.
  const returnTo = sanitizeReturnTo(searchParams.get("returnTo"));
  const [authConfig, setAuthConfig] = useState<AuthConfig | null>(null);

  useEffect(() => {
    fetch(withBasePath("/api/auth/config"))
      .then((res) => (res.ok ? res.json() : { mode: "access_key" }))
      .then(setAuthConfig)
      .catch(() => setAuthConfig({ mode: "access_key" }));
  }, []);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const res = await fetch(withBasePath("/api/auth/login"), {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key }),
      });

      if (res.ok) {
        // Navigate to the returnTo URL
        router.push(returnTo);
        router.refresh();
      } else {
        const data = await res.json().catch(() => null);
        setError(data?.error || t("invalidKey"));
      }
    } catch {
      setError(t("connectFailed"));
    } finally {
      setLoading(false);
    }
  }

  const isRbac = authConfig?.mode === "rbac";

  return (
    <LoginShell
      title={isRbac ? t("welcomeTitle") : t("title")}
      subtitle={
        !isRbac
          ? t("description")
          : authConfig?.google
            ? t("ssoDescription")
            : t("tokenDescription")
      }
    >
      {authConfig === null ? (
        // Same footprint as the form, so nothing jumps when the options arrive.
        <div aria-hidden className="h-[132px] animate-pulse rounded-lg bg-muted" />
      ) : isRbac ? (
        <RbacLogin
          google={!!authConfig.google}
          tokenLogin={!!authConfig.tokenLogin}
          returnTo={returnTo}
          error={searchParams.get("error")}
        />
      ) : (
        <form onSubmit={handleSubmit} className="space-y-4" noValidate>
          <SecretField
            id="access-key"
            label={t("accessKey")}
            value={key}
            onChange={(value) => {
              setKey(value);
              if (error) setError("");
            }}
            placeholder={t("accessKeyPlaceholder")}
            error={error}
            autoFocus
          />
          <Button
            type="submit"
            variant="gradient"
            className="h-11 w-full gap-2"
            disabled={loading || !key}
            aria-busy={loading}
          >
            {loading && <Spinner size="sm" />}
            {loading ? t("signingIn") : t("signIn")}
          </Button>
        </form>
      )}
    </LoginShell>
  );
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginForm />
    </Suspense>
  );
}
