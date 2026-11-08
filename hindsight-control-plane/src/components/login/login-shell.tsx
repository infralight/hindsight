"use client";

/**
 * fork(rbac): the frame around every sign-in form — a brand panel on wide screens
 * (what Hindsight is, and why sign-in exists), the form on the right.
 */

import type { ReactNode } from "react";
import Image from "next/image";
import { useTranslations } from "next-intl";
import { LockKeyhole, Moon, ScrollText, Sun, UsersRound } from "lucide-react";
import { LanguageSwitcher } from "@/components/language-switcher";
import { Button } from "@/components/ui/button";
import { withBasePath } from "@/lib/base-path";
import { useTheme } from "@/lib/theme-context";

interface LoginShellProps {
  title: string;
  subtitle: string;
  children: ReactNode;
}

export function LoginShell({ title, subtitle, children }: LoginShellProps) {
  const t = useTranslations("login");
  const tNav = useTranslations("nav");
  const { theme, toggleTheme } = useTheme();
  const themeLabel = theme === "light" ? tNav("darkMode") : tNav("lightMode");
  const points = [
    { icon: LockKeyhole, text: t("brandPointPrivacy") },
    { icon: UsersRound, text: t("brandPointSharing") },
    { icon: ScrollText, text: t("brandPointAudit") },
  ];

  return (
    <div className="grid min-h-dvh bg-background lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
      <aside className="relative hidden overflow-hidden bg-primary-gradient text-fg-on-accent lg:flex lg:flex-col lg:justify-between lg:p-12">
        {/* Darkens the teal end so small white text keeps 4.5:1; deeper in dark mode so
            the panel does not glare next to the dark form side. */}
        <div aria-hidden className="absolute inset-0 bg-black/20 dark:bg-black/45" />
        <div
          aria-hidden
          className="absolute inset-0 opacity-[0.14] [background-image:linear-gradient(to_right,white_1px,transparent_1px),linear-gradient(to_bottom,white_1px,transparent_1px)] [background-size:40px_40px] [mask-image:radial-gradient(ellipse_at_top_left,black_20%,transparent_70%)]"
        />
        <div
          aria-hidden
          className="absolute -bottom-40 -right-32 h-[28rem] w-[28rem] rounded-full bg-white/10 blur-3xl"
        />

        <div className="relative flex items-center gap-3">
          <Image
            src={withBasePath("/favicon.png")}
            alt=""
            width={40}
            height={40}
            className="rounded-lg bg-white/95 p-1 shadow-sm"
            unoptimized
          />
          <span className="text-xl font-semibold tracking-tight">Hindsight</span>
        </div>

        <div className="relative max-w-md space-y-8">
          <h2 className="text-4xl font-semibold leading-tight tracking-tight [text-wrap:balance]">
            {t("brandTitle")}
          </h2>
          <ul className="space-y-4">
            {points.map(({ icon: Icon, text }) => (
              <li key={text} className="flex items-start gap-3 text-base leading-relaxed">
                <span className="mt-0.5 flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-white/15 ring-1 ring-white/25">
                  <Icon aria-hidden className="h-4 w-4" />
                </span>
                <span className="pt-1">{text}</span>
              </li>
            ))}
          </ul>
        </div>

        <p className="relative text-sm text-white/80">{t("brandFooter")}</p>
      </aside>

      <main className="relative flex items-center justify-center px-4 py-16 sm:px-10">
        <div className="absolute right-4 top-4 flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            onClick={toggleTheme}
            title={themeLabel}
            aria-label={themeLabel}
          >
            {theme === "light" ? <Moon className="h-4 w-4" /> : <Sun className="h-4 w-4" />}
          </Button>
          <LanguageSwitcher />
        </div>
        <div className="w-full max-w-sm animate-soft-fade-in">
          <Image
            src={withBasePath("/logo.png")}
            alt="Hindsight"
            width={132}
            height={132}
            className="mb-8 lg:hidden"
            unoptimized
          />
          <h1 className="text-2xl font-semibold tracking-tight text-foreground">{title}</h1>
          <p className="mt-2 text-sm leading-relaxed text-muted-foreground">{subtitle}</p>
          <div className="mt-8">{children}</div>
        </div>
      </main>
    </div>
  );
}
