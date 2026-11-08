"use client";

/**
 * fork(rbac): a labelled secret input (API token, access key) with show/hide,
 * helper text and an inline error announced to screen readers. Paste and
 * password managers work: nothing here blocks either.
 */

import { useState } from "react";
import { useTranslations } from "next-intl";
import { Eye, EyeOff } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

interface SecretFieldProps {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  help?: string;
  error?: string;
  autoFocus?: boolean;
}

export function SecretField({
  id,
  label,
  value,
  onChange,
  placeholder,
  help,
  error,
  autoFocus,
}: SecretFieldProps) {
  const t = useTranslations("login");
  const [revealed, setRevealed] = useState(false);
  const helpId = `${id}-help`;
  const errorId = `${id}-error`;
  const describedBy =
    [help ? helpId : null, error ? errorId : null].filter(Boolean).join(" ") || undefined;

  return (
    <div className="space-y-2">
      <Label htmlFor={id} className="text-sm font-medium">
        {label}
      </Label>
      <div className="relative">
        <Input
          id={id}
          name={id}
          type={revealed ? "text" : "password"}
          autoComplete="current-password"
          spellCheck={false}
          autoFocus={autoFocus}
          placeholder={placeholder}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          aria-invalid={error ? true : undefined}
          aria-describedby={describedBy}
          className="h-11 pr-11 font-mono text-sm aria-[invalid=true]:border-red-500 aria-[invalid=true]:focus-visible:ring-red-500"
        />
        <button
          type="button"
          onClick={() => setRevealed((r) => !r)}
          aria-label={revealed ? t("hideSecret") : t("showSecret")}
          aria-pressed={revealed}
          className="absolute inset-y-0 right-0 flex w-11 cursor-pointer items-center justify-center rounded-r-md text-muted-foreground transition-colors hover:text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
        >
          {revealed ? (
            <EyeOff aria-hidden className="h-4 w-4" />
          ) : (
            <Eye aria-hidden className="h-4 w-4" />
          )}
        </button>
      </div>
      {help && !error && (
        <p id={helpId} className="text-xs leading-relaxed text-muted-foreground">
          {help}
        </p>
      )}
      {error && (
        <p id={errorId} role="alert" className="text-sm text-red-600 dark:text-red-400">
          {error}
        </p>
      )}
    </div>
  );
}
