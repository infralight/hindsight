"use client";

/**
 * fork(rbac): search people and teams by name or email and pick one — used to share a
 * bank and to add team members. Searches the dataplane directory as the user types.
 */

import { useEffect, useState } from "react";
import { useTranslations } from "next-intl";
import { Plus, User, Users, type LucideIcon } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Command,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
} from "@/components/ui/command";
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover";
import { rbac, type GranteeType } from "@/lib/rbac-api";

const SEARCH_DEBOUNCE_MS = 250;

export interface PickedGrantee {
  type: GranteeType;
  id: string;
  name: string;
}

interface Option extends PickedGrantee {
  detail: string | null;
}

interface DirectoryPickerProps {
  kinds: GranteeType[];
  /** Ids already granted or already members; never offered. */
  exclude: Set<string>;
  onPick: (picked: PickedGrantee) => void;
  placeholder: string;
  disabled?: boolean;
  icon?: LucideIcon;
}

export function DirectoryPicker({
  kinds,
  exclude,
  onPick,
  placeholder,
  disabled,
  icon: Icon = Plus,
}: DirectoryPickerProps) {
  const t = useTranslations("rbac.picker");
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [options, setOptions] = useState<Option[] | null>(null);
  const wantPeople = kinds.includes("principal");
  const wantTeams = kinds.includes("team");

  useEffect(() => {
    if (!open) return;
    let live = true; // a slower, older search must not overwrite a newer one
    const timer = setTimeout(async () => {
      try {
        const found = await rbac.directory(query);
        if (!live) return;
        setOptions([
          ...(wantPeople
            ? found.principals.map((p) => ({
                type: "principal" as const,
                id: p.id,
                name: p.name,
                detail: p.email,
              }))
            : []),
          ...(wantTeams
            ? found.teams.map((team) => ({ type: "team" as const, ...team, detail: null }))
            : []),
        ]);
      } catch {
        if (live) setOptions([]); // the client already showed the error
      }
    }, SEARCH_DEBOUNCE_MS);
    return () => {
      live = false;
      clearTimeout(timer);
    };
  }, [open, query, wantPeople, wantTeams]);

  const shown = options?.filter((o) => !exclude.has(o.id)) ?? null;

  const handleOpenChange = (next: boolean) => {
    setOpen(next);
    if (!next) {
      setQuery("");
      setOptions(null);
    }
  };

  return (
    <Popover open={open} onOpenChange={handleOpenChange}>
      <PopoverTrigger asChild>
        <Button variant="outline" size="sm" disabled={disabled} aria-label={placeholder}>
          <Icon className="mr-1.5 h-4 w-4" />
          {placeholder}
        </Button>
      </PopoverTrigger>
      <PopoverContent className="w-80 p-0" align="start">
        <Command shouldFilter={false}>
          <CommandInput placeholder={t("search")} value={query} onValueChange={setQuery} />
          <CommandList>
            {shown === null && (
              <p className="py-6 text-center text-sm text-muted-foreground">{t("searching")}</p>
            )}
            {shown?.length === 0 && (
              <p className="py-6 text-center text-sm text-muted-foreground">{t("noMatches")}</p>
            )}
            {shown && shown.length > 0 && (
              <CommandGroup>
                {shown.map((option) => (
                  <CommandItem
                    key={`${option.type}:${option.id}`}
                    value={`${option.type}:${option.id}`}
                    onSelect={() => {
                      onPick({ type: option.type, id: option.id, name: option.name });
                      handleOpenChange(false);
                    }}
                  >
                    {option.type === "team" ? (
                      <Users className="mr-2 h-4 w-4 text-muted-foreground" />
                    ) : (
                      <User className="mr-2 h-4 w-4 text-muted-foreground" />
                    )}
                    <span className="truncate">{option.name}</span>
                    {option.detail && (
                      <span className="ml-2 truncate text-xs text-muted-foreground">
                        {option.detail}
                      </span>
                    )}
                  </CommandItem>
                ))}
              </CommandGroup>
            )}
          </CommandList>
        </Command>
      </PopoverContent>
    </Popover>
  );
}
