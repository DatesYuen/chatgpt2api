"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

import webConfig from "@/constants/common-env";
import { clearStoredAuthSession, getStoredAuthSession, type StoredAuthSession } from "@/store/auth";
import { cn } from "@/lib/utils";

const adminNavItems = [
  { href: "/image", label: "画图" },
  { href: "/accounts", label: "号池管理" },
  { href: "/settings", label: "设置" },
];

const userNavItems = [{ href: "/image", label: "画图" }];

export function TopNav() {
  const pathname = usePathname();
  const router = useRouter();
  const [session, setSession] = useState<StoredAuthSession | null | undefined>(undefined);

  useEffect(() => {
    let active = true;

    const load = async () => {
      if (pathname === "/login") {
        if (!active) {
          return;
        }
        setSession(null);
        return;
      }

      const storedSession = await getStoredAuthSession();
      if (!active) {
        return;
      }
      setSession(storedSession);
    };

    void load();
    return () => {
      active = false;
    };
  }, [pathname]);

  const handleLogout = async () => {
    await clearStoredAuthSession();
    router.replace("/login");
  };

  if (pathname === "/login" || session === undefined || !session) {
    return null;
  }

  const navItems = session.role === "admin" ? adminNavItems : userNavItems;
  const userLabel = session.username || session.name || (session.role === "admin" ? "管理员" : "用户");

  return (
    <header>
      <div className="flex h-12 items-start justify-between pt-1">
        <div className="flex flex-1 items-center gap-3">
          <Link
            href="/image"
            className="py-2 text-[15px] font-semibold tracking-tight text-stone-950 transition hover:text-stone-700"
          >
            George绘图
          </Link>
        </div>
        <div className="flex justify-center gap-8">
          {navItems.map((item) => {
            const active = pathname === item.href;
            return (
              <Link
                key={item.href}
                href={item.href}
                className={cn(
                  "relative py-2 text-[15px] font-medium transition",
                  active ? "font-semibold text-stone-950" : "text-stone-500 hover:text-stone-900",
                )}
              >
                {item.label}
                {active ? <span className="absolute inset-x-0 -bottom-[3px] h-0.5 bg-stone-950" /> : null}
              </Link>
            );
          })}
        </div>
        <div className="flex flex-1 items-center justify-end gap-3">
          <span className="rounded-md bg-stone-100 px-2 py-1 text-[11px] font-medium text-stone-500">{userLabel}</span>
          <span className="rounded-md bg-stone-100 px-2 py-1 text-[11px] font-medium text-stone-500">
            v{webConfig.appVersion}
          </span>
          <button
            type="button"
            className="py-2 text-sm text-stone-400 transition hover:text-stone-700"
            onClick={() => void handleLogout()}
          >
            退出
          </button>
        </div>
      </div>
    </header>
  );
}
