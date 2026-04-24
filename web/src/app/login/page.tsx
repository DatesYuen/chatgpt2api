"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { LoaderCircle, LockKeyhole, UserRound } from "lucide-react";
import { toast } from "sonner";

import webConfig from "@/constants/common-env";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { exchangeAuthentikTicket, fetchAuthentikStatus, login, loginWithPassword, type LoginResponse } from "@/lib/api";
import { useRedirectIfAuthenticated } from "@/lib/use-auth-guard";
import { getDefaultRouteForRole, setStoredAuthSession } from "@/store/auth";

type LoginMode = "password" | "key";

function getAuthentikStartUrl() {
  const apiBase = webConfig.apiUrl.replace(/\/$/, "");
  const redirectTo = typeof window === "undefined" ? "/login/" : `${window.location.origin}/login/`;
  return `${apiBase}/auth/authentik/start?redirect_to=${encodeURIComponent(redirectTo)}`;
}

function LoginPageContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [mode, setMode] = useState<LoginMode>("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authKey, setAuthKey] = useState("");
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isAuthentikExchanging, setIsAuthentikExchanging] = useState(false);
  const [isGeorgeLoginEnabled, setIsGeorgeLoginEnabled] = useState(false);
  const { isCheckingAuth } = useRedirectIfAuthenticated();

  const authentikTicket = useMemo(() => searchParams.get("authentik_ticket") || "", [searchParams]);
  const authentikError = useMemo(() => searchParams.get("auth_error") || "", [searchParams]);

  const persistSession = async (data: LoginResponse, fallbackToken = "") => {
    const token = String(data.token || fallbackToken || "").trim();
    if (!token) {
      throw new Error("登录响应缺少 token");
    }
    await setStoredAuthSession({
      key: token,
      role: data.role,
      subjectId: data.subject_id,
      username: data.username,
      name: data.name,
      quotaLimit: data.quota_limit ?? null,
      quotaRemaining: data.quota_remaining ?? null,
      quotaUsed: data.quota_used ?? null,
      quotaResetAt: data.quota_reset_at ?? null,
    });
    router.replace(getDefaultRouteForRole(data.role));
  };

  useEffect(() => {
    let active = true;
    void fetchAuthentikStatus()
      .then((data) => {
        if (!active) {
          return;
        }
        setIsGeorgeLoginEnabled(Boolean(data.enabled));
      })
      .catch(() => {
        if (!active) {
          return;
        }
        setIsGeorgeLoginEnabled(false);
      });
    return () => {
      active = false;
    };
  }, []);

  useEffect(() => {
    if (authentikError) {
      toast.error(decodeURIComponent(authentikError));
      router.replace("/login/");
      return;
    }
    if (!authentikTicket) {
      return;
    }

    let active = true;
    setIsAuthentikExchanging(true);
    void exchangeAuthentikTicket(authentikTicket)
      .then(async (data) => {
        if (!active) {
          return;
        }
        await persistSession(data);
      })
      .catch((error) => {
        if (!active) {
          return;
        }
        toast.error(error instanceof Error ? error.message : "Authentik 登录失败");
        router.replace("/login/");
      })
      .finally(() => {
        if (active) {
          setIsAuthentikExchanging(false);
        }
      });

    return () => {
      active = false;
    };
  }, [authentikError, authentikTicket, router]);

  const handlePasswordLogin = async () => {
    if (!username.trim() || !password.trim()) {
      toast.error("请输入用户名和密码");
      return;
    }
    setIsSubmitting(true);
    try {
      const data = await loginWithPassword(username.trim(), password);
      await persistSession(data);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "登录失败");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleKeyLogin = async () => {
    const normalizedAuthKey = authKey.trim();
    if (!normalizedAuthKey) {
      toast.error("请输入密钥");
      return;
    }

    setIsSubmitting(true);
    try {
      const data = await login(normalizedAuthKey);
      await persistSession(data);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "登录失败");
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isCheckingAuth || isAuthentikExchanging) {
    return (
      <div className="grid min-h-[calc(100vh-1rem)] w-full place-items-center px-4 py-6">
        <LoaderCircle className="size-5 animate-spin text-stone-400" />
      </div>
    );
  }

  return (
    <div className="grid min-h-[calc(100vh-1rem)] w-full place-items-center px-4 py-6">
      <Card className="w-full max-w-[540px] rounded-[30px] border-white/80 bg-white/95 shadow-[0_28px_90px_rgba(28,25,23,0.10)]">
        <CardContent className="space-y-7 p-6 sm:p-8">
          <div className="space-y-4 text-center">
            <div className="mx-auto inline-flex size-14 items-center justify-center rounded-[18px] bg-stone-950 text-white shadow-sm">
              <LockKeyhole className="size-5" />
            </div>
            <div className="space-y-2">
              <h1 className="text-3xl font-semibold tracking-tight text-stone-950">欢迎回来</h1>
              <p className="text-sm leading-6 text-stone-500">支持本地用户名密码、兼容密钥登录，也可通过 George 单点登录。</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-2 rounded-2xl bg-stone-100 p-1">
            <button
              type="button"
              className={`h-11 rounded-2xl text-sm font-medium transition ${
                mode === "password" ? "bg-white text-stone-950 shadow-sm" : "text-stone-500 hover:text-stone-900"
              }`}
              onClick={() => setMode("password")}
            >
              用户名登录
            </button>
            <button
              type="button"
              className={`h-11 rounded-2xl text-sm font-medium transition ${
                mode === "key" ? "bg-white text-stone-950 shadow-sm" : "text-stone-500 hover:text-stone-900"
              }`}
              onClick={() => setMode("key")}
            >
              密钥登录
            </button>
          </div>

          {mode === "password" ? (
            <div className="space-y-3">
              <label htmlFor="username" className="block text-sm font-medium text-stone-700">
                用户名
              </label>
              <Input
                id="username"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="请输入用户名"
                className="h-13 rounded-2xl border-stone-200 bg-white px-4"
              />
              <label htmlFor="password" className="block text-sm font-medium text-stone-700">
                密码
              </label>
              <Input
                id="password"
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    void handlePasswordLogin();
                  }
                }}
                placeholder="请输入密码"
                className="h-13 rounded-2xl border-stone-200 bg-white px-4"
              />
              <Button
                className="h-13 w-full rounded-2xl bg-stone-950 text-white hover:bg-stone-800"
                onClick={() => void handlePasswordLogin()}
                disabled={isSubmitting}
              >
                {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : <UserRound className="size-4" />}
                登录
              </Button>
            </div>
          ) : (
            <div className="space-y-3">
              <label htmlFor="auth-key" className="block text-sm font-medium text-stone-700">
                密钥
              </label>
              <Input
                id="auth-key"
                type="password"
                value={authKey}
                onChange={(event) => setAuthKey(event.target.value)}
                onKeyDown={(event) => {
                  if (event.key === "Enter") {
                    void handleKeyLogin();
                  }
                }}
                placeholder="请输入密钥"
                className="h-13 rounded-2xl border-stone-200 bg-white px-4"
              />
              <Button
                className="h-13 w-full rounded-2xl bg-stone-950 text-white hover:bg-stone-800"
                onClick={() => void handleKeyLogin()}
                disabled={isSubmitting}
              >
                {isSubmitting ? <LoaderCircle className="size-4 animate-spin" /> : null}
                登录
              </Button>
            </div>
          )}

          {isGeorgeLoginEnabled ? (
            <div className="space-y-3">
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t border-stone-200" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-white px-3 text-stone-400">或者</span>
                </div>
              </div>
              <Button
                type="button"
                variant="outline"
                className="h-13 w-full rounded-2xl border-stone-200 bg-white text-stone-800"
                onClick={() => {
                  window.location.href = getAuthentikStartUrl();
                }}
              >
                使用George登录
              </Button>
            </div>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="grid min-h-[calc(100vh-1rem)] w-full place-items-center px-4 py-6">
          <LoaderCircle className="size-5 animate-spin text-stone-400" />
        </div>
      }
    >
      <LoginPageContent />
    </Suspense>
  );
}
