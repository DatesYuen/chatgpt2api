"use client";

import { useEffect, useRef, useState } from "react";
import { Ban, CheckCircle2, Copy, KeyRound, LoaderCircle, Pencil, Plus, Shield, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  createUser,
  deleteUser,
  fetchUsers,
  resetUserApiKey,
  updateUser,
  type AuthRole,
  type LocalUser,
} from "@/lib/api";

type UserFormState = {
  username: string;
  displayName: string;
  role: AuthRole;
  password: string;
  enabled: boolean;
  dailyLimit: string;
  authentikUsername: string;
};

const DEFAULT_FORM: UserFormState = {
  username: "",
  displayName: "",
  role: "user",
  password: "",
  enabled: true,
  dailyLimit: "20",
  authentikUsername: "",
};

function formatDateTime(value?: string | null) {
  if (!value) {
    return "—";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return new Intl.DateTimeFormat("zh-CN", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(date);
}

export function UserKeysCard() {
  const didLoadRef = useRef(false);
  const [items, setItems] = useState<LocalUser[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isDialogOpen, setIsDialogOpen] = useState(false);
  const [editingUser, setEditingUser] = useState<LocalUser | null>(null);
  const [form, setForm] = useState<UserFormState>(DEFAULT_FORM);
  const [isSaving, setIsSaving] = useState(false);
  const [pendingId, setPendingId] = useState<string | null>(null);
  const [revealedKey, setRevealedKey] = useState("");

  const load = async () => {
    setIsLoading(true);
    try {
      const data = await fetchUsers();
      setItems(data.items);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "加载用户失败");
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (didLoadRef.current) {
      return;
    }
    didLoadRef.current = true;
    void load();
  }, []);

  const openCreateDialog = () => {
    setEditingUser(null);
    setForm(DEFAULT_FORM);
    setIsDialogOpen(true);
  };

  const openEditDialog = (item: LocalUser) => {
    setEditingUser(item);
    setForm({
      username: item.username || "",
      displayName: item.name || "",
      role: item.role,
      password: "",
      enabled: item.enabled,
      dailyLimit: String(item.daily_image_limit ?? 20),
      authentikUsername: item.authentik_username || "",
    });
    setIsDialogOpen(true);
  };

  const updateForm = (field: keyof UserFormState, value: string | boolean) => {
    setForm((current) => ({ ...current, [field]: value }));
  };

  const handleSave = async () => {
    if (!form.username.trim()) {
      toast.error("请输入用户名");
      return;
    }

    setIsSaving(true);
    try {
      const dailyLimit = Math.max(0, Number(form.dailyLimit) || 0);
      if (editingUser) {
        const data = await updateUser(editingUser.id, {
          username: form.username.trim(),
          display_name: form.displayName.trim(),
          role: form.role,
          password: form.password,
          enabled: form.enabled,
          daily_image_limit: dailyLimit,
          authentik_username: form.authentikUsername.trim(),
        });
        setItems(data.items);
        toast.success("用户已更新");
      } else {
        const data = await createUser({
          username: form.username.trim(),
          display_name: form.displayName.trim(),
          role: form.role,
          password: form.password,
          enabled: form.enabled,
          daily_image_limit: dailyLimit,
          authentik_username: form.authentikUsername.trim(),
        });
        setItems(data.items);
        toast.success("用户已创建");
      }
      setIsDialogOpen(false);
      setForm(DEFAULT_FORM);
      setEditingUser(null);
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "保存用户失败");
    } finally {
      setIsSaving(false);
    }
  };

  const handleToggle = async (item: LocalUser) => {
    setPendingId(item.id);
    try {
      const data = await updateUser(item.id, { enabled: !item.enabled });
      setItems(data.items);
      toast.success(item.enabled ? "用户已禁用" : "用户已启用");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "更新用户失败");
    } finally {
      setPendingId(null);
    }
  };

  const handleDelete = async (item: LocalUser) => {
    if (!window.confirm(`确认删除用户「${item.username}」吗？`)) {
      return;
    }
    setPendingId(item.id);
    try {
      const data = await deleteUser(item.id);
      setItems(data.items);
      toast.success("用户已删除");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "删除用户失败");
    } finally {
      setPendingId(null);
    }
  };

  const handleResetApiKey = async (item: LocalUser) => {
    setPendingId(item.id);
    try {
      const data = await resetUserApiKey(item.id);
      setItems(data.items);
      setRevealedKey(data.key);
      toast.success(item.has_api_key ? "API Key 已重置" : "API Key 已生成");
    } catch (error) {
      toast.error(error instanceof Error ? error.message : "生成 API Key 失败");
    } finally {
      setPendingId(null);
    }
  };

  const handleCopy = async (value: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success("已复制到剪贴板");
    } catch {
      toast.error("复制失败，请手动复制");
    }
  };

  return (
    <>
      <Card className="rounded-2xl border-white/80 bg-white/90 shadow-sm">
        <CardContent className="space-y-6 p-6">
          <div className="flex items-start justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className="flex size-10 items-center justify-center rounded-xl bg-stone-100">
                <KeyRound className="size-5 text-stone-600" />
              </div>
              <div>
                <h2 className="text-lg font-semibold tracking-tight">用户管理</h2>
                <p className="text-sm text-stone-500">维护本地用户名、密码、API Key、Authentik 绑定和普通用户每日额度。</p>
              </div>
            </div>
            <Button className="h-9 rounded-xl bg-stone-950 px-4 text-white hover:bg-stone-800" onClick={openCreateDialog}>
              <Plus className="size-4" />
              创建用户
            </Button>
          </div>

          {revealedKey ? (
            <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-4 text-sm text-emerald-900">
              <div className="font-medium">API Key 仅展示一次，请立即保存：</div>
              <div className="mt-3 flex flex-col gap-3 rounded-lg border border-emerald-200 bg-white/80 p-3 md:flex-row md:items-center md:justify-between">
                <code className="break-all font-mono text-[13px]">{revealedKey}</code>
                <Button
                  type="button"
                  variant="outline"
                  className="h-9 rounded-xl border-emerald-200 bg-white px-4 text-emerald-700"
                  onClick={() => void handleCopy(revealedKey)}
                >
                  <Copy className="size-4" />
                  复制
                </Button>
              </div>
            </div>
          ) : null}

          {isLoading ? (
            <div className="flex items-center justify-center py-10">
              <LoaderCircle className="size-5 animate-spin text-stone-400" />
            </div>
          ) : items.length === 0 ? (
            <div className="rounded-xl bg-stone-50 px-6 py-10 text-center text-sm text-stone-500">
              暂无本地用户。点击右上角即可创建用户名密码账号；Authentik 首次登录也会自动建号。
            </div>
          ) : (
            <div className="space-y-3">
              {items.map((item) => {
                const isPending = pendingId === item.id;
                return (
                  <div key={item.id} className="flex flex-col gap-3 rounded-xl border border-stone-200 bg-white px-4 py-4">
                    <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                      <div className="min-w-0 space-y-2">
                        <div className="flex flex-wrap items-center gap-2">
                          <div className="truncate text-sm font-semibold text-stone-900">{item.username}</div>
                          <Badge variant={item.role === "admin" ? "success" : "secondary"} className="rounded-md">
                            {item.role === "admin" ? "管理员" : "普通用户"}
                          </Badge>
                          <Badge variant={item.enabled ? "success" : "secondary"} className="rounded-md">
                            {item.enabled ? "已启用" : "已禁用"}
                          </Badge>
                        </div>
                        <div className="text-sm text-stone-600">{item.name || "—"}</div>
                        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-stone-500">
                          <span>密码 {item.has_password ? "已设置" : "未设置"}</span>
                          <span>API Key {item.has_api_key ? "已生成" : "未生成"}</span>
                          <span>每日额度 {item.daily_image_limit}</span>
                          <span>今日剩余 {item.role === "user" ? item.quota_remaining ?? item.daily_image_limit : "不限"}</span>
                          <span>Authentik {item.authentik_username || "未绑定"}</span>
                        </div>
                        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-stone-500">
                          <span>创建时间 {formatDateTime(item.created_at)}</span>
                          <span>最近使用 {formatDateTime(item.last_used_at)}</span>
                        </div>
                      </div>

                      <div className="flex flex-wrap items-center gap-2">
                        <Button
                          type="button"
                          variant="outline"
                          className="h-9 rounded-xl border-stone-200 bg-white px-4 text-stone-700"
                          onClick={() => openEditDialog(item)}
                          disabled={isPending}
                        >
                          <Pencil className="size-4" />
                          编辑
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          className="h-9 rounded-xl border-stone-200 bg-white px-4 text-stone-700"
                          onClick={() => void handleResetApiKey(item)}
                          disabled={isPending}
                        >
                          {isPending ? <LoaderCircle className="size-4 animate-spin" /> : <Shield className="size-4" />}
                          {item.has_api_key ? "重置 API Key" : "生成 API Key"}
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          className="h-9 rounded-xl border-stone-200 bg-white px-4 text-stone-700"
                          onClick={() => void handleToggle(item)}
                          disabled={isPending}
                        >
                          {isPending ? (
                            <LoaderCircle className="size-4 animate-spin" />
                          ) : item.enabled ? (
                            <Ban className="size-4" />
                          ) : (
                            <CheckCircle2 className="size-4" />
                          )}
                          {item.enabled ? "禁用" : "启用"}
                        </Button>
                        <Button
                          type="button"
                          variant="outline"
                          className="h-9 rounded-xl border-rose-200 bg-white px-4 text-rose-600 hover:bg-rose-50 hover:text-rose-700"
                          onClick={() => void handleDelete(item)}
                          disabled={isPending}
                        >
                          <Trash2 className="size-4" />
                          删除
                        </Button>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </CardContent>
      </Card>

      <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
        <DialogContent className="rounded-2xl p-6">
          <DialogHeader className="gap-2">
            <DialogTitle>{editingUser ? `编辑用户 ${editingUser.username}` : "创建用户"}</DialogTitle>
            <DialogDescription className="text-sm leading-6">
              用户名是登录主标识；密码可留空，留给 Authentik 自动建号或后续补设。
            </DialogDescription>
          </DialogHeader>
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-700">用户名</label>
              <Input
                value={form.username}
                onChange={(event) => updateForm("username", event.target.value)}
                placeholder="alice"
                className="h-11 rounded-xl border-stone-200 bg-white"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-700">显示名</label>
              <Input
                value={form.displayName}
                onChange={(event) => updateForm("displayName", event.target.value)}
                placeholder="Alice"
                className="h-11 rounded-xl border-stone-200 bg-white"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-700">角色</label>
              <Select value={form.role} onValueChange={(value) => updateForm("role", value as AuthRole)}>
                <SelectTrigger className="h-11 rounded-xl border-stone-200 bg-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="user">普通用户</SelectItem>
                  <SelectItem value="admin">管理员</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-700">每日额度</label>
              <Input
                type="number"
                min="0"
                value={form.dailyLimit}
                onChange={(event) => updateForm("dailyLimit", event.target.value)}
                className="h-11 rounded-xl border-stone-200 bg-white"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-700">
                {editingUser ? "新密码（留空则不修改）" : "密码"}
              </label>
              <Input
                type="password"
                value={form.password}
                onChange={(event) => updateForm("password", event.target.value)}
                placeholder={editingUser ? "留空不修改" : "可留空"}
                className="h-11 rounded-xl border-stone-200 bg-white"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-700">Authentik 用户名绑定</label>
              <Input
                value={form.authentikUsername}
                onChange={(event) => updateForm("authentikUsername", event.target.value)}
                placeholder="preferred_username"
                className="h-11 rounded-xl border-stone-200 bg-white"
              />
            </div>
            <div className="space-y-2">
              <label className="text-sm font-medium text-stone-700">状态</label>
              <Select value={form.enabled ? "enabled" : "disabled"} onValueChange={(value) => updateForm("enabled", value === "enabled")}>
                <SelectTrigger className="h-11 rounded-xl border-stone-200 bg-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="enabled">启用</SelectItem>
                  <SelectItem value="disabled">禁用</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <DialogFooter>
            <Button
              type="button"
              variant="secondary"
              className="h-10 rounded-xl bg-stone-100 px-5 text-stone-700 hover:bg-stone-200"
              onClick={() => setIsDialogOpen(false)}
              disabled={isSaving}
            >
              取消
            </Button>
            <Button
              type="button"
              className="h-10 rounded-xl bg-stone-950 px-5 text-white hover:bg-stone-800"
              onClick={() => void handleSave()}
              disabled={isSaving}
            >
              {isSaving ? <LoaderCircle className="size-4 animate-spin" /> : <Plus className="size-4" />}
              保存
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
