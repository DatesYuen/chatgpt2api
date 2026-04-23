import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from fastapi.testclient import TestClient

from services import api as api_module
from services.auth_service import AuthService


class _FakeThread:
    def join(self, timeout: float | None = None) -> None:
        return None


class _FakeChatGPTService:
    last_call: dict[str, object] | None = None

    def __init__(self, _account_service, *_args) -> None:
        return None

    def edit_with_pool(
        self,
        prompt: str,
        images,
        model: str,
        n: int,
        response_format: str = "b64_json",
        base_url: str | None = None,
        identity: dict[str, object] | None = None,
    ):
        normalized_images = list(images)
        type(self).last_call = {
            "prompt": prompt,
            "images": normalized_images,
            "model": model,
            "n": n,
            "response_format": response_format,
            "base_url": base_url,
            "identity": identity,
        }
        return {
            "created": 123,
            "data": [{"b64_json": "ZmFrZQ==", "revised_prompt": prompt}],
        }

    def generate_with_pool(
        self,
        prompt: str,
        model: str,
        n: int,
        response_format: str = "b64_json",
        base_url: str = "",
        identity: dict[str, object] | None = None,
    ):
        return {
            "created": 123,
            "data": [{"b64_json": "ZmFrZQ==", "revised_prompt": prompt, "url": f"{base_url}/images/fake.png"}],
        }


class ImageEditsApiTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeChatGPTService.last_call = None
        self.auth_header = {"Authorization": "Bearer test-auth"}
        self.patches = [
            mock.patch.object(api_module, "ChatGPTService", _FakeChatGPTService),
            mock.patch.object(
                api_module,
                "config",
                SimpleNamespace(auth_key="test-auth", refresh_account_interval_minute=60),
            ),
            mock.patch.object(api_module, "start_limited_account_watcher", lambda _stop_event: _FakeThread()),
        ]
        for patcher in self.patches:
            patcher.start()
        self.addCleanup(self._cleanup_patches)
        self.client = TestClient(api_module.create_app())
        self.addCleanup(self.client.close)

    def _cleanup_patches(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()

    def test_accepts_repeated_image_field(self) -> None:
        response = self.client.post(
            "/v1/images/edits",
            headers=self.auth_header,
            data={"prompt": "test prompt", "model": "gpt-image-1", "n": "1"},
            files=[
                ("image", ("first.png", b"first", "image/png")),
                ("image", ("second.png", b"second", "image/png")),
            ],
        )

        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(_FakeChatGPTService.last_call)
        self.assertEqual(len(_FakeChatGPTService.last_call["images"]), 2)
        self.assertEqual(
            [item[1] for item in _FakeChatGPTService.last_call["images"]],
            ["first.png", "second.png"],
        )


class _FakeConfig:
    def __init__(self, tmp_dir: str):
        self.auth_key = "admin-secret"
        self.refresh_account_interval_minute = 60
        self.base_url = ""
        self.images_dir = Path(tmp_dir) / "images"
        self.images_dir.mkdir(parents=True, exist_ok=True)
        self._data = {
            "proxy": "",
            "base_url": "",
            "refresh_account_interval_minute": 60,
        }

    def get(self) -> dict[str, object]:
        return dict(self._data)

    def update(self, data: dict[str, object]) -> dict[str, object]:
        self._data.update(dict(data or {}))
        return self.get()

    def get_proxy_settings(self) -> str:
        return str(self._data.get("proxy") or "")


class ApiAuthRoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp_dir.cleanup)

        self.auth_service = AuthService(Path(self.tmp_dir.name) / "auth_keys.json")
        self.user_item, self.user_key = self.auth_service.create_key(role="user", name="设计同学")
        self.fake_config = _FakeConfig(self.tmp_dir.name)

        self.patches = [
            mock.patch.object(api_module, "auth_service", self.auth_service),
            mock.patch.object(api_module, "config", self.fake_config),
            mock.patch.object(api_module, "ChatGPTService", _FakeChatGPTService),
            mock.patch.object(api_module, "start_limited_account_watcher", lambda _stop_event: _FakeThread()),
        ]
        for patcher in self.patches:
            patcher.start()
        self.addCleanup(self._cleanup_patches)

        self.client = TestClient(api_module.create_app())
        self.addCleanup(self.client.close)

    def _cleanup_patches(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()

    @staticmethod
    def _auth_header(key: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {key}"}

    def test_login_returns_admin_and_user_role(self) -> None:
        admin_response = self.client.post("/auth/login", headers=self._auth_header("admin-secret"))
        user_response = self.client.post("/auth/login", headers=self._auth_header(self.user_key))

        self.assertEqual(admin_response.status_code, 200)
        self.assertEqual(admin_response.json()["role"], "admin")
        self.assertTrue(admin_response.json()["token"].startswith("cg2a_session."))
        self.assertEqual(user_response.status_code, 200)
        self.assertEqual(user_response.json()["role"], "user")
        self.assertEqual(user_response.json()["name"], "设计同学")
        self.assertEqual(user_response.json()["username"], self.user_item["username"])

    def test_user_is_forbidden_from_admin_endpoints(self) -> None:
        settings_response = self.client.get("/api/settings", headers=self._auth_header(self.user_key))
        user_keys_response = self.client.get("/api/auth/users", headers=self._auth_header(self.user_key))

        self.assertEqual(settings_response.status_code, 403)
        self.assertEqual(user_keys_response.status_code, 403)

    def test_user_can_generate_images_and_admin_can_manage_user_keys(self) -> None:
        image_response = self.client.post(
            "/v1/images/generations",
            headers=self._auth_header(self.user_key),
            json={"prompt": "test prompt", "model": "gpt-image-1", "n": 1},
        )
        create_user_response = self.client.post(
            "/api/auth/users",
            headers=self._auth_header("admin-secret"),
            json={"username": "ops-user", "display_name": "运营同学", "role": "user", "daily_image_limit": 20},
        )

        self.assertEqual(image_response.status_code, 200)
        self.assertEqual(image_response.json()["data"][0]["revised_prompt"], "test prompt")
        self.assertEqual(create_user_response.status_code, 200)
        payload = create_user_response.json()
        self.assertEqual(payload["item"]["role"], "user")
        self.assertEqual(payload["item"]["name"], "运营同学")
        self.assertEqual(payload["item"]["username"], "ops-user")

    def test_accepts_repeated_image_bracket_field(self) -> None:
        response = self.client.post(
            "/v1/images/edits",
            headers=self._auth_header("admin-secret"),
            data={"prompt": "test prompt", "model": "gpt-image-1", "n": "1"},
            files=[
                ("image[]", ("first.png", b"first", "image/png")),
                ("image[]", ("second.png", b"second", "image/png")),
            ],
        )

        self.assertEqual(response.status_code, 200)
        self.assertIsNotNone(_FakeChatGPTService.last_call)
        self.assertEqual(len(_FakeChatGPTService.last_call["images"]), 2)
        self.assertEqual(
            [item[1] for item in _FakeChatGPTService.last_call["images"]],
            ["first.png", "second.png"],
        )

    def test_settings_save_returns_readable_error_when_config_is_not_writable(self) -> None:
        with mock.patch.object(self.fake_config, "update", side_effect=PermissionError("config is read-only")):
            response = self.client.post(
                "/api/settings",
                headers=self._auth_header("admin-secret"),
                json={"proxy": "", "base_url": ""},
            )

        self.assertEqual(response.status_code, 500)
        self.assertIn("save settings failed", response.json()["detail"]["error"])


if __name__ == "__main__":
    unittest.main()
