import os
import types
import unittest
from unittest.mock import patch

import doh_http_proxy


class PortDetectionTests(unittest.TestCase):
    def test_parse_listening_rows_ignores_non_listening_entries(self) -> None:
        stdout = "\n".join(
            [
                "TCP    0.0.0.0:8080    0.0.0.0:0    LISTENING    22100",
                "TCP    0.0.0.0:8080    0.0.0.0:0    TIME_WAIT     0",
                "TCP    127.0.0.1:8080  127.0.0.1:0  ESTABLISHED   0",
            ]
        )

        fake_completed = types.SimpleNamespace(stdout=stdout)

        with patch("doh_http_proxy.subprocess.run", return_value=fake_completed):
            self.assertEqual(
                doh_http_proxy.parse_listening_rows(),
                [("0.0.0.0:8080", 22100)],
            )

    def test_listening_pids_for_target_ignores_zero_pid_rows(self) -> None:
        with patch(
            "doh_http_proxy.parse_listening_rows",
            return_value=[("0.0.0.0:8080", 22100), ("0.0.0.0:8080", 0)],
        ):
            pids, details = doh_http_proxy.listening_pids_for_target("0.0.0.0", 8080)

        self.assertEqual(pids, [22100])
        self.assertEqual(details, ["0.0.0.0:8080 -> PID 22100"])


class StartupConfigTests(unittest.TestCase):
    def test_build_startup_config_uses_persisted_values_and_overrides(self) -> None:
        persisted = doh_http_proxy.StartupConfig(
            listen="127.0.0.1",
            port=9999,
            set_system_proxy=False,
            doh_file="saved-doh.txt",
            use_doh_proxy=False,
            output="saved.txt",
        )
        args = types.SimpleNamespace(use_doh_proxy=True)

        with patch(
            "doh_http_proxy.load_saved_startup_config",
            return_value=persisted,
        ):
            config = doh_http_proxy.build_startup_config_from_namespace(args)

        self.assertEqual(config.listen, "127.0.0.1")
        self.assertEqual(config.port, 9999)
        self.assertFalse(config.set_system_proxy)
        self.assertEqual(config.doh_file, "saved-doh.txt")
        self.assertTrue(config.use_doh_proxy)
        self.assertEqual(config.output, "saved.txt")

    def test_save_persistent_startup_config_round_trips(self) -> None:
        config_path = os.path.join(os.getcwd(), "_startup_config_test.json")
        config = doh_http_proxy.StartupConfig(
            listen="127.0.0.1",
            port=9000,
            use_doh_proxy=False,
            verbose=True,
        )

        try:
            if os.path.exists(config_path):
                os.unlink(config_path)

            with patch(
                "doh_http_proxy.get_startup_config_path",
                return_value=config_path,
            ):
                doh_http_proxy.save_persistent_startup_config(config)
                loaded = doh_http_proxy.load_startup_config(config_path, delete=False)
        finally:
            if os.path.exists(config_path):
                os.unlink(config_path)

        self.assertEqual(loaded, config)


if __name__ == "__main__":
    unittest.main()
