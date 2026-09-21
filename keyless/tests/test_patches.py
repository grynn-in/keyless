from __future__ import annotations

import unittest

from frappe.modules.patch_handler import PatchType, get_patches_from_app

USER_HANDLE_PATCH = "keyless.patches.v1_0.create_user_handle_custom_field"


class TestPatchesFile(unittest.TestCase):
    def test_patches_file_parses_for_install(self):
        self.assertIsInstance(get_patches_from_app("keyless"), list)

    def test_patches_file_parses_for_each_migrate_phase(self):
        for patch_type in (PatchType.pre_model_sync, PatchType.post_model_sync):
            with self.subTest(patch_type=patch_type):
                self.assertIsInstance(get_patches_from_app("keyless", patch_type), list)

    def test_user_handle_patch_runs_post_model_sync(self):
        self.assertIn(USER_HANDLE_PATCH, get_patches_from_app("keyless", PatchType.post_model_sync))
