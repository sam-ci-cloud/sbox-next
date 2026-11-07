"""Dependency-free JavaScript regression checks; CI provides Node.js."""
from pathlib import Path
import shutil
import subprocess
import unittest

NODE=shutil.which('node')

@unittest.skipUnless(NODE,'Node.js is required for frontend regression checks')
class FrontendLogic(unittest.TestCase):
 def test_chart_plan_and_delayed_responses(self):
  for name in ('test_rule_tester.cjs','test_usage_chart.cjs','test_plan_form.cjs','test_ui_async.cjs','test_adaptive_charts.cjs','test_portal_lifecycle.cjs','test_webui_guard_ui.cjs','test_portal_devices.cjs','test_admin_auth_lifecycle.cjs','test_dialog_focus.cjs'):
   with self.subTest(script=name):
    result=subprocess.run([NODE,str(Path(__file__).with_name(name))],capture_output=True,text=True,timeout=20)
    self.assertEqual(result.returncode,0,result.stdout+result.stderr)

if __name__=='__main__':unittest.main()
