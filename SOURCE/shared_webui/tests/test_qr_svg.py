"""Fail-first regression: encoder-supplied crispEdges must remain valid SVG."""
import sys,unittest,xml.etree.ElementTree as ET
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_panel_v2 import Panel
class QRGeometry(Panel):
 def test_existing_shape_attribute_is_not_duplicated(self):
  self.app.qrencode=[sys.executable,'-c','print(\'<svg xmlns="http://www.w3.org/2000/svg" shape-rendering="crispEdges" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>\')']
  code,headers,result=self.req('/api/v1/qr',{'text':'https://example.test/synthetic-public-fixture'},self.admin())
  self.assertEqual(code,200,result);root=ET.fromstring(result['svg']);self.assertEqual(root.attrib['shape-rendering'],'crispEdges');self.assertEqual(result['svg'].count('shape-rendering='),1)
 def test_missing_shape_attribute_is_added(self):
  self.app.qrencode=[sys.executable,'-c','print(\'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 10 10"><rect width="10" height="10"/></svg>\')']
  code,_,result=self.req('/api/v1/qr',{'text':'https://example.test/synthetic-public-fixture'},self.admin());self.assertEqual(code,200,result);self.assertEqual(ET.fromstring(result['svg']).attrib['shape-rendering'],'crispEdges')
if __name__=='__main__':unittest.main()
