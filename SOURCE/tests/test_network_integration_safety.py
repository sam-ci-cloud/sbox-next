import unittest
import test_audit_network as audit
class IntegrationSafety(unittest.TestCase):
 def test_dns_override_does_not_authorize_an_unassigned_listener(self):
  s={'mode':'ipv6','scope':'internal','ipv6':'fd00::1','listen':'fd00::1','endpoint_override':'Private DNS transition has been explicitly reviewed'}
  self.assertEqual(audit.AuditNetwork().assess(s,{'ipv6':['fd00::1']},[])['status'],'FAIL')
if __name__=='__main__':unittest.main(verbosity=2)
