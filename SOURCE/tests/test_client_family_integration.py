"""Client endpoint transport and destination address families are independent."""
import unittest,yaml
import reality_fixture as fx
class FamilyIntegration(unittest.TestCase):
 def test_ipv6_node_ipv4_destinations_keep_transport_enabled(self):
  s=fx.base_state();s['server'].update(mode='ipv6',scope='internal',ipv4='127.0.0.1',ipv6='::1',listen='::1',policies={'inbound':'ipv6','egress':'ipv4','dns':'ipv4','client':'ipv6'})
  for profile in ['global','cn','internal']:
   p=yaml.safe_load((fx.render(s)/('mihomo-'+profile+'.yaml')).read_text());self.assertTrue(p['ipv6'],'Mihomo global gate must allow IPv6 node sockets');self.assertFalse(p['dns']['ipv6'],'IPv4 destination DNS stays independent');self.assertEqual(p['proxies'][0]['ip-version'],'ipv6')
if __name__=='__main__':unittest.main(verbosity=2)
