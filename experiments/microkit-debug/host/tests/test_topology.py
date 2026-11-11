"""Negative checks against the host model-service authority, including built caps."""
import copy
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET
from host.harness import BROKER
import check_topology as topo
import check_built_caps as caps


def variants(root):
    a=copy.deepcopy(root)
    a.find("protection_domain[@name='worker']/map[@mr='context']").set('perms','rw')
    b=copy.deepcopy(root)
    ET.SubElement(b.find("protection_domain[@name='net']"),'map',mr='inbox',vaddr='0x3000000',perms='r')
    c=copy.deepcopy(root)
    ch=ET.SubElement(c,'channel')
    ET.SubElement(ch,'end',pd='net',id='3',pp='true',notify='false')
    ET.SubElement(ch,'end',pd='sink',id='3',notify='false')
    return [('worker-context-write',a),('net-inbox-read',b),('net-sink-call',c)]


class ModelTopology(unittest.TestCase):
    def test_host_boundaries_and_mutations(self):
        root=ET.parse(BROKER/'model.system').getroot()
        policy=json.loads((BROKER/'model-flow-policy.json').read_text())
        header=(BROKER/'src/model_topology.h').read_text()
        self.assertTrue(all(ok for _,ok,_ in topo.check(topo.System(root),policy,header)))
        for name,bad in variants(root):
            with self.subTest(name=name):
                self.assertTrue(any(not ok for _,ok,_ in topo.check(topo.System(bad),policy,header)))

    @unittest.skipUnless(os.environ.get('MICROKIT_SDK'),'needs Microkit SDK')
    def test_built_caps_reject_accepted_bad_descriptions(self):
        subprocess.run(['make','-s','BACKEND=host','POLICY=open','all'],cwd=BROKER,check=True,capture_output=True)
        search=BROKER/'build/open-injected-s1-malicious-allowed-host'
        tool=Path(os.environ['MICROKIT_SDK'])/'bin/microkit'
        root=ET.parse(BROKER/'model.system').getroot()
        policy=json.loads((BROKER/'model-flow-policy.json').read_text())
        with tempfile.TemporaryDirectory() as temp:
            folder=Path(temp)
            for name,bad in variants(root):
                with self.subTest(name=name):
                    system=folder/(name+'.system');ET.ElementTree(bad).write(system)
                    output=folder/name
                    r=subprocess.run([str(tool),str(system),'--search-path',str(search),'--board','qemu_virt_aarch64',
                                      '--config','debug','-o',str(folder/(name+'.img')),'-r',str(folder/(name+'.txt')),
                                      '--viper-output',str(output)],cwd=BROKER,capture_output=True,text=True)
                    self.assertEqual(r.returncode,0,r.stdout+r.stderr)
                    peers,irqs=caps.describe_channels(system.read_text())
                    self.assertTrue(caps.check(caps.load_tables(output),policy,peers,irqs))
