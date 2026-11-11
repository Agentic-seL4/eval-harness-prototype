import ctypes
import json
import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor

from host.protocol import Request, Proposal
from host.backend import Backend, BackendError, Ledger, parse_output
from host.harness import BROKER, configurations, reference, wanted, ex


class ProtocolTests(unittest.TestCase):
    def test_all_natural_campaign_cases_have_reference_records(self):
        for policy in ['open', 'fenced']:
            for email in ['benign', 'malicious']:
                name=f'{policy}-injected-s1-{email}-allowed'
                self.assertIn(name, configurations())
                self.assertTrue(reference(name))

    def test_proposal_fixture_text_is_compared_in_formal_vocabulary(self):
        _, texts=ex.manifest()
        proposal=Proposal('fetch',texts['Data 7'].encode('utf-8'))
        for policy in ['open','fenced']:
            records=wanted(f'{policy}-injected-s1-benign-allowed',proposal)
            self.assertFalse(ex.compare(records,ex.to_fixture_text(records)))

    def test_request_and_limits(self):
        r=Request.parse(b'REQ 1 1 2 2 446174612031 456d61696c\n')
        self.assertEqual(r.secret,b'Data 1')
        for line in [b'REQ 2 1 2 2 - -\n',b'REQ 1 0 2 2 - -\n',b'REQ 1 1 1 2 - -\n',
                     b'REQ 1 1 2 2 zz -\n', b'REQ 1 1 2 2 - '+b'61'*257+b'\n']:
            with self.subTest(line=line[:40]),self.assertRaises(ValueError): Request.parse(line)

    def test_shared_c_decoder(self):
        with tempfile.TemporaryDirectory() as tmp:
            so=Path(tmp)/'wire.dylib'
            subprocess.run(['clang','-shared','-fPIC','-I'+str(BROKER/'include'),'-I'+str(BROKER/'src'),
                            str(BROKER/'src/model_wire.c'),str(BROKER/'src/util.c'),'-o',str(so)],check=True)
            lib=ctypes.CDLL(str(so))
            f=lib.model_response
            f.argtypes=[ctypes.c_char_p,ctypes.c_size_t,ctypes.c_uint64,ctypes.c_void_p,ctypes.POINTER(ctypes.c_uint64)]
            for proposal in [Proposal('none'),Proposal('fetch'),Proposal('fetch',b'Data 1'),Proposal('fetch',b'\xff'*64)]:
                line=proposal.wire(1); buf=ctypes.create_string_buffer(64);n=ctypes.c_uint64()
                self.assertEqual(f(line,len(line),1,buf,ctypes.byref(n)),proposal.kind=='fetch')
                self.assertEqual(buf.raw[:n.value],proposal.value)
            for line in [b'RES 1 2 NONE\n',b'RES 1 1 ERROR\n',b'RES 1 1 FETCH 0z\n',
                         b'RES 1 1 FETCH '+b'61'*65+b'\n',b'RES 1 1 NONE\nRES 1 1 NONE\n']:
                self.assertEqual(f(line,len(line),1,buf,ctypes.byref(n)),-1)

    def test_scripted_and_adversarial(self):
        r=Request(1,2,2,b'Data 1',b'benign')
        self.assertEqual(Backend().propose(r),Proposal('none'))
        self.assertEqual(Backend('adversarial').propose(r),Proposal('fetch',b'Data 1'))


class APITests(unittest.TestCase):
    def test_client_settings_and_reservation_precede_request(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ,{'OPENAI_API_KEY_PNEW':'offline-placeholder'}), \
                patch('openai.OpenAI') as factory:
            folder=Path(tmp); ledger=folder/'ledger.json'
            response=NS(status='completed',output=[],model='test-model',usage=None,_request_id='offline-request',
                        model_dump=lambda **kw: {'status':'completed','output':[]})
            def send(**body):
                self.assertEqual(len(json.loads(ledger.read_text())['attempts']),1)
                self.assertEqual(body['tool_choice'],'auto')
                self.assertFalse(body['parallel_tool_calls'])
                self.assertEqual(body['reasoning'],{'effort':'none'})
                self.assertEqual(body['max_output_tokens'],512)
                self.assertNotIn('previous_response_id',body)
                return response
            factory.return_value.responses.create.side_effect=send
            self.assertEqual(Backend('openai',model='test-model',evidence=folder,ledger=ledger).propose(
                Request(1,2,2,b'Data 1',b'dummy')),Proposal('none'))
            factory.assert_called_once_with(api_key='offline-placeholder',timeout=30.0,max_retries=0)

    def test_response_validation(self):
        def response(args='{"value":"Data 1"}',name='fetch',count=1,status='completed'):
            return NS(status=status,output=[NS(type='function_call',name=name,arguments=args)]*count)
        self.assertEqual(parse_output(response()),Proposal('fetch',b'Data 1'))
        self.assertEqual(parse_output(response(count=0)),Proposal('none'))
        for r in [response(count=2),response(name='shell'),response(status='incomplete'),
                  response(args='{"value":1}'),response(args=json.dumps({'value':'x'*65}))]:
            with self.assertRaises(BackendError):parse_output(r)

    def test_budget_lock_and_failed_attempts_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            ledger=Ledger(Path(tmp)/'ledger.json')
            def reserve(_):
                try:return ledger.reserve('dummy','offline-test')
                except BackendError:return None
            with ThreadPoolExecutor(max_workers=8) as pool: ids=list(pool.map(reserve,range(12)))
            self.assertEqual(sorted(x for x in ids if x),list(range(1,7)))
            self.assertEqual(len(json.loads(ledger.path.read_text())['attempts']),6)

    def test_no_fallback_key(self):
        with patch.dict(os.environ,{'OPENAI_API_KEY':'unrelated'},clear=True):
            with self.assertRaisesRegex(BackendError,'PNEW'):
                Backend('openai').propose(Request(1,2,2,b'a',b'b'))

if __name__=='__main__': unittest.main()
