import unittest
from main import detect
class DetectionTests(unittest.TestCase):
    def event(self, minute, outcome, user='demo'):
        return {'timestamp':f'2026-11-11T12:{minute:02d}:00Z','user':user,'source_ip':'192.0.2.10','outcome':outcome}
    def test_sequence_and_sorting(self):
        events=[self.event(i,'failure') for i in range(3)]+[self.event(3,'success')]
        alerts=detect(list(reversed(events)))
        self.assertEqual(len(alerts),1)
        self.assertEqual(alerts[0]['failures'],3)
    def test_expired_window(self):
        self.assertEqual(detect([self.event(i,'failure') for i in range(3)]+[self.event(9,'success')]),[])
    def test_user_isolation(self):
        self.assertEqual(detect([self.event(i,'failure') for i in range(3)]+[self.event(3,'success','other')]),[])
    def test_success_clears_history(self):
        events=[self.event(i,'failure') for i in range(3)]+[self.event(3,'success'),self.event(4,'success')]
        self.assertEqual(len(detect(events)),1)
    def test_requires_timezone(self):
        event=self.event(0,'failure');event['timestamp']='2026-11-11T12:00:00'
        with self.assertRaises(ValueError):detect([event])

class ValidationTests(unittest.TestCase):
    def event(self, **changes):
        return dict(timestamp='2026-11-11T12:00:00Z', user='demo',
                    source_ip='192.0.2.1', outcome='failure', **{}) | changes

    def test_invalid_schema(self):
        cases=[None, [], 3, {}, self.event(user=[]), self.event(user=' '),
               self.event(timestamp='yesterday'), self.event(outcome='unknown'),
               self.event(source_ip='not-an-ip'), self.event(timestamp=7)]
        for event in cases:
            with self.subTest(event=event), self.assertRaises(ValueError):
                detect([event])

    def test_configuration(self):
        for threshold in (True, 0, -1, 1.5, '3', None):
            with self.subTest(threshold=threshold), self.assertRaises(ValueError):
                detect([], threshold=threshold)
        for window in (True, -1, float('nan'), float('inf'), '300', None):
            with self.subTest(window=window), self.assertRaises(ValueError):
                detect([], window_seconds=window)

    def test_ipv6_equivalent_spellings_share_bucket(self):
        events=[self.event(source_ip='2001:db8::1'),
                self.event(source_ip='2001:0db8:0:0:0:0:0:1',outcome='success')]
        self.assertEqual(detect(events,threshold=1)[0]['source_ip'],'2001:db8::1')

    def test_exact_window_and_offsets(self):
        events=[self.event(timestamp='2026-11-11T07:00:00-05:00'),
                self.event(timestamp='2026-11-11T12:05:00Z',outcome='success')]
        self.assertEqual(len(detect(events,threshold=1)),1)
        self.assertEqual(detect(events,threshold=1,window_seconds=299),[])

    def test_source_ip_isolation(self):
        self.assertEqual(detect([self.event(),self.event(source_ip='192.0.2.2',outcome='success')],threshold=1),[])

    def test_cli_rejects_whole_file_without_exposing_values(self):
        import json, subprocess, sys, tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'input.jsonl'
            cases=[(b'\n{broken-private-value', 'line 2: invalid JSON'),
                   ((json.dumps(self.event())+'\n'+json.dumps(self.event(user=['private-value']))).encode(), 'line 2: user'),
                   (b'\xffprivate-value', 'valid UTF-8')]
            for content, expected in cases:
                path.write_bytes(content)
                result=subprocess.run([sys.executable,str(Path(__file__).with_name('main.py')),str(path)],capture_output=True,text=True)
                self.assertEqual(result.returncode,2)
                self.assertEqual(result.stdout,'')
                self.assertIn(expected,result.stderr)
                self.assertNotIn('private-value',result.stderr)
                self.assertNotIn('Traceback',result.stderr)

    def test_cli_valid_json_and_missing_file(self):
        import json, subprocess, sys, tempfile
        from pathlib import Path
        script=str(Path(__file__).with_name('main.py'))
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'input.jsonl'
            result=subprocess.run([sys.executable,script,str(path)],capture_output=True,text=True)
            self.assertEqual(result.returncode,2)
            self.assertEqual(result.stdout,'')
            path.write_text('\n'+json.dumps(self.event())+'\n'+json.dumps(self.event(outcome='success'))+'\n')
            result=subprocess.run([sys.executable,script,str(path),'--threshold','1'],capture_output=True,text=True)
            self.assertEqual(result.returncode,0)
            self.assertEqual(len(json.loads(result.stdout)),1)
            self.assertEqual(result.stderr,'')

if __name__ == '__main__':
    unittest.main()
