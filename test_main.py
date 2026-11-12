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
if __name__=='__main__':unittest.main()
