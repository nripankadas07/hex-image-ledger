import unittest,hashlib
from hex_image_ledger import analyze,record
EOF=record(0,1)
def image(*lines):return '\n'.join([*lines,EOF])
class ImageTests(unittest.TestCase):
 def test_sparse_coverage_and_gap(self):
  r=analyze(image(record(0,4,b'\x08\x00'),record(0,0,b'abc'),record(8,0,b'de')));self.assertEqual(r['coverage'],[{'start':0x8000000,'end_exclusive':0x8000003},{'start':0x8000008,'end_exclusive':0x800000a}]);self.assertEqual(r['gap_bytes'],5);self.assertFalse(r['has_findings'])
 def test_segment_mode(self):self.assertEqual(analyze(image(record(0,2,b'\x12\x00'),record(0x2462,0,b'a')))['coverage'][0]['start'],0x14462)
 def test_mode_changes(self):
  r=analyze(image(record(0,4,b'\x00\x01'),record(0,0,b'a'),record(0,2,b'\x00\x01'),record(0,0,b'b')));self.assertEqual([v['start'] for v in r['coverage']],[16,65536])
 def test_identical_overlap_visible(self):
  r=analyze(image(record(0,0,b'abc'),record(1,0,b'b')));self.assertTrue(r['has_findings']);self.assertEqual(r['conflicting_addresses'],0);self.assertFalse(r['overlap_evidence'][0]['conflicting'])
 def test_conflict_has_no_winner(self):
  r=analyze(image(record(0,0,b'ab'),record(1,0,b'c')));self.assertEqual(r['unambiguous_bytes'],1);self.assertEqual(r['overlap_evidence'][0]['values'],[98,99]);self.assertEqual(r['conflicting_addresses'],1)
 def test_hash_is_order_independent(self):
  a=record(0,0,b'ab');b=record(4,0,b'cd');self.assertEqual(analyze(image(a,b))['unambiguous_sparse_map_sha256'],analyze(image(b,a))['unambiguous_sparse_map_sha256'])
 def test_hash_includes_address(self):
  self.assertNotEqual(analyze(image(record(0,0,b'a')))['unambiguous_sparse_map_sha256'],analyze(image(record(1,0,b'a')))['unambiguous_sparse_map_sha256'])
 def test_entry_covered(self):
  r=analyze(image(record(0,5,b'\0\0\0\x01'),record(0,0,b'ab')));self.assertFalse(r['entry_uncovered'])
 def test_uncovered_and_segment_entry(self):
  r=analyze(image(record(0,3,b'\x10\0\0\x10'),record(0,0,b'a')));self.assertTrue(r['entry_uncovered']);self.assertEqual(r['entry']['address'],65552)
 def test_bad_checksum_and_length(self):
  for bad in [':0100000061FF',':02000000619E']:
   with self.assertRaises(ValueError):analyze(image(bad))
 def test_missing_eof_and_post_eof(self):
  for text in [record(0,0,b'a'),image(record(0,0,b'a'))+'\n'+EOF,EOF]:
   with self.assertRaises(ValueError):analyze(text)
 def test_offset_wrap(self):
  with self.assertRaises(ValueError):analyze(image(record(65535,0,b'ab')))
 def test_32bit_last_byte(self):
  r=analyze(image(record(0,4,b'\xff\xff'),record(65535,0,b'a')));self.assertEqual(r['coverage'][0]['end_exclusive'],2**32)
 def test_record_shapes(self):
  for bad in [record(1,1),record(0,4,b'a'),record(0,2,b'abc'),record(0,6)]:
   with self.assertRaises(ValueError):analyze(image(record(0,0,b'a'),bad))
 def test_duplicate_entry(self):
  with self.assertRaises(ValueError):analyze(image(record(0,0,b'a'),record(0,5,b'\0'*4),record(0,5,b'\0'*4)))
 def test_size_budget(self):
  with self.assertRaises(ValueError):analyze(' '*(1024*1024+1))
if __name__=='__main__':unittest.main()
