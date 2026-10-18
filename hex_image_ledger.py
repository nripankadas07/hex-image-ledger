"""Explain sparse Intel HEX address coverage, checksums and overlapping writes."""
from __future__ import annotations
import argparse,hashlib,json,re,sys
from pathlib import Path
MAX_BYTES=1024*1024
def record(address,kind,data=b''):
    b=bytes([len(data)])+address.to_bytes(2,'big')+bytes([kind])+data;return ':'+(b+bytes([-sum(b)%256])).hex().upper()
def analyze(text):
    if len(text.encode('ascii'))>MAX_BYTES:raise ValueError('HEX exceeds1MiB')
    cells={};base=0;entry=None;eof=False;records=[];data_events=0
    for line_no,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if not line:continue
        if eof or len(records)>=8192 or not re.fullmatch(r':[0-9a-fA-F]{10,520}',line) or len(line)%2!=1:raise ValueError('invalid/budget/post-EOF record at line '+str(line_no))
        raw=bytes.fromhex(line[1:]);size=raw[0];address=int.from_bytes(raw[1:3],'big');kind=raw[3];data=raw[4:-1]
        if len(raw)!=size+5 or sum(raw)%256:raise ValueError('record length/checksum mismatch at line '+str(line_no))
        if kind==0:
            if not size or address+size>65536 or base+address+size>2**32:raise ValueError('empty data, record offset wrap or address overflow')
            data_events+=size
            if data_events>262144:raise ValueError('data-byte event budget262144')
            for i,value in enumerate(data):
                cell=cells.setdefault(base+address+i,{'values':set(),'lines':[]});cell['values'].add(value);cell['lines'].append(line_no)
            item={'line':line_no,'kind':'data','start':base+address,'end_exclusive':base+address+size}
        elif kind==1:
            if size or address:raise ValueError('strict EOF requires zero count/address')
            eof=True;item={'line':line_no,'kind':'eof'}
        elif kind in (2,4):
            if size!=2 or address:raise ValueError('extended-address record shape invalid')
            base=int.from_bytes(data,'big')<<(4 if kind==2 else 16);item={'line':line_no,'kind':'segment_base' if kind==2 else 'linear_base','base':base}
        elif kind in (3,5):
            if size!=4 or address or entry is not None:raise ValueError('one correctly shaped entry record supported')
            value=int.from_bytes(data,'big') if kind==5 else int.from_bytes(data[:2],'big')*16+int.from_bytes(data[2:],'big')
            entry={'kind':'linear' if kind==5 else 'segment_unwrapped','address':value,'raw':data.hex(),'line':line_no};item={'line':line_no,'kind':'entry'}
        else:raise ValueError('unsupported record type')
        records.append(item)
    if not eof or not cells:raise ValueError('terminated nonempty image required')
    addresses=sorted(cells);ranges=[];start=prior=addresses[0]
    for address in addresses[1:]:
        if address!=prior+1:ranges.append({'start':start,'end_exclusive':prior+1});start=address
        prior=address
    ranges.append({'start':start,'end_exclusive':prior+1})
    gaps=[{'start':a['end_exclusive'],'end_exclusive':b['start']} for a,b in zip(ranges,ranges[1:])]
    overlaps=[{'address':a,'lines':cells[a]['lines'],'values':sorted(cells[a]['values']),'conflicting':len(cells[a]['values'])>1} for a in addresses if len(cells[a]['lines'])>1]
    digest=hashlib.sha256(b'hex-map-v1\0');unambiguous=0;conflicts=0
    for address in addresses:
        values=cells[address]['values']
        if len(values)==1:digest.update(address.to_bytes(4,'big')+bytes([next(iter(values))]));unambiguous+=1
        else:conflicts+=1
    entry_uncovered=entry is not None and entry['address'] not in cells
    return {'records':records,'unique_addresses':len(cells),'data_byte_events':data_events,'coverage':ranges,'interior_gaps':gaps,'gap_bytes':sum(g['end_exclusive']-g['start'] for g in gaps),'overlap_addresses':len(overlaps),'conflicting_addresses':conflicts,'overlap_evidence':overlaps[:256],'omitted_overlap_addresses':max(0,len(overlaps)-256),'entry':entry,'entry_uncovered':entry_uncovered,'unambiguous_bytes':unambiguous,'unambiguous_sparse_map_sha256':digest.hexdigest(),'has_findings':bool(overlaps or entry_uncovered),
      'scope':'No flashing, fill-byte synthesis or overlap winner. Hash covers sorted address32-big-endian/value8 pairs with hex-map-v1 NUL prefix, only unambiguous cells. Gaps are informational. Entry coverage uses raw numerical/unwrapped segment address, no CPU/A20/Thumb interpretation.'}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('input');a=p.parse_args()
    try:
        with Path(a.input).open('rb') as f:raw=f.read(MAX_BYTES+1)
        if len(raw)>MAX_BYTES:raise ValueError('HEX exceeds1MiB')
        r=analyze(raw.decode('ascii'));print(json.dumps(r,indent=2,sort_keys=True));return int(r['has_findings'])
    except (ValueError,OSError,UnicodeError,OverflowError) as e:print(json.dumps({'error':str(e)}),file=sys.stderr);return 2
if __name__=='__main__':raise SystemExit(main())
