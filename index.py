import pandas as pd

input_file = 'latest.csv'  # เปลี่ยนเป็นชื่อไฟล์ของคุณ
chunk_size = 1000000           # จำนวนแถวต่อ 1 ไฟล์ (1 ล้านแถว)

# เริ่มต้นอ่านไฟล์แบบ Chunk
for i, chunk in enumerate(pd.read_csv(input_file, chunksize=chunk_size)):
    output_file = f'split_file_{i+1}.csv'
    chunk.to_csv(output_file, index=False)
    print(f'สร้างไฟล์ {output_file} สำเร็จแล้ว!')

print("แบ่งไฟล์ทั้งหมดเรียบร้อยแล้ว!")