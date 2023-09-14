target="${1}.S"
objdump -d $1 > target
num=$(cat target | grep _afl_maybe_log | wc -l)
echo Total Regions: $((num - 1))
python hd.py
