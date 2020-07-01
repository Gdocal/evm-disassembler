for i in tests/*.py.out; do python3 ${i%.out} | diff - $i; done
