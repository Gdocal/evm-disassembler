# source ../z3.env
for i in tests/*.py.out; do python3 -O ${i%.out} | diff - $i; done
