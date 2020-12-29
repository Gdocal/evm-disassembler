# source ../z3.env
for i in tests/*.py.out; do echo $i; python3 -O ${i%.out} | diff - $i; done
