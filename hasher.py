def h(s):
  total = 0
  count = 1
  for c in s:
    total += ord(c) * count + total // 3
    count += 1
  return total
 

while True:
  print(h(input()))

