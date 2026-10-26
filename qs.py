import random
before = []
for i in range(1000):
    while not rand in before:
        rand = random.randint(0,1000)
        before.append(rand)