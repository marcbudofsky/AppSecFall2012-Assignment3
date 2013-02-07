##
# CS 9163: Application Security
# Professor Justin Cappos, Professor Dan Guido
# TestCase03.py
# 
# @author       Marc Budofsky <mrb543@students.poly.edu>
# @created      September 10, 2012
# @modified     September 10, 2012
# 
# Compute Factorial; Print out values
##

def factorial(x):
    if x == 0:
        return 1
    else:
        return x * factorial(x-1)
        
for foo in range (10):
    fact = factorial(foo)

print fact
