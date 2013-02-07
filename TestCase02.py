##
# CS 9163: Application Security
# Professor Justin Cappos, Professor Dan Guido
# TestCase02.py
# 
# @author       Marc Budofsky <mrb543@students.poly.edu>
# @created      September 7, 2012
# @modified     September 7, 2012
# 
# Compute the first 10 Fibonacci Numbers; Print out values
##

def fib(x):
    if x == 0:
        return 0
    elif x == 1:
        return 1
    else:
        return fib(x-1) + fib(x-2)
        
for foo in range (10):
    print fib(foo)
