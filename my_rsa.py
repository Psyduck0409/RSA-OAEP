#!/usr/bin/env python
# -*- coding: utf-8 -*-

def encode(n,e,m):
    return fast_mod(m, e, n)

def decode1(n,d,c):
    return fast_mod(c, d, n)

def decode2(p,q,dp,dq,qInv,c):
    m1 = fast_mod(c,dp,p)
    m2 = fast_mod(c,dq,q)
    h = ((m1-m2) * qInv)%p
    m = m2+ q*h
    return m

def fast_mod(x,n,m):
    d=1
    while n>0: 
        if n%2==1:
            d=((d%m)*(x%m))%m
        n = n>>1
        x=((x%m)*(x%m))%m
    return d
