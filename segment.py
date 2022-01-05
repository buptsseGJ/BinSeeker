#-*- coding: utf-8 -*-
dataSegment = []#initialized global variable and static variable
rodataSegment = []#string constant and variable decorated by const
bssSegment = []#the uninitialized global variable and static variable
codeSegment = []#为了判断函数最后一块return时，会有一个从内存中加载调用者中下一条语句的load操作，这个地址在每个二进制下是不同的，所以要泛化成指针
constUsage = {}#addr:value
