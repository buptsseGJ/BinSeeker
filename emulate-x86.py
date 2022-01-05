#-*- coding: utf-8 -*-
from registerOffset import *
import pyvex
import archinfo
import database
import convertToIR
import registerOffset
#import x86g_calculate_eflags_c
import x86g_calculate_condition
import libFuncs
import segment
import math
import sys
import os
import copy
import traceback
from __builtin__ import True
from msilib.schema import Condition
from ctypes import *
import shutil#删除目录使用
import platform
import datetime
import randomInput
from copy import deepcopy

reload(sys)
sys.setdefaultencoding('utf8')

ls = os.linesep
currentEmulatedBlock = 0#用块的开始地址表示
currentNextIP = 0#用块的开始地址表示，循环两个分支一个地址更高，一个地址更低（会包含等于的情况）
maxLoopOrRecursion = 5
funcLoopOrRecursion = {}#递归计数使用
blockLoopOrRecursion = {}#块循环计数使用
priorLoopFlag = {}
allUserFuncs = set()
stackStart = 0#ebp-based 函数使用，根据ebp指定,不用这个了，因为即使是ebp-based的函数也可能没有put(ebp)这样的IR出现
stackStartList = []#非 ebp-based 函数使用，根据函数开始时的esp指定
stackEnd = 0#无论是否是ebp-based的函数均可使用,永远有esp指定
stackArgs = []
registerArgs = []
temporarySpace = {}
globalSpace = {}
memorySpace= {}
constsSpace = {}
switchJump = {}
ebpBased = {}
switchFlag = False
currentInstr = 0
currentState = ""
nextStartAddr = 0
currentStartAddr = 0
ebp = 178956976
esp = 178956970
nan = float('nan')
emulateAll = True
emulateAddr = 0
emulateFunctions = set()
childPath = "signature"
pushAndCallList = []
functionInfo = {}
signatureLength = 0
argsDistributionIndex = 0
randomValueList_same = []
functionArgs = {}
registerArgsState = {}
isVulnerabilityProgram = False
programName = ""
fileName = ""
db = 0
fwrite = 0

def getArgValue(arg):
    if isinstance(arg,pyvex.expr.Const):
        return int(str(arg),16)
    elif isinstance(arg, pyvex.expr.RdTmp):
        return temporarySpace[int(arg.tmp)]
    else:
        print "error in getArgValue"
        raise BaseException
        return 0


def processTriOp(op,args):
    arg1 = getArgValue(args[0])#舍入编码
    arg2 = getArgValue(args[1])
    arg3 = getArgValue(args[2])
    result = 0
    if "AddF64" in op[4:]:
        result = arg2 + arg3        
        return intOrFloatToFloat(arg1, result)
    elif "SubF64" in op[4:]:
        result = arg2 - arg3
        return intOrFloatToFloat(arg1, result)
    elif "MulF64" in op[4:]:
        result = arg2 * arg3
        return intOrFloatToFloat(arg1, result)
    elif "DivF64" in op[4:]:
        if arg3 != 0:
            result = arg2 / arg3
            return intOrFloatToFloat(arg1, result)
        else:
            return intOrFloatToFloat(arg1, 0)
    else:
        print "other in processTriop"
        raise BaseException
    return result
    
def processQop(op,args):
    arg1 = getValue(args[0])
    arg2 = getValue(args[1])
    arg3 = getValue(args[2])
    arg4 = getValue(args[3])
    result = 0
    if "x86g_use_seg_selector" in op[4:]:
        return result
    else:
        print "other in processQop"
        raise BaseException

def processCCall(type,op,args):
    if "x86g_use_seg_selector" == str(op.name):
        arg1 = getValue(args[0])
        arg2 = getValue(args[1])
        arg3 = getValue(args[2])
        arg4 = getValue(args[3])
        result = 0
        return 0
    elif "x86g_calculate_eflags_c" == str(op.name):
        arg1 = getValue(args[0])#cc_op
        arg2 = getValue(args[1])#dep1
        arg3 = getValue(args[2])#dep2
        arg4 = getValue(args[3])#ndep
        result = x86g_calculate_condition.x86g_calculate_eflags_c(arg1,arg2,arg3,arg4)
        return result
    elif "x86g_calculate_condition" == str(op.name):#计算cmp指令啊
        max_value = 2147483647
        min_value = -2147483648
        arg1 = getValue(args[0])#condition code
        arg2 = getValue(args[1])#cc_op
        arg3 = getValue(args[2])#arg1
        arg4 = getValue(args[3])#arg2
        arg5 = getValue(args[4])#不知道是啥  
        return x86g_calculate_condition.x86g_calculate_condition(arg1,arg2,arg3,arg4,arg5)
    elif "x86g_calculate_eflags_all" == str(op.name):
        arg1 = getValue(args[0])
        arg2 = getValue(args[1])
        arg3 = getValue(args[2])
        arg4 = getValue(args[3])
        return x86g_calculate_condition.x86g_calculate_eflags_all(arg1,arg2,arg3,arg4)
    elif "x86g_create_fpucw" == str(op.name):
        arg1 = getValue(args[0])
        return x86g_calculate_condition.x86g_create_fpucw(arg1)
    elif "x86g_check_fldcw" == str(op.name):
        arg1 = getValue(args[0])
        return x86g_calculate_condition.x86g_check_fldcw(arg1)
        
def writeCmp(op,arg1,arg2):
    fwrite.write("CC" + " " + str(arg1) + " " + str(arg2) + " " + op + "\n")
    
def writeIO(type,value):
    fwrite.write(type + " " + str(value) + "\n")

def two32sTo64(arg1,arg2):
    leftSide = c_ulonglong(arg1).value
    leftSide = leftSide << 32
    rightSide = c_ulonglong(arg2).value
    return c_ulonglong(leftSide | rightSide).value

def two16to32(arg1,arg2):
    leftSide = c_uint32(arg1).value
    leftSide = leftSide << 16
    rightSide = c_uint32(arg2).value
    return c_uint32(leftSide | rightSide).value

def two32sTo64S(arg1,arg2):
    leftSide = c_longlong(arg1).value
    leftSide = leftSide << 32
    rightSide = c_longlong(arg2).value
    return leftSide | rightSide
def divMod64to32(signed,arg1,arg2):#高一半是mod
    if arg2 == 0:
        return 0
    else:
        if signed:#有符号数除法
            mod = int(arg1)%int(arg2)
            div = int(arg1)//int(arg2)
            sameSigned = arg1 * arg2 
            if sameSigned >= 0:#同符号不用转换
                result = two32sTo64S(mod, div)
                return result
            else:#不同符号需要转换
                if mod !=0:
                    mod = mod - arg2
                    div = div + 1
                result = two32sTo64S(mod, div)
                return result
            
        else:#无符号数除法
            div = int(arg1)//int(arg2)
            mod = int(arg1)%int(arg2)
            result = two32sTo64(mod, div)
            return result

def getValueFromVector64_u(bits,arg1):
    if bits == 8:
        value1_1 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#8-15bit
        value1_2 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#16~23bit
        value1_3 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#24~31bit
        value1_4 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#32~39bit
        value1_5 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#40~47bit
        value1_6 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#48~55bit
        value1_7 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#56~63bit
        value1_8 = c_ubyte(arg1 & 0xFF).value
        return value1_1,value1_2,value1_3,value1_4,value1_5,value1_6,value1_7,value1_8
    elif bits == 16:
        value1_1 = c_ushort(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16
        value1_2 = c_ushort(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16
        value1_3 = c_ushort(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16
        value1_4 = c_ushort(arg1 & 0xFFFF).value
        return value1_1,value1_2,value1_3,value1_4
    elif bits == 32:
        value1_1 = c_uint32(arg1 & 0xFFFFFFFF).value
        arg1 = arg1 >> 32
        value1_2 = c_uint32(arg1 & 0xFFFFFFFF).value
        return value1_1,value1_2

def getValueFromVector64_s(bits,arg1):
    if bits == 8:
        value1_1 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#8-15bit
        value1_2 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#16~23bit
        value1_3 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#24~31bit
        value1_4 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#32~39bit
        value1_5 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#40~47bit
        value1_6 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#48~55bit
        value1_7 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#56~63bit
        value1_8 = c_byte(arg1 & 0xFF).value
        return value1_1,value1_2,value1_3,value1_4,value1_5,value1_6,value1_7,value1_8
    elif bits == 16:
        value1_1 = c_short(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16
        value1_2 = c_short(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16
        value1_3 = c_short(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16
        value1_4 = c_short(arg1 & 0xFFFF).value
        return value1_1,value1_2,value1_3,value1_4
    elif bits == 32:
        value1_1 = c_int32(arg1 & 0xFFFFFFFF).value
        arg1 = arg1 >> 32
        value1_2 = c_int32(arg1 & 0xFFFFFFFF).value
        return value1_1,value1_2

def permVector64(bits,arg1,arg2):
    value1_1,value1_2,value1_3,value1_4,value1_5,value1_6,value1_7,value1_8 = getValueFromVector64_u(bits, arg1)
    value2_1,value2_2,value2_3,value2_4,value2_5,value2_6,value2_7,value2_8 = getValueFromVector64_u(bits, arg1)
    argL = []
    argR = []
    argL.append(value1_8)
    argL.append(value1_7)
    argL.append(value1_6)
    argL.append(value1_5)
    argL.append(value1_4)
    argL.append(value1_3)
    argL.append(value1_2)
    argL.append(value1_1)
    argR.append(value2_8)
    argR.append(value2_7)
    argR.append(value2_6)
    argR.append(value2_5)
    argR.append(value2_4)
    argR.append(value2_3)
    argR.append(value2_2)
    argR.append(value2_1)
    result = []
    for i in range(8):
        tmp = argR[i]
        if tmp <= 7 and tmp >=0:
            result.append(argL[tmp])
        else:
            raise BaseException("error in perm8x8")
    return (result[7] << 0) | (result[6] << 8) | (result[5] << 16) | (result[4] << 24) | (result[3] << 32) | (result[2] << 40) | (result[1] << 48) | (result[0] << 56)

def shlVector64(bits,arg1,arg2):
    if bits == 8:
        value1_1,value1_2,value1_3,value1_4,value1_5,value1_6,value1_7,value1_8 = getValueFromVector64_u(bits, arg1)
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 7:
            value1_1 = c_ubyte(value1_1 << shift).value
            value1_2 = c_ubyte(value1_2 << shift).value
            value1_3 = c_ubyte(value1_3 << shift).value
            value1_4 = c_ubyte(value1_4 << shift).value
            value1_5 = c_ubyte(value1_5 << shift).value
            value1_6 = c_ubyte(value1_6 << shift).value
            value1_7 = c_ubyte(value1_7 << shift).value
            value1_8 = c_ubyte(value1_8 << shift).value
        return (value1_1 << 0) | (value1_2 << 8) | (value1_3 << 16) | (value1_4 << 24) | (value1_5 << 32) | (value1_6 << 40) | (value1_7 << 48) | (value1_8 << 56)
    elif bits == 16:
        value1_1,value1_2,value1_3,value1_4 = getValueFromVector64_u(bits, arg1)
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 15:
            value1_1 = c_ushort(value1_1 << shift).value
            value1_2 = c_ushort(value1_2 << shift).value
            value1_3 = c_ushort(value1_3 << shift).value
            value1_4 = c_ushort(value1_4 << shift).value
        return (value1_1 << 0) | (value1_2 << 16) | (value1_3 << 32) | (value1_4 << 48)
    elif bits == 32:
        value1_1,value1_2 = getValueFromVector64_u(bits, arg1)
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 31:
            value1_1 = c_uint32(value1_1 << shift).value
            value1_2 = c_uint32(value1_2 << shift).value
        return (value1_1 << 0) | (value1_2 << 32)    
    
def sarVector64(bits,arg1,arg2):
    if bits == 8:
        value1_1,value1_2,value1_3,value1_4,value1_5,value1_6,value1_7,value1_8 = getValueFromVector64_s(bits, arg1)
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 7:
            value1_1 = c_ubyte(value1_1 >> shift).value
            value1_2 = c_ubyte(value1_2 >> shift).value
            value1_3 = c_ubyte(value1_3 >> shift).value
            value1_4 = c_ubyte(value1_4 >> shift).value
            value1_5 = c_ubyte(value1_5 >> shift).value
            value1_6 = c_ubyte(value1_6 >> shift).value
            value1_7 = c_ubyte(value1_7 >> shift).value
            value1_8 = c_ubyte(value1_8 >> shift).value
        return (value1_1 << 0) | (value1_2 << 8) | (value1_3 << 16) | (value1_4 << 24) | (value1_5 << 32) | (value1_6 << 40) | (value1_7 << 48) | (value1_8 << 56)
    elif bits == 16:
        value1_1,value1_2,value1_3,value1_4 = getValueFromVector64_s(bits, arg1)
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 15:
            value1_1 = c_ushort(value1_1 >> shift).value
            value1_2 = c_ushort(value1_2 >> shift).value
            value1_3 = c_ushort(value1_3 >> shift).value
            value1_4 = c_ushort(value1_4 >> shift).value
        return (value1_1 << 0) | (value1_2 << 16) | (value1_3 << 32) | (value1_4 << 48)
    elif bits == 32:
        value1_1,value1_2 = getValueFromVector64_s(bits, arg1)
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 31:
            value1_1 = c_uint32(value1_1 >> shift).value
            value1_2 = c_uint32(value1_2 >> shift).value
        return (value1_1 << 0) | (value1_2 << 32)

def addV128(bits,arg1,arg2):
    count = 128/bits
    mask = 0
    if bits == 32:
        mask = 0xFFFFFFFF
    elif bits == 64:
        mask = 0xFFFFFFFFFFFFFFFF
    else:
        raise BaseException("error in addV128 method")
    result = 0
    for i in range(count):
        item1 = arg1 & mask    
        item2 = arg2 & mask
        if bits == 32:
            temp = c_uint32(item1 + item2).value
            result = result | temp<<(32*i)
            arg1=arg1>>32
            arg2=arg2>>32
        elif bits == 64:
            temp = c_ulonglong(item1 + item2).value
            result = result| temp<<(64*i)
            arg1 = arg1>>64
            arg2 = arg2>>64
    return result

def addVector64(bits,arg1,arg2):
    if bits == 8:
        value1_1 = c_ubyte(arg1 & 0xFF).value
        value2_1 = c_ubyte(arg2 & 0xFF).value
        arg1 = arg1 >> 8#8-15bit
        arg2 = arg2 >> 8
        value1_2 = c_ubyte(arg1 & 0xFF).value
        value2_2 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#16~23bit
        arg2 = arg2 >> 8
        value1_3 = c_ubyte(arg1 & 0xFF).value
        value2_3 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#24~31bit
        arg2 = arg2 >> 8
        value1_4 = c_ubyte(arg1 & 0xFF).value
        value2_4 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#32~39bit
        arg2 = arg2 >> 8
        value1_5 = c_ubyte(arg1 & 0xFF).value
        value2_5 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#40~47bit
        arg2 = arg2 >> 8
        value1_6 = c_ubyte(arg1 & 0xFF).value
        value2_6 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#48~55bit
        arg2 = arg2 >> 8
        value1_7 = c_ubyte(arg1 & 0xFF).value
        value2_7 = c_ubyte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#56~63bit
        arg2 = arg2 >> 8
        value1_8 = c_ubyte(arg1 & 0xFF).value
        value2_8 = c_ubyte(arg1 & 0xFF).value
        result1 = c_ubyte(value1_1 + value2_1).value
        result2 = c_ubyte(value1_2 + value2_2).value
        result3 = c_ubyte(value1_3 + value2_3).value
        result4 = c_ubyte(value1_4 + value2_4).value
        result5 = c_ubyte(value1_5 + value2_5).value
        result6 = c_ubyte(value1_6 + value2_6).value
        result7 = c_ubyte(value1_7 + value2_7).value
        result8 = c_ubyte(value1_8 + value2_8).value
        result = (result1 << 0)| (result2 << 8)|(result3 << 16)|(result4 << 24)|(result5 << 32)|(result6 << 40)|(result7 << 48)|(result8 << 56)
        return result
    elif bits == 16:
        value1_1 = c_ushort(arg1 & 0xFFFF).value
        value2_1 = c_ushort(arg2 & 0xFFFF).value
        arg1 = arg1 >> 16
        arg2 = arg2 >> 16
        value1_2 = c_ushort(arg1 & 0xFFFF).value
        value2_2 = c_ushort(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16
        arg2 = arg2 >> 16
        value1_3 = c_ushort(arg1 & 0xFFFF).value
        value2_3 = c_ushort(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16
        arg2 = arg2 >> 16
        value1_4 = c_ushort(arg1 & 0xFFFF).value
        value2_4 = c_ushort(arg1 & 0xFFFF).value
        result1 = c_ushort(value1_1 + value2_1).value
        result2 = c_ushort(value1_2 + value2_2).value
        result3 = c_ushort(value1_3 + value2_3).value
        result4 = c_ushort(value1_4 + value2_4).value
        result = (result1 << 0)| (result2 << 16)|(result3 << 32)|(result4 << 48)
        return result
    elif bits == 32:
        value1_1 = c_uint32(arg1 & 0xFFFFFFFF).value
        value2_1 = c_uint32(arg2 & 0xFFFFFFFF).value
        arg1 = arg1 >> 32
        arg2 = arg2 >> 32
        value1_2 = c_uint32(arg1 & 0xFFFFFFFF).value
        value2_2 = c_uint32(arg1 & 0xFFFFFFFF).value
        result1 = c_uint32(value1_1 + value2_1).value
        result2 = c_uint32(value1_2 + value2_2).value
        result = (result1 << 0)| (result2 << 32)
        return result

def interleaveLO32_4(value1,value2):
    result = 0
    for i in range(4):
        item1 = value1 & 0xFF#高位置
        item2 = value2 & 0xFF#低位置
        result = result | ((item1<< (16*i+8))) | (item2<<(16*i))
        value1 = value1 >> 8
        value2 = value2 >> 8
    return result
        

def processBinOp(op,args):
    arg1 = getArgValue(args[0])
    if arg1 == None:
        pass
    arg2 = getArgValue(args[1])
    result = 0
    if "Sub32" == op[4:] or "Sub64" == op[4:]:
        result = arg1 - arg2
        return c_uint32(result).value
    elif "Sub8" == op[4:]:
        result = arg1 - arg2
        return toUChar(result)
    elif "Add8" == op[4:]:
        result = arg1 + arg2
        return toUChar(result)
    elif "Add16" == op[4:]:
        result = arg1 + arg2
        return toUShort(result)
    elif "Add32" == op[4:] or "Add64" == op[4:]:
        result = arg1 + arg2
        return c_uint32(result).value
    elif "And32" == op[4:]:
        result = int(arg1 & arg2)
        return c_uint32(result).value
    elif "And64" == op[4:]:
        result = arg1 & arg2
        return c_ulonglong(result).value
    elif "AndV128" == op[4:]:
        result = arg1 & arg2
        return result
    elif "And8" == op[4:]:
        result = toUChar(arg1 & arg2)
    elif "And16" == op[4:]:
        result = toUShort(arg1 & arg2)
    elif "Max32U" == op[4:]:
        value1 = c_uint32(arg1).value
        value2 = c_uint32(arg2).value
        result = 0
        if value1 > value2:
            result = value1
        else:
            result = value2
        return result
    elif "Mul32" == op[4:]:
        result = arg1 * arg2
        return c_uint32(result).value
    elif "Mul64" == op[4:]:
        result = arg1 * arg2
        return c_ulonglong(result).value
    elif "Mul8" == op[4:]:
        result = arg1 * arg2
        return toUChar(result)
    elif "Mul16" == op[4:]:
        result = arg1 * arg2
        return toUShort(result)
    elif "MullS32" == op[4:]:
        value1 = c_uint32(arg1).value
        value2 = c_uint32(arg2).value
        value1_s = c_int32(value1).value
        value2_s = c_int32(value2).value
        value1_s_l = c_longlong(value1_s).value
        value2_s_l = c_longlong(value2_s).value
        result_s_l = value1_s_l * value2_s_l
        result_u_l = c_ulonglong(result_s_l).value
        return result_u_l
    elif "MullU32" == op[4:]:
        value1 = c_uint32(arg1).value
        value2 = c_uint32(arg2).value
        value1_u_l = c_ulonglong(value1).value
        value2_u_l = c_ulonglong(value2).value
        result_u_l = value1_u_l * value2_u_l
        result_u_l = c_ulonglong(result_u_l).value
        return result_u_l
    elif "DivU32" == op[4:]:
        arg1_u = c_uint32(arg1).value
        arg2_u = c_uint32(arg2).value
        if arg2_u != 0:
            return arg1_u / arg2_u
        else:
            return 0
    elif "DivS32" == op[4:]:
        arg1_s = c_int32(arg1).value
        arg2_s = c_int32(arg2).value
        if arg2_s != 0:
            return arg1_s / arg2_s
        else:
            return 0
    elif "Or32" == op[4:]:
        result = arg1 | arg2
        return c_uint32(result).value
    elif "Or64" == op[4:] or "OrV128" == op[4:]:
        result = arg1 | arg2
        return c_ulonglong(result).value
    elif "Or8" == op[4:]:
        result = toUChar(arg1 | arg2)
    elif "Or16" == op[4:]:
        result = toUShort(arg1 | arg2)
    elif "Shl32" == op[4:]:
        shift = c_int32(arg2).value
        if shift>=0 and shift<=31:
            result = arg1 << shift
        return c_uint32(result).value
    elif "Shl64" == op[4:]:
        shift = c_int32(arg2).value
        if shift >=0 and shift <=63:
            result = arg1 << shift
        return c_ulonglong(result).value
    elif "Shl8" == op[4:]:
        arg2 = c_int32(arg2).value
        if arg2 >= 0 and arg2 <= 7:
            result = toUChar(arg1 << arg2)
        return result
    elif "Shl16" == op[4:]:
        arg2 = c_int32(arg2).value
        if arg2 >=0 and arg2 <= 15:
            result = toUShort(arg1 << arg2)
        return result
    elif "Shr32" == op[4:]:
        value = c_uint32(arg1).value
        shift = c_int32(arg2).value
        if shift >=0 and shift <=31:
            result = value >> shift
        return c_uint32(result).value
    elif "Shr64" == op[4:]:
        value = c_ulonglong(arg1).value
        shift = c_int32(arg2).value
        if shift >=0 and shift <=63:
            result = value >> shift
        return c_ulonglong(result).value
    elif "Shr8" == op[4:]:
        value = c_ubyte(arg1).value
        shift = c_int32(arg2).value
        if shift >=0 and shift <= 7:
            result = value >> shift
        return toUChar(result)
    elif "Shr16" == op[4:]:
        value = c_ushort(arg1).value
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 15:
            result = arg1 >> arg2
        return toUShort(result)
    elif "Sar32" == op[4:]:#这个是算数右移指令，用符号位补足，而shr是用0补足
        value = c_int32(arg1).value
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 31:
            result = c_uint32(value >> shift).value
        return result
    elif "Sar64" == op[4:]:
        value = c_longlong(arg1).value
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 63:
            result = c_ulonglong(value >> shift).value
        return result
    elif "Sar8" == op[4:]:#这个是算数右移指令，用符号位补足，而shr是用0补足
        value = c_byte(arg1).value
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 7:
            result = value >> shift
        return c_ubyte(result).value
    elif "Sar16" == op[4:]:#这个是算数右移指令，用符号位补足，而shr是用0补足
        value = c_short(arg1).value
        shift = c_int32(arg2).value
        if shift >= 0 and shift <= 15:
            result = value >> shift
        return c_ushort(result).value 
    elif "Xor32" == op[4:]:
        result = arg1 ^ arg2
        return c_uint32(result).value
    elif "Xor64" == op[4:] or "XorV128" == op[4:]:
        result = arg1 ^ arg2
        return c_ulonglong(result).value
    elif "Xor8" == op[4:]:
        result = toUChar(arg1 ^ arg2)
    elif "Xor16" == op[4:]:
        result = toUShort(arg1 ^ arg2)    
    elif "32HLto64" == op[4:]:
        result = two32sTo64(arg1,arg2)
    elif "16HLto32" == op[4:]:
        result = two16to32(arg1,arg2)
    elif "DivModU64to32" == op[4:]:
        result = divMod64to32(False,arg1,arg2)
    elif "DivModS64to32" == op[4:]:
        result = divMod64to32(True,arg1,arg2)
    elif "CmpLE32S" == op[4:]:
        arg1 = c_int32(arg1).value#gai
        arg2 = c_int32(arg2).value
        temp = cmp(arg1,arg2)
        if temp <= 0:
            result = True
        else:
            result = False
        
        writeCmpWrapper("LT",arg1,arg2 + 1)
    elif "CmpLE64S" == op[4:]:
        arg1 = c_longlong(arg1).value#gai
        arg2 = c_longlong(arg2).value
        temp = cmp(arg1,arg2)
        if temp <= 0:
            result = True
        else:
            result = False
        writeCmpWrapper("LT",arg1,arg2 + 1)
    elif "CmpLE32U" == op[4:]:#gai
        arg1 = c_uint32(arg1).value
        arg2 = c_uint32(arg2).value
        temp = cmp(arg1,arg2)
        if temp <= 0:
            result = True
        else:
            result = False
        writeCmpWrapper("LT",arg1,arg2 + 1)
    elif "CmpLE64U" == op[4:]:#gai
        arg1 = c_ulonglong(arg1).value
        arg2 = c_ulonglong(arg2).value
        temp = cmp(arg1,arg2)
        if temp <= 0:
            result = True
        else:
            result = False
        writeCmpWrapper("LT",arg1,arg2 + 1)
    elif "CmpLT32S" == op[4:]:#gai
        arg1 = c_int32(arg1).value
        arg2 = c_int32(arg2).value
        temp = cmp(arg1,arg2)
        if temp < 0:
            result = True
        else:
            result = False
        writeCmpWrapper("LT",arg1,arg2)
    elif "CmpLT64S" == op[4:]:#gai
        arg1 = c_longlong(arg1).value
        arg2 = c_longlong(arg2).value
        temp = cmp(arg1,arg2)
        if temp < 0:
            result = True
        else:
            result = False
        writeCmpWrapper("LT",arg1,arg2)
    elif "CmpLT32U" == op[4:]:#gai
        arg1 = c_uint32(arg1).value
        arg2 = c_uint32(arg2).value
        temp = cmp(arg1,arg2)
        if temp < 0:
            result = True
        else:
            result = False
        writeCmpWrapper("LT",arg1,arg2)
    elif "CmpLT64U" == op[4:]:#gai
        arg1 = c_ulonglong(arg1).value
        arg2 = c_ulonglong(arg2).value
        temp = cmp(arg1,arg2)
        if temp < 0:
            result = True
        else:
            result = False
        writeCmpWrapper("LT",arg1,arg2)
    elif "CmpEQ32" == op[4:] or "CmpEQ64" == op[4:]:
        temp = cmp(arg1,arg2)#gai
        if temp == 0:
            result = True
        else:
            result = False
        writeCmpWrapper("EQ",arg1,arg2)
    elif "CmpEQ8" == op[4:]:
        arg1 = 0xFF & arg1#gai
        arg2 = 0xFF & arg2
        temp = cmp(arg1,arg2)#gai
        if temp == 0:
            result = True
        else:
            result = False
        writeCmpWrapper("EQ",arg1,arg2)   
    elif "CmpEQ16" == op[4:]:
        arg1 = 0xFFFF & arg1#gai
        arg2 = 0xFFFF & arg2
        temp = cmp(arg1,arg2)#gai
        if temp == 0:
            result = True
        else:
            result = False
        writeCmpWrapper("EQ",arg1,arg2)                
    elif "CmpNE8" == op[4:] or "CasCmpNE8" == op[4:] or "ExpCmpNE8" == op[4:]:
        arg1 = 0xFF & arg1#gai
        arg2 = 0xFf & arg2
        temp = cmp(arg1,arg2)
        if temp == 0:
            result = False
        else:
            result = True
        writeCmpWrapper("NE",arg1,arg2)
    elif "CmpNE16" == op[4:] or "CasCmpNE16" == op[4:] or "ExpCmpNE16" == op[4:]:
        arg1 = 0xFFFF & arg1#gai
        arg2 = 0xFFFF & arg2
        temp = cmp(arg1,arg2)
        if temp == 0:
            result = False
        else:
            result = True
        writeCmpWrapper("NE",arg1,arg2)
    elif "CmpNE32" == op[4:] or "CasCmpNE32" == op[4:] or "ExpCmpNE32" == op[4:]:
        temp = cmp(arg1,arg2)#gai
        if temp == 0:
            result = False
        else:
            result = True
        writeCmpWrapper("NE",arg1,arg2)
    elif "CmpNE64" == op[4:] or "CasCmpNE64" == op[4:] or "ExpCmpNE64" == op[4:]:
        temp = cmp(arg1,arg2)#gai
        if temp == 0:
            result = False
        else:
            result = True
        writeCmpWrapper("NE",arg1,arg2)    
    elif "CmpORD32S" == op[4:]:
        arg1_u = c_uint32(arg1).value
        arg2_u = c_uint32(arg2).value
        arg1_s = c_int32(arg1_u).value
        arg2_s = c_int32(arg2_u).value
        r = 2
        if arg1_s < arg2s:
            r = 8
            writeCmpWrapper("LT",arg1,arg2)  
        elif arg1_s > arg2_s:
            r = 4
            writeCmpWrapper("GT",arg1,arg2)  
        else:
            r = 2
            writeCmpWrapper("EQ",arg1,arg2)  
        return r
    elif "64HLtoV128" == op[4:]:
        result = f64HItoV128(arg1,arg2)
        return result
    elif "V128HLtoV256" == op[4:] or "InterleaveLO8x16" == op[4:]:
        raise BaseException("other binop in V128HLtoV256")
    elif "CmpF64" == op[4:]:
        if(isNan(arg1) or isNan(arg2)):
            result = int(str("0x45"),16)
        else:
            if isClose(arg1,arg2):
                result = int(str("0x40"),16)
                writeCmpWrapper("EQ",arg1,arg2)  
            elif arg1 < arg2:
                result = int(str("0x01"),16)
                writeCmpWrapper("LT",arg1,arg2)  
            else:
                result = int(str("0x00"),16)
                writeCmpWrapper("GT",arg1,arg2)
    elif "I64StoF64" == op[4:] or "I64UtoF64" == op[4:] or "I64UtoF32" == op[4:] or "I32UtoF32" == op[4:] or "I32StoF32" == op[4:] or "I64StoF32" == op[4:]:
        result = intOrFloatToFloat(arg1,arg2)
    elif "SarN8x8" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            return sarVector64(8,arg1,arg2)
    elif "SarN16x4" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            return sarVector64(16,arg1,arg2)
    elif "SarN32x2" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            return sarVector64(32,arg1,arg2)
    elif "ShrN8x8" == op[4:] or "ShrN16x4" == op[4:] or "ShrN32x2" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            raise BaseException("error in ShrN8x8")
    elif "ShlN8x8" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            return shlVector64(8,arg1,arg2)
    elif "ShlN16x4" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            return shlVector64(16,arg1,arg2)
    elif "ShlN32x2" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            return shlVector64(32,arg1,arg2)
    elif "SarN8x16" == op[4:] or "SarN16x8" == op[4:] or "SarN32x4" == op[4:] or "SarN64x2" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            raise BaseException("error in SarN8x16")
    elif "ShrN8x16" == op[4:] or "ShrN16x8" == op[4:] or "ShrN32x4" == op[4:] or "ShrN64x2" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            raise BaseException("error in ShrN8x16")
    elif "ShlN8x16" == op[4:] or "ShlN16x8" == op[4:] or "ShlN32x4" == op[4:] or "ShlN64x2" == op[4:]:
        if arg1 == 0:
            return 0
        else:
            raise BaseException("error in ShlN8x16")
    elif "Perm8x8" == op[4:]:
        if (arg1 == 0 and arg2 == 0) or (arg1 == arg2):
            return 0
        else:
            result = permVector64(8,arg1,arg2)
    elif "Add8x16" == op[4:] or "Add16x8" == op[4:] or "Add64x2" == op[4:]:
        if arg1 == 0 and arg2 == 0:
            return 0
        else:
            raise BaseException("error in Add8x16")
    elif "Add32x4" == op[4:]:
        if arg1 == 0 and arg2 == 0:
            return 0
        else:
            return addV128(32,arg1,arg2)
    elif "Add8x8" == op[4:]:
        if arg1 == 0 and arg2 == 0:
            return 0
        else:
            return addVector64(8,arg1,arg2)       
    elif "Add16x4" == op[4:]:
        if arg1 == 0 and arg2 == 0:
            return 0
        else:
            return addVector64(16,arg1,arg2)    
    elif "Add32x2" == op[4:]:
        if arg1 == 0 and arg2 == 0:
            return 0
        else:
            return addVector64(32,arg1,arg2)           
    elif "Sub8x16" == op[4:] or "Sub16x8" == op[4:] or "Sub32x4" == op[4:] or "Sub64x2" == op[4:]:
        if (arg1 == 0 and arg2 == 0) or (arg1 == arg2):
            return 0
        else:
            raise BaseException("error in Sub32x4")
    elif "InterleaveLO32x2" == op[4:]:#目的操作数的结果在高半部分，源操作数结果在低半部分
        if (arg1 == 0 and arg2 == 0):
            return 0
        elif arg1 == arg2:
            return arg1
        else:
            raise BaseException("error in InterleaveLO32x2")
    elif "CmpGT8Sx8" == op[4:]:
        writeCmpWrapper("GT",arg1,arg2)  
        if (arg1 == 0 and arg2 == 0) or (arg1 == arg2):
            return 0
        else:
            result = cmpGT64(8,arg1,arg2)
            return result
    elif "CmpGT16Sx4" == op[4:]:
        writeCmpWrapper("GT",arg1,arg2)  
        if (arg1 == 0 and arg2 == 0) or (arg1 == arg2):
            return 0
        else:
            result = cmpGT64(16,arg1,arg2)
            return result
    elif"CmpGT32Sx2" == op[4:]:
        writeCmpWrapper("GT",arg1,arg2)  
        if (arg1 == 0 and arg2 == 0) or (arg1 == arg2):
            return 0
        else:
            result = cmpGT64(32,arg1,arg2)
            return result
    elif "CmpGT32Sx4" == op[4:] or "CmpGT64Sx2" == op[4:] or "CmpGT16Sx8" == op[4:] or "CmpGT8Sx16" == op[4:]:
        writeCmpWrapper("GT",arg1,arg2)  
        if arg1 == 0 and arg2 == 0:
            return 0
        else:
            raise BaseException("error in CmpGT32Sx4")
    elif "F64toI32S" == op[4:]:
        return f64toI32S(arg1,arg2)
    elif "F64toI64S" == op[4:]:
        return f64toI64S(arg1,arg2)
    elif "Div64F0x2" == op[4:]:#从这里开始实现的可能不对
        if arg1 == 0 or arg2 == 0:
            return 0
        else:
            return arg1/arg2
    elif "Add64F0x2" == op[4:]:
        if arg1 == 0 or arg2 == 0:
            return 0
        else:
            return arg1 + arg2
    elif "Sub64F0x2" == op[4:]:
        result = arg1 - arg2
        return result
    elif "Mul64F0x2" == op[4:]:
        if arg1 == 0 or arg2 == 0:
            return 0
        else:
            return arg1 * arg2
    elif "CmpEQ64F0x2" == op[4:]:#cmpeqsd 对低64位数双精度浮点数比较
        temp = cmp(arg1,arg2)#gai
        if temp == 0:
            result = True
        else:
            result = False
        writeCmpWrapper("EQ",arg1,arg2)   
    elif "InterleaveLO32x4" == op[4:]:#交叉组合
        if arg1 == 0 and arg2 == 0:
            return 0
        else:
            return interleaveLO32_4(arg1,arg2)#左边是源操作数，右边是目的操作数
    else:
        print "other binary operations"
        raise BaseException("other binary operations",op[4:])
    return result

def writeCmpWrapper(type,arg1,arg2):
    pointer1 = isPointer(arg1)
    pointer2 = isPointer(arg2)
    global signatureLength
    signatureLength = signatureLength + 1
    if pointer1 and pointer2:
        writeCmp(type, "pointer", "pointer")
    elif pointer1:
        writeCmp(type, "pointer", arg2)
    elif pointer2:
        writeCmp(type, arg1, "pointer")
    else:
        writeCmp(type, arg1, arg2)

def cmpGT64(bits,arg1,arg2):
    result = 0
    if bits == 8:
        value1_1 = c_byte(arg1 & 0xFF).value
        value2_1 = c_byte(arg2 & 0xFF).value
        arg1 = arg1 >> 8#8-15bit
        arg2 = arg2 >> 8
        value1_2 = c_byte(arg1 & 0xFF).value
        value2_2 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#16~23bit
        arg2 = arg2 >> 8
        value1_3 = c_byte(arg1 & 0xFF).value
        value2_3 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#24~31bit
        arg2 = arg2 >> 8
        value1_4 = c_byte(arg1 & 0xFF).value
        value2_4 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#32~39bit
        arg2 = arg2 >> 8
        value1_5 = c_byte(arg1 & 0xFF).value
        value2_5 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#40~47bit
        arg2 = arg2 >> 8
        value1_6 = c_byte(arg1 & 0xFF).value
        value2_6 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#48~55bit
        arg2 = arg2 >> 8
        value1_7 = c_byte(arg1 & 0xFF).value
        value2_7 = c_byte(arg1 & 0xFF).value
        arg1 = arg1 >> 8#56~63bit
        arg2 = arg2 >> 8
        value1_8 = c_byte(arg1 & 0xFF).value
        value2_8 = c_byte(arg1 & 0xFF).value
        flag8 = cmp(value1_8,value2_8)
        flag7 = cmp(value1_7,value2_7)
        flag6 = cmp(value1_6,value2_6)
        flag5 = cmp(value1_5,value2_5)
        flag4 = cmp(value1_4,value2_4)
        flag3 = cmp(value1_3,value2_3)
        flag2 = cmp(value1_2,value2_2)
        flag1 = cmp(value1_1,value2_1)
        if flag8 > 0:
            result = result | (1<<56)
        else:
            result = result | (0<<56)
        if flag7 > 0:
            result = result | (1<<48)
        else:
            result = result | (0<<48)
        if flag6 > 0:
            result = result | (1<<40)
        else:
            result = result | (0<<40)
        if flag5 > 0:
            result = result | (1<<32)
        else:
            result = result | (0<<32)
        if flag4 > 0:
            result = result | (1<<24)
        else:
            result = result | (0<<24)
        if flag3 > 0:
            result = result | (1<<16)
        else:
            result = result | (0<<16)
        if flag2 > 0:
            result = result | (1<<8)
        else:
            result = result | (0<<8)
        if flag1 > 0:
            result = result | (1<<0)
        else:
            result = result | (0<<0)            
        return result
    elif bits == 16:
        value1_1 = c_short(arg1 & 0xFFFF).value
        value2_1 = c_short(arg2 & 0xFFFF).value
        arg1 = arg1 >> 16#16-31bit
        arg2 = arg2 >> 16
        value1_2 = c_short(arg1 & 0xFFFF).value
        value2_2 = c_short(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16#32~47bit
        arg2 = arg2 >> 16
        value1_3 = c_short(arg1 & 0xFFFF).value
        value2_3 = c_short(arg1 & 0xFFFF).value
        arg1 = arg1 >> 16#48~63bit
        arg2 = arg2 >> 16
        value1_4 = c_short(arg1 & 0xFFFF).value
        value2_4 = c_short(arg1 & 0xFFFF).value            
        flag4 = cmp(value1_4,value2_4)
        flag3 = cmp(value1_3,value2_3)
        flag2 = cmp(value1_2,value2_2)
        flag1 = cmp(value1_1,value2_1)
        if flag4 > 0:
            result = result | (1<<48)
        else:
            result = result | (0<<48)
        if flag3 > 0:
            result = result | (1<<32)
        else:
            result = result | (0<<32)
        if flag2 > 0:
            result = result | (1<<16)
        else:
            result = result | (0<<16)
        if flag1 > 0:
            result = result | (1<<0)
        else:
            result = result | (0<<0)            
        return result
    elif bits == 32:
        value1_1 = c_int32(arg1 & 0xFFFFFFFF).value
        value2_1 = c_int32(arg2 & 0xFFFFFFFF).value
        arg1 = arg1 >> 32#32-63bit
        arg2 = arg2 >> 32
        value1_2 = c_int32(arg1 & 0xFFFFFFFF).value
        value2_2 = c_int32(arg1 & 0xFFFFFFFF).value

        flag2 = cmp(value1_2,value2_2)
        flag1 = cmp(value1_1,value2_1)
        if flag2 > 0:
            result = result | (1<<32)
        else:
            result = result | (0<<32)
        if flag1 > 0:
            result = result | (1<<0)
        else:
            result = result | (0<<0)            
        return result
        

def f64HItoV128(value1,value2):
    value1 = value1 << 64
    result = value1 | value2
    return result

def f64toI64S(encoding,value):
    if encoding == 0:#Round to nearest, ties to even
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_longlong(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_longlong(int(math.ceil(value))).value
        else:#.5出现的情形
            value1 = int(math.ceil(value))
            value2 = int(math.floor(value))
            if (value1 % 2) == 0:
                return c_longlong(int(math.ceil(value))).value
            else:
                return c_longlong(int(math.floor(value))).value
    elif encoding == 1:#Round to negative infinity
        return c_longlong(int(math.floor(value))).value
    elif encoding == 2:#Round to positive infinity
        return c_longlong(int(math.ceil(value))).value
    elif encoding == 3:#Round toward zero
        if value > 0:
            return c_longlong(int(math.floor(value))).value
        else:
            return c_longlong(int(math.ceil(value))).value
    elif encoding == 4:#Round to nearest, ties away from 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_longlong(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_longlong(int(math.ceil(value))).value
        else:#.5出现的情形
            if value < 0 :
                return c_longlong(int(math.floor(value))).value
            else:
                return c_longlong(int(math.ceil(value))).value
    elif encoding == 5:#Round to prepare for shorter precision
        return c_longlong(int(round(value))).value
    elif encoding == 6:#Round to away from 0
        if value < 0:
            return c_longlong(int(math.floor(value))).value
        else:
            return c_longlong(int(math.ceil(value))).value
    elif encoding == 7:#Round to nearest, ties towards 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_longlong(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_longlong(int(math.ceil(value))).value
        else:#.5出现的情形
            if value > 0 :
                return c_longlong(int(math.floor(value))).value
            else:
                return c_longlong(int(math.ceil(value))).value
    else:
        print "其他的近似方式"
        raise BaseException

def f64toI32S(encoding,value):
    if encoding == 0:#Round to nearest, ties to even
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_int32(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_int32(int(math.ceil(value))).value
        else:#.5出现的情形
            value1 = int(math.ceil(value))
            value2 = int(math.floor(value))
            if (value1 % 2) == 0:
                return c_int32(int(math.ceil(value))).value
            else:
                return c_int32(int(math.floor(value))).value
    elif encoding == 1:#Round to negative infinity
        return c_int32(int(math.floor(value))).value
    elif encoding == 2:#Round to positive infinity
        return c_int32(int(math.ceil(value))).value
    elif encoding == 3:#Round toward zero
        if value > 0:
            return c_int32(int(math.floor(value))).value
        else:
            return c_int32(int(math.ceil(value))).value
    elif encoding == 4:#Round to nearest, ties away from 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_int32(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_int32(int(math.ceil(value))).value
        else:#.5出现的情形
            if value < 0 :
                return c_int32(int(math.floor(value))).value
            else:
                return c_int32(int(math.ceil(value))).value
    elif encoding == 5:#Round to prepare for shorter precision
        return c_int32(int(round(value))).value
    elif encoding == 6:#Round to away from 0
        if value < 0:
            return c_int32(int(math.floor(value))).value
        else:
            return c_int32(int(math.ceil(value))).value
    elif encoding == 7:#Round to nearest, ties towards 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return c_int32(int(math.floor(value))).value
        elif abs(value11 - value) < abs(value22 - value):
            return c_int32(int(math.ceil(value))).value
        else:#.5出现的情形
            if value > 0 :
                return c_int32(int(math.floor(value))).value
            else:
                return c_int32(int(math.ceil(value))).value
    else:
        print "其他的近似方式"
        raise BaseException

def intOrFloatToFloat(encoding,value):
    if encoding == 0:#Round to nearest, ties to even
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return float(math.floor(value))
        elif abs(value11 - value) < abs(value22 - value):
            return float(math.ceil(value))
        else:#.5出现的情形
            value1 = int(math.ceil(value))
            value2 = int(math.floor(value))
            if (value1 % 2) == 0:
                return float(math.ceil(value))
            else:
                return float(math.floor(value))
    elif encoding == 1:#Round to negative infinity
        return float(math.floor(value))
    elif encoding == 2:#Round to positive infinity
        return float(math.ceil(value))
    elif encoding == 3:#Round toward zero
        if value > 0:
            return float(math.floor(value))
        else:
            return float(math.ceil(value))
    elif encoding == 4:#Round to nearest, ties away from 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return float(math.floor(value))
        elif abs(value11 - value) < abs(value22 - value):
            return float(math.ceil(value))
        else:#.5出现的情形
            if value < 0 :
                return float(math.floor(value))
            else:
                return float(math.ceil(value))
    elif encoding == 5:#Round to prepare for shorter precision
        return float(round(value))
    elif encoding == 6:#Round to away from 0
        if value < 0:
            return float(math.floor(value))
        else:
            return float(math.ceil(value))
    elif encoding == 7:#Round to nearest, ties towards 0
        value11 = math.ceil(value)
        value22 = math.floor(value)
        if abs(value11 - value) > abs(value22 - value):
            return float(math.floor(value))
        elif abs(value11 - value) < abs(value22 - value):
            return float(math.ceil(value))
        else:#.5出现的情形
            if value > 0 :
                return float(math.floor(value))
            else:
                return float(math.ceil(value))
    else:
        print "其他的近似方式"
        raise BaseException

def isClose(a, b, rel_tol=1e-09, abs_tol=0.0):
    return abs(a-b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)

def isNan(x):
    if math.isnan(x):
        return True
    else:
        return False
    
def get64HIto32(value1):
    value1 = c_ulonglong(value1).value
    return c_uint32(value1>>32).value

def get32HIto16(value1):
    value1 = c_uint32(value1).value
    return c_uint32(value1>>16).value
    
def toUShort(value):
    value = int(value & 0xFFFF)
    return c_ushort(value).value

def toUChar(value):
    value = int(value & 0xFF)
    return c_ubyte(value).value

def processUnopExpr(op,args):
    result = getArgValue(args[0])
    if ("1Uto32" in op[4:]) or ("1Uto8" in op[4:]) or ("1Uto64" in op[4:]):
        if result == True:
            return 1
        else:
            return 0
    elif "1Sto8" in op[4:]:
        if result == True:
            return 0xFF
        else:
            return 0
    elif "1Sto16" in op[4:]:
        if result == True:
            return 0xFFFF
        else:
            return 0
    elif "1Sto32" in op[4:]:
        if result == True:
            return 0xFFFFFFFF
        else:
            return 0
    elif "1Sto64" in op[4:]:
        if result == True:
            return 0xFFFFFFFFFFFFFFFF
        else:
            return 0
    elif "8Sto32" in op[4:]:
        value = c_int32(result<<24).value
        value = value >> 24
        return value
    elif ("8Sto64" in op[4:]):
        value = c_longlong(result << 56).value
        value = value >> 56
        return value
    elif "16Sto32" in op[4:]:
        value = c_int32(result<<16).value
        value = value >> 16
        return value
    elif ("8Uto32" in op[4:]) or ("8Uto64" in op[4:]) :
        return result & 0xFF
    elif ("8Uto16" in op[4:]):
        return result & 0xFF
    elif "8Sto16" in op[4:]:
        value = c_short(result<<8).value
        value = value >> 8
        return value
    elif "16Uto32" in op[4:]:
        return result & 0xFFFF
    elif ("16Uto64" in op[4:]):
        return result & 0xFFFF
    elif "32to16" in op[4:]:
        return toUShort(result)
    elif "32to8" in op[4:]:
        return toUChar(result)
    elif "32to1" in op[4:] or "64to1" in op[4:]:
        result = result & 1
        if result == 1:
            return True
        else:
            return False
    elif "NotV128" in op[4:]:
        return ~result
    elif "Not32" in op[4:] or "Not64" in op[4:]:
        return ~result
    elif "Not16" in op[4:]:
        return toUShort(~result)
    elif "Not8" in op[4:]:
        return toUChar(~result)
    elif "Not1" in op[4:]:
        if result == True:
            return False
        else:
            return True
    elif "64to8" in op[4:]:
        result = int(result & 0xFF)
        return c_ubyte(result).value
    elif "64to16" in op[4:]:
        result = int(result & 0xFFFF)
        return c_ushort(result).value
    elif "64to32" in op[4:]:
        return c_uint32(result & 0xFFFFFFFF).value
    elif "64HIto32" in op[4:]:
        return get64HIto32(result)    
    elif "32HIto16" in op[4:]:
        return get32HIto16(result)
    elif ("32Uto64" in op[4:]):
        return result & 0xFFFFFFFF
    elif ("16Sto64" in op[4:]):
        value = c_longlong(result << 48).value
        return value >> 48
    elif ("32Sto64" in op[4:]):
        value = c_longlong(result << 32).value
        return value >> 32#signed shift
    elif "16to8" in op[4:]:
        value = toUShort(result) & 0xFF
        return toUChar(value)
    elif "16HIto8" in op[4:]:
        value = (toUShort(result) >> 8) & 0xFF
        return toUChar(value)
    elif "CmpNEZ8" in op[4:]:
        value = result & 0xFF 
        if value != 0:
            return True
        else:
            return False
    elif "CmpNEZ32" in op[4:]:
        value = result & 0xFFFFFFFF
        if value != 0:
            return True
        else:
            return False
    elif "CmpNEZ64" in op[4:]:
        if result != 0:
            return True
        else:
            return False
    elif "CmpwNEZ32" in op[4:]:
        value = c_uint32(result).value
        if value == 0:
            return 0
        else:
            return 0xFFFFFFFF
    elif "CmpwNEZ64" in op[4:]:
        value = c_ulonglong(result).value
        if value == 0:
            return 0
        else:
            return 0xFFFFFFFFFFFFFFFF
    elif "Left32" in op[4:]:
        raise BaseException("Left32")
        return
    elif "Left64" in op[4:]:
        raise BaseException("Left64")
        return
    elif "Clz32" in op[4:]:
        value = c_uint32(result).value
        return fold_Clz32(value)
    elif "Clz64" in op[4:]:
        value = c_ulonglong(result).value
        return fold_Clz64(value)
    elif "32UtoV128" in op[4:]:
        value = c_uint32(result).value
        if value == 0:
            return 0
        else:
            return value
    elif "V128to64" in op[4:]:
        value = c_ushort(result).value
        if 0 == ((value >> 0) & 0xFF):
            return 0
        else:
            value = getLow64BitValue(result)
            return value
    elif "V128HIto64" in op[4:]:
        value = c_ushort(result).value
        if 0 == ((value >> 8) & 0xFF):
            return 0
        else:
            value = getHigh64BitValue(result)&0xFFFFFFFFFFFFFFFF
            return value
    elif "64UtoV128" in op[4:]:
        value = c_ulonglong(int(result)).value
        if value == 0:
            return 0
        else:
            return value    
    elif "V256to64_0" in op[4:] or "V256to64_1" in op[4:] or "V256to64_2" in op[4:] or "V256to64_3" in op[4:]:
        value = c_uint32(result).value
        if value == 0x00000000:
            return 0
        else:
            raise BaseException("V256to64_0")
    elif "ZeroHI64ofV128" in op[4:]:
        value = c_ushort(result).value
        if value == 0x0000:
            return 0x0000
        else:
            raise BaseException("ZeroHI64ofV128")
    elif "F32toF64" in op[4:]:
        return result
    elif "I32StoF64" in op[4:]:
        return float(result)
    elif "NegF64" in op[4:]:
        return -result
    elif "AbsF64" in op[4:]:
        return math.fabs(result)
    elif "ReinterpF64asI64" in op[4:]:
        return int(result)
    elif "ReinterpI64asF64" in op[4:]:
        return float(result)
    else:
        print "other processUnopExpr"
        raise BaseException("other unopExpr",op[4:])

def fold_Clz32(value):
    i = 0
    while i < 32:
        #if (0 != (value & (((UInt)1) << (31 - i)))) return i;
        shift =  c_uint32(1).value << (31 - i)
        result = value & shift
        if result != 0:
            return i
        i = i + 1
    return 0#正常不应该出现返回0的值

def fold_Clz64(value):
    i = 0
    while i < 64:
        #if (0 != (value & (((UInt)1) << (31 - i)))) return i;
        shift =  c_ulonglong(1).value << (63 - i)
        result = value & shift
        if result != 0:
            return i
        i = i + 1
    return 0#正常不应该出现返回0的值

def isPointer(value):
    global currentStartAddr
    if IsConstDataAddr(value):
        return True
    else:
        if value >= segment.codeSegment[0] and value < segment.codeSegment[1]:
            return True 
    return False

def processLoadExpr(expr):
    global currentStartAddr
    global signatureLength
    mem = 0
    if isinstance(expr,pyvex.IRExpr.RdTmp):
        mem = temporarySpace[int(expr.tmp)]#读值的地址
    elif isinstance(expr,pyvex.IRExpr.Const):
        mem = readValueFromConst(expr)#读值的地址
    if mem in memorySpace.keys():
        if mem > stackStartList[len(stackStartList) - 1]:
            signatureLength = signatureLength + 1
            if isPointer(memorySpace[mem]):
                writeIO("I","pointer")
            else:
                writeIO("I",memorySpace[mem])
        return memorySpace[mem]
    elif mem in constsSpace.keys():
        signatureLength = signatureLength + 1
        if isPointer(constsSpace[mem]):
            writeIO("I","pointer")
        else:
            writeIO("I",constsSpace[mem])
        return constsSpace[mem]
    else:#未知的地址值读取
        memorySpace[mem] = 0
        return 0        

def initFPU(tagname,row,column):
    registerNo = []
    for i in range(row):
        tempList = []
        for j in range(column):
            tempList.append(0)#0代表这个寄存器还没使用
        registerNo.append(tempList)
    return registerNo

def processGetIExpr(descr,ix,bias):
    index = str(descr).find(":")
    fpuTagReg = -1
    if index!=-1:
        fpuTagReg = int(str(descr)[0:index]) 
    else:
        print "error in GetIExpr"
    tagname = registerOffset.x86Offset[fpuTagReg]
    if fpuTagReg == 136:
        if tagname not in globalSpace.keys():
            fpuTag = initFPU(tagname,8,8)#8,8指的是二维数组8*8
            globalSpace[tagname] = fpuTag
        else:
            pass
        row = temporarySpace[int(ix.tmp)] + bias
        column = 0
        if row > 7:#同下面的情形相同
            row = 7
        return globalSpace[tagname][row][column]
    elif fpuTagReg == 72:
        offset = getValue(ix) + bias
        index = int(descr.base) + offset*8
        if index not in globalSpace.keys():
            globalSpace[index] = 1#由于函数仿真达到一定次数时，会强制退出，导致出现对未知浮点寄存器的使用
            if 'fpu_tags' not in globalSpace.keys():
                fpuTag = initFPU('fpu_tags',8,8)#8,8指的是二维数组8*8
                globalSpace['fpu_tags'] = fpuTag
            if offset > 7:#这个判断条件保证了当仿真异常时，程序不会崩溃。wget-gcc-O3地址80750DA处的语句由于上面的__assert_fail找不到函数实体，导致了ftop越界了
                offset = 7
            globalSpace['fpu_tags'][offset][0] = 1
            return globalSpace[index]
        else:
            return globalSpace[index]
    else:
        print "error in processGetIExpr"

def getValue(data):
    if isinstance(data,pyvex.expr.RdTmp):
        return readValueFromTmp(data)
    elif isinstance(data,pyvex.expr.Const):
        return readValueFromConst(data)

def processITEExpr(cond,iftrue,iffalse):
    condition = getValue(cond)
    result = 0
    if condition == True:
        result = getValue(iftrue)
    else:
        result = getValue(iffalse)
    return result

def getLow8BitValue(value):
    if isinstance(value,basestring):#如果是字符串,Python的字符串的基类是basestring，包括了str和unicode类型
        print "ord",ord(value[0])
        return ord(value[0])
    else:
        return value&255

def getLow16BitValue(value):
    return value&65535

#16bit值的高8位
def getLeft8BitValue(value):
    return value>>8

def getHigh64BitValue(value):
    return (value>>64)&0xFFFFFFFFFFFFFFFF

def getLow64BitValue(value):
    return (value)&0xFFFFFFFFFFFFFFFF

def getNewRegister(register):
    if register == "ah" or register == "eax":
        return "eax"
    elif register == "dh" or register == "edx":
        return "edx"
    elif register == "ch"or register == "ecx":
        return "ecx"

def updateRegisterArgsState(offset):
    global currentStartAddr
    global registerArgsState
    if offset >= 8 and offset < 24:
        if offset in registerOffset.x86Offset.keys():
            register = registerOffset.x86Offset[int(offset)]
            register = getNewRegister(register)
            argsList = registerArgsState[currentStartAddr]
            if register in argsList:#意味着这个参数寄存器已经被修改了
                registerArgsState[currentStartAddr].remove(register)
        else:
            raise BaseException("error in writeIOWhenRegisterArg")

def writeIOWhenRegisterArg(offset):
    global currentStartAddr
    global registerArgsState
    if offset >= 8 and offset < 24:
        if offset in registerOffset.x86Offset.keys():
            register = registerOffset.x86Offset[int(offset)]
            register = getNewRegister(register)
            argsList = registerArgsState[currentStartAddr]
            if register in argsList:#意味着这是一个参数
                writeIO("I", globalSpace[register])
        else:
            raise BaseException("error in writeIOWhenRegisterArg")
        
def processWrTmp(stmt):
    for expr in stmt.expressions:
        #print "type ",type(expr)
        if isinstance(expr, pyvex.IRExpr.Get):
            offset = expr.offset
            ty = expr.type
            writeIOWhenRegisterArg(offset)
            print expr.offset,ty#28,Ity_I32
            print stmt.data,stmt.tmp#0
            #栈帧的开始与结束设置
            number = int(expr.offset)
            if number not in registerOffset.x86Offset.keys():
                if number == 184:#高64位
                    if "xmm1" in globalSpace.keys():
                        value =  getHigh64BitValue(globalSpace["xmm1"])
                        temporarySpace[int(stmt.tmp)] = value
                    else:
                        temporarySpace[int(stmt.tmp)] = 0
                    return 
                
            if registerOffset.x86Offset[int(expr.offset)] == "esp":
                global stackEnd
                stackEnd = globalSpace[registerOffset.x86Offset[int(expr.offset)]]                    
            elif registerOffset.x86Offset[int(expr.offset)] == "ebp":
                global stackStart
                stackStart = globalSpace[registerOffset.x86Offset[int(expr.offset)]]
            if registerOffset.x86Offset[int(expr.offset)] in globalSpace.keys():
                value = globalSpace[registerOffset.x86Offset[int(expr.offset)]]
                if "I8" in str(stmt.data)[4:]:
                    result = getLow8BitValue(value)
                    temporarySpace[int(stmt.tmp)] = result
                elif "I16" in str(stmt.data)[4:]:
                    result = getLow16BitValue(value)
                    temporarySpace[int(stmt.tmp)] = result
                else:
                    temporarySpace[int(stmt.tmp)]=globalSpace[registerOffset.x86Offset[int(expr.offset)]]#t0 = GET:I32(offset=28),t0的临时变量值入栈
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "ah":
                if "ah" not in globalSpace.keys():
                    if "eax" in globalSpace.keys():
                        eax_tmp = globalSpace["eax"]
                        ax = getLow16BitValue(eax_tmp)
                        ah = getLeft8BitValue(ax)
                        temporarySpace[int(stmt.tmp)] = ah
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "bh":            
                if "bh" not in globalSpace.keys():
                    if "ebx" in globalSpace.keys():
                        ebx_tmp = globalSpace["ebx"]
                        bx = getLow16BitValue(ebx_tmp)
                        bh = getLeft8BitValue(bx)
                        temporarySpace[int(stmt.tmp)] = bh
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "dh":
                if "dh" not in globalSpace.keys():
                    if "edx" in globalSpace.keys():
                        edx_tmp = globalSpace["edx"]
                        dx = getLow16BitValue(edx_tmp)
                        dh = getLeft8BitValue(dx)
                        temporarySpace[int(stmt.tmp)] = dh
                return
            elif registerOffset.x86Offset[int(expr.offset)] == "ch":
                if "ch" not in globalSpace.keys():
                    if "ecx" in globalSpace.keys():
                        ecx_tmp = globalSpace["ecx"]
                        cx = getLow16BitValue(ecx_tmp)
                        ch = getLeft8BitValue(cx)
                        temporarySpace[int(stmt.tmp)] = ch
                return                
            elif registerOffset.x86Offset[int(expr.offset)]=="ftop":
                globalSpace["ftop"] = 7
                temporarySpace[int(stmt.tmp)] = globalSpace["ftop"] 
                return
            elif registerOffset.x86Offset[int(expr.offset)]=="gs":
                globalSpace["gs"] = 0
                temporarySpace[int(stmt.tmp)] = globalSpace["gs"] 
                return
            elif registerOffset.x86Offset[int(expr.offset)]=="ldt":
                globalSpace["ldt"] = 0
                temporarySpace[int(stmt.tmp)] = globalSpace["ldt"] 
                return
            elif registerOffset.x86Offset[int(expr.offset)]=="gdt":
                globalSpace["gdt"] = 0
                temporarySpace[int(stmt.tmp)] = globalSpace["gdt"] 
                return
            elif registerOffset.x86Offset[int(expr.offset)]=="fpround":
                globalSpace["fpround"] = 0
                temporarySpace[int(stmt.tmp)] = globalSpace["fpround"]
                return 
            if registerOffset.x86Offset[int(expr.offset)] not in globalSpace.keys():
                if registerOffset.x86Offset[int(expr.offset)]=="eax":
                    globalSpace["eax"] = 1
                    temporarySpace[int(stmt.tmp)] = globalSpace["eax"] 
                    return
                elif registerOffset.x86Offset[int(expr.offset)]=="d":
                    globalSpace["d"] = 1
                    temporarySpace[int(stmt.tmp)] = globalSpace["d"] 
                    return
                else:
                    globalSpace[registerOffset.x86Offset[int(expr.offset)]] = 0
                    temporarySpace[int(stmt.tmp)] = 0
                    return 
        elif isinstance(expr,pyvex.IRExpr.GetI):
            #print expr.descr, expr.ix, expr.bias
            status = processGetIExpr(expr.descr,expr.ix,expr.bias)
            temporarySpace[int(stmt.tmp)] = status
            return
        elif isinstance(expr,pyvex.IRExpr.Binop):
             result = processBinOp(expr.op, expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr,pyvex.IRExpr.Unop):
            result = processUnopExpr(expr.op, expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr,pyvex.IRExpr.Load):
            content = processLoadExpr(expr.addr)
            if isinstance(content,basestring):#有可能加载的是字符串的值
                content = ord(content[0])
            if expr.ty == "Ity_F64":
                temporarySpace[int(stmt.tmp)] = float(content)
            elif expr.ty == "Ity_F32":
                temporarySpace[int(stmt.tmp)] = float(content)
            elif expr.ty == "Ity_I8":
                result = getLow8BitValue(content)
                temporarySpace[int(stmt.tmp)] = result
            elif expr.ty == "Ity_I16":
                result = getLow16BitValue(content)
                temporarySpace[int(stmt.tmp)] = result
            elif expr.ty == "Ity_I32":
                temporarySpace[int(stmt.tmp)] = int(content)
            elif expr.ty == "Ity_I64":
                temporarySpace[int(stmt.tmp)] = int(content)
            else:
                temporarySpace[int(stmt.tmp)] = content
            return
        elif isinstance(expr, pyvex.IRExpr.RdTmp):
            temporarySpace[int(stmt.tmp)] = temporarySpace[int(expr.tmp)]
        elif isinstance(expr, pyvex.IRExpr.Const):
            con = expr.con
            if str(con) == "nan":
                x = float('nan')
                temporarySpace[int(stmt.tmp)] = x
            else:
                temporarySpace[int(stmt.tmp)] = con.value
                
        elif isinstance(expr, pyvex.IRExpr.ITE):
            result = processITEExpr(expr.cond,expr.iftrue,expr.iffalse)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr,pyvex.IRExpr.Triop):
            result = processTriOp(expr.op, expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr,pyvex.IRExpr.Qop):
            result = processQop(expr.op,expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        elif isinstance(expr, pyvex.IRExpr.CCall):
            #print expr.retty,expr.cee,expr.args
            result = processCCall(expr.retty,expr.cee,expr.args)
            temporarySpace[int(stmt.tmp)] = result
            return
        else:
            print "other:"
            print type(expr),expr.pp()

def processPut(stmt): 
    for expr in stmt.expressions:
        offset = int(stmt.offset)
        updateRegisterArgsState(offset)
        if isinstance(expr,pyvex.expr.RdTmp):
            value = temporarySpace[int(stmt.data.tmp)]
            if isinstance(value,basestring):#如果是字符串的话，仅转换第一个字符
                value = ord(value[0])
            if offset in registerOffset.x86Offset.keys():
                globalSpace[registerOffset.x86Offset[int(stmt.offset)]] = value
            else:
                globalSpace[offset] = value#offset有可能是xmm0的高64位，暂时还没有分配给具体的xmmi
        elif isinstance(expr,pyvex.expr.Const):
            #print "expr.con",expr.con
            if offset in registerOffset.x86Offset.keys():
                globalSpace[registerOffset.x86Offset[int(stmt.offset)]] = int(str(expr.con),16)#存储进去的是str，不知道是否要变成整数，暂时还没用到
            else:
                globalSpace[offset] = int(str(expr.con),16)#offset有可能是xmm0的高64位，暂时还没有分配给具体的xmmi,如accept_connection的804BEA9指令     
    if offset in registerOffset.x86Offset.keys():        
        if registerOffset.x86Offset[int(stmt.offset)] == "ebp":
            global ebp,stackStart
            ebp = globalSpace[registerOffset.x86Offset[int(stmt.offset)]]
            stackStart = globalSpace[registerOffset.x86Offset[int(stmt.offset)]]
        elif registerOffset.x86Offset[int(stmt.offset)] == "esp":
            global esp,stackEnd
            esp = globalSpace[registerOffset.x86Offset[int(stmt.offset)]]
            stackEnd = globalSpace[registerOffset.x86Offset[int(stmt.offset)]]
    else:
        pass
        
def readValueFromTmp(data):
    if int(data.tmp) in temporarySpace.keys():
        return temporarySpace[int(data.tmp)]
    else:
        return -1

def readValueFromConst(data):
    return int(str(data),16)

def processPutIStmt(stmt):
    offset = getValue(stmt.ix) + stmt.bias
    if int(stmt.descr.base)==72:
        
        index = int(stmt.descr.base) + offset*8
        source = getValue(stmt.data)
        globalSpace[index] = source
    elif int(stmt.descr.base)==136:
        tagname = registerOffset.x86Offset[136]
        if tagname not in globalSpace.keys():
            fpuTag = initFPU(tagname,8,8)#8,8指的是二维数组8*8
            globalSpace[tagname] = fpuTag
        else:
            pass
        result = getValue(stmt.data)
        if offset > 7:#同GetI中的情形相同
            offset = 7
        globalSpace[registerOffset.x86Offset[136]][offset][0] = result
    return

def IsConstDataAddr(addr):
    if (addr < segment.rodataSegment[1]) and (addr >= segment.rodataSegment[0]):
        return True
    elif (addr < segment.dataSegment[1]) and (addr >= segment.dataSegment[0]):
        return True
    elif (addr < segment.bssSegment[1]) and (addr >= segment.bssSegment[0]):
        return True
    else:
        return False

def processStore(stmt):
    global currentStartAddr
    global signatureLength
    global constsSpace
    value = 0
    if isinstance(stmt.data,pyvex.expr.RdTmp):
        value = readValueFromTmp(stmt.data)
    elif isinstance(stmt.data,pyvex.expr.Const):
        value = readValueFromConst(stmt.data)
    if IsConstDataAddr(value):#mov [esp],offset ABC中offset的特殊处理
        signatureLength = signatureLength + 1
        if value in constsSpace.keys():
            if isinstance(constsSpace[value],basestring):
                writeIO("I",constsSpace[value].strip())
            else:
                writeIO("I",constsSpace[value])
        else:
            writeIO("I", 0)
    addr = getValue(stmt.addr)
    if IsConstDataAddr(addr):#如果是常量地址，放到常量空间和普通地址空间
        constsSpace[addr] = value
        memorySpace[addr] = value
    else:
        if addr > stackStartList[len(stackStartList) - 1] and currentInstr not in pushAndCallList:
            signatureLength = signatureLength + 1
            if isPointer(value):
                writeIO("O","pointer")
            else:
                writeIO("O",value)
        memorySpace[addr] = value#如果是普通地址，放到普通地址空间 

def setPriorLoopFlag(addr,condition):
    global priorLoopFlag
    priorLoopFlag[addr] = condition
    
def removeLoopFlag(addr):
    global priorLoopFlag
    global blockLoopOrRecursion
    if addr in priorLoopFlag.keys():
        priorLoopFlag.pop(addr)
    if addr in blockLoopOrRecursion.keys():
        blockLoopOrRecursion.pop(addr)
    

def processExitStmt(stmt):
    condition = temporarySpace[int(stmt.guard.tmp)]
    global currentEmulatedBlock
    global currentNextIP#代表false的地址
    global currentInstr
    loopFlag = 0#0表示不是循环
    trueAddr = int(str(stmt.dst),16)#代表true的地址
    global priorLoopFlag
    #判断是否是循环
    if currentNextIP > trueAddr:
        if currentNextIP > currentEmulatedBlock and trueAddr <= currentEmulatedBlock:#无法解决rep指令的重复，如果要是修改，可以通过IMark的个数吧。
            loopFlag = 1#代表是循环
    else:
        if currentNextIP <= currentEmulatedBlock and trueAddr > currentEmulatedBlock:
            loopFlag = 1
    if currentNextIP > currentEmulatedBlock and trueAddr > currentEmulatedBlock:#这种情况比较少见，openssl中的gnames_stack_print函数
        loopFlag = 1
    if currentNextIP == trueAddr:#解决rep指令的IR表示中间出现if判断的情形
        loopFlag = 0
    if currentInstr == trueAddr:#在openssl-gcc-O3的aesni_xts_encrypt函数中，基本块IR中总出现if判断
        loopFlag = 0
    if loopFlag ==1: #碰到循环的处理
        incCountOfBlock(currentEmulatedBlock)
        if reachMaxCountOfBlock(currentEmulatedBlock):#达到了最大限制
            if condition == priorLoopFlag[currentEmulatedBlock]:
                condition = not condition
            removeLoopFlag(currentEmulatedBlock)#强制退出循环后需要处理的，有可能是循环嵌套的情形，不强制也需要删除
        else:
            setPriorLoopFlag(currentEmulatedBlock,condition)

    #退出循环的做法
    if condition == True:
        globalSpace[registerOffset.x86Offset[int(stmt.offsIP)]] = int(str(stmt.dst),16)
    else:
        globalSpace[registerOffset.x86Offset[int(stmt.offsIP)]] = 0#也可能需要改成不变eip的值
    return stmt.jk,condition
        
    
def setReturnAddr(value):
    if isinstance(value,pyvex.expr.RdTmp):
        globalSpace[registerOffset.x86Offset[68]] = readValueFromTmp(value)
    if isinstance(value, pyvex.expr.Const):
        globalSpace[registerOffset.x86Offset[68]] = readValueFromConst(value) 
        
def processCAS(stmt):
    print 'addr', 'dataLo', 'dataHi', 'expdLo', 'expdHi', 'oldLo', 'oldHi', 'end'
    print stmt.addr,stmt.dataLo,stmt.dataHi,stmt.expdLo,stmt.expdHi,stmt.oldLo,stmt.oldHi,stmt.end
    if stmt.end == "Iend_LE":
        if stmt.dataHi == None and stmt.expdHi == None:
            value_addr = getValue(stmt.addr)
            #value_old_lo = getValue(stmt.oldLo)
            value_exped_lo = getValue(stmt.expdLo)
            temporarySpace[int(stmt.oldLo)] = value_addr
            if value_addr == value_exped_lo:
                temporarySpace[int(stmt.addr.tmp)] = getValue(stmt.dataLo)#data里的新值放到addr中
             
def processDirty(tmpVariable,func,args,storeAddr):#转换64位浮点数成80位浮点数，le指的是小端
    print type(func)
    storeAddr = getValue(storeAddr)
    if func.name == "x86g_dirtyhelper_storeF80le":
        valueArg = args[1]
        value = getValue(valueArg)
        memorySpace[storeAddr] = value
    elif func.name == "x86g_dirtyhelper_loadF80le":
        temporarySpace[int(tmpVariable)] = memorySpace[storeAddr]

def emulateIR(irStmts):
    temporarySpace.clear()
    global switchFlag
    global currentInstr
    switchFlag = False
    type = ""
    for item in irStmts:
        if isinstance(item,pyvex.IRStmt.IMark):
            currentInstr = item.addr
            print "currentInstr",currentInstr
            if item.addr in switchJump.keys():
                switchFlag = True
            continue
        elif isinstance(item,pyvex.IRStmt.NoOp):
            raise BaseException("NoOp operation")
        elif isinstance(item,pyvex.IRStmt.AbiHint):
            raise BaseException("AbiHint operation")
        elif isinstance(item,pyvex.IRStmt.Put):
            processPut(item)
        elif isinstance(item,pyvex.IRStmt.PutI):
            processPutIStmt(item)
        elif isinstance(item,pyvex.IRStmt.WrTmp):#t0 = GET:I32等
            processWrTmp(item)
        elif isinstance(item,pyvex.IRStmt.Store):
            processStore(item)
        elif isinstance(item,pyvex.IRStmt.CAS):
            processCAS(item)
        elif isinstance(item,pyvex.IRStmt.LLSC):
            raise BaseException("LLSC operation")
        elif isinstance(item,pyvex.IRStmt.MBE):
            raise BaseException("MBE operation")
        elif isinstance(item,pyvex.IRStmt.Dirty):
            print "tmp","guard","cee","args",'mFx', 'mAddr', 'mSize', 'nFxState'
            print item.tmp,item.guard,item.cee,','.join(str(arg) for arg in item.args),item.mFx,item.mAddr,item.mSize,item.nFxState
            processDirty(item.tmp,item.cee,item.args,item.mAddr)
            #raise BaseException("Dirty operation")
        elif isinstance(item,pyvex.IRStmt.Exit):
            type,condition = processExitStmt(item)
            if "MapFail" in type[4:]:#Ijk_MapFail有可能在IR中间出现
                continue
            elif "SigSEGV" in type[4:]:
                continue #代表无效的地址，试图对只读映射区域进行写操作
            if condition == True:#条件变为true的时候就需要退出该基本块的仿真了
                return type
        elif isinstance(item,pyvex.IRStmt.LoadG):
            raise BaseException("LoadG operation")
        elif isinstance(item,pyvex.IRStmt.StoreG):
            raise BaseException("StoreG operation")
        else:
            pass  
    return type      


def initArgs(regArgs,stackArgs,randomValueList,startAddr):
    global ebpBased
    global argsDistributionIndex
    global randomValueList_same
    argsDistributionIndex = argsDistributionIndex % 10
    i = argsDistributionIndex * 15
    tempRegArgs = copy.deepcopy(regArgs)
    for arg in tempRegArgs:
        globalSpace[arg] = randomValueList[i]
        i = i + 1
    tempStackArgs = sorted(copy.deepcopy(stackArgs))
    if ebpBased[startAddr]:#ebp基于的函数由于被保存的寄存器ebp和函数返回地址的共同存在，导致访问的时候会使用ebp的地址，实际上是比栈要小4个地址
        newEBP = esp - 4        
        for arg in tempStackArgs:
            mem = arg + newEBP
            memorySpace[mem] = randomValueList[i]
            i = i + 1 
            if i >=200:
                raise BaseException("参数数量超过个!!!")
    else:
        newEBP = esp     
        for arg in tempStackArgs:
            mem = arg + newEBP
            memorySpace[mem] = randomValueList[i]
            i = i + 1 
            if i >=200:
                raise BaseException("参数数量超过个!!!")

#当一个函数不是被调用仿真时，那么其返回地址是有问题的，找不到改地址的函数
def setVirtualReturnAddress():
    memorySpace.clear()
    memorySpace[esp] = 0
    
def updateFPU(value):
    ftop = globalSpace["ftop"]
    ftop = ftop - 1;#设置新的栈顶用于存放库函数调用后的返回值
    globalSpace["ftop"] = ftop
    globalSpace[registerOffset.x86Offset[136]][ftop][0] = 1
    index = 72 + ftop * 8
    globalSpace[index] = value 
    
def updateEAX(value):
    globalSpace["eax"] = value

def getString1(addr):
    exit = False
    catString = ""
    sourceAddr = memorySpace[addr]
    while not exit:        
        if sourceAddr not in memorySpace.keys():
            memorySpace[sourceAddr] = 0
        source = memorySpace[sourceAddr]
        hexString = hex(source)[2:]
        while len(hexString)<8:#保证hexString的长度是8
            hexString  = '0' + hexString
        tmp = hexString[-2:]
        count = 1
        while tmp != "00":
            catString = catString + chr(int(tmp,16))
            hexString = hexString[0:7-2*count+1]
            tmp = hexString[-2:]
            count = count + 1
            if count == 5:
                sourceAddr = sourceAddr + 4                
                break
        if count < 5:
            exit = True
    return catString#发现00的时候意味着串的结束
    
def processLibFunc(funcName):
    global esp
    sourceAddr = esp + 4#获取库函数的参数
    if funcName == ".exit":
        return "exit"
    if funcName in libFuncs.libFuncsList:
        if funcName == ".sqrt":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_sqrt(source)
            updateFPU(result)
        elif funcName == ".abs":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_abs(source)
            updateEAX(result)
        elif funcName == ".rand":
            result = libFuncs.lib_rand()
            updateEAX(result)
        elif funcName == ".cabs":
            pass
        elif funcName == ".fabs":
            source =  memorySpace[sourceAddr]
            result = libFuncs.lib_fabs(source)
            updateFPU(result)
        elif funcName == ".labs":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_labs(source)
            updateEAX(value)#长整型的返回值不一定是eax
        elif funcName == ".exp":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_exp(source)
            updateFPU(result)
        elif funcName == ".frexp":
            source = memorySpace[sourceAddr]
            result1,result2 = libFuncs.lib_frexp(source,0)#已特殊处理，需要验证
            updateFPU(result1)
            source2 = memorySpace[sourceAddr + 8]
            memorySpace[source2] = result2
        elif funcName == ".ldexp":
            source = memorySpace[sourceAddr]#已特殊处理，需要验证
            source2 = memorySpace[sourceAddr + 8]
            result = libFuncs.lib_ldexp(source,source2)
            updateFPU(result)
        elif funcName == ".log":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_log(source)
            updateFPU(result)
        elif funcName == ".log10":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_log10(source)
            updateFPU(result)
        elif funcName == ".pow":#已特殊处理，需要验证
            source = memorySpace[sourceAddr]
            source2 = memorySpace[sourceAddr + 8]
            result = libFuncs.lib_pow(source,source2)
            updateFPU(result)
        elif funcName == ".pow10":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_pow10(source)
            updateFPU(result)
        elif funcName == ".acos":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_acos(source)
            updateFPU(result)
        elif funcName == ".asin":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_asin(source)
            updateFPU(result)
        elif funcName == ".atan":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_atan(source)
            updateFPU(result)
        elif funcName == ".atan2":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_atan2(source)
            updateFPU(result)
        elif funcName == ".cos":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_cos(source)
            updateFPU(result)
        elif funcName == ".sin":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_sin(source)
            updateFPU(result)
        elif funcName == ".tan":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_tan(source)
            updateFPU(result)
        elif funcName == ".cosh":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_cosh(source)
            updateFPU(result)
        elif funcName == ".sinh":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_sinh(source)
            updateFPU(result)
        elif funcName == ".tanh":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_tanh(source)
            updateFPU(result)
        elif funcName == ".hypot":
            source = memorySpace[sourceAddr]
            source2 = memorySpace[sourceAddr + 8]
            result = libFuncs.lib_hypot(source,source2)
            updateFPU(result)
        elif funcName == ".ceil":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_ceil(source)
            updateFPU(result)
        elif funcName == ".floor":
            source = memorySpace[sourceAddr]
            result = libFuncs.lib_floor(source)
            updateFPU(result)
        elif funcName == ".fmod":
            source = memorySpace[sourceAddr]
            source2 = memorySpace[sourceAddr + 8]
            result = libFuncs.lib_fmod(source,source2)
            updateFPU(result)
        elif funcName == ".modf":#已特殊实现，需要验证
            source = memorySpace[sourceAddr]
            result1,result2 = libFuncs.lib_modf(source,0)
            updateFPU(result1)
            source2 = memorySpace[sourceAddr + 8]
            memorySpace[source2] = result2
        elif funcName == ".strcmp":#两个参数是指针，需要两次的引用
            str1 = getString1(sourceAddr)
            str2 = getString1(sourceAddr + 4)
            result = cmp(str1,str2)
            globalSpace['eax'] = result        
    else:
        print "other case in processLibFunc",funcName

def reachMaxCountOfBlock(addr):
    global maxLoopOrRecursion
    if blockLoopOrRecursion[addr] < maxLoopOrRecursion:
        print "块循环次数",addr, blockLoopOrRecursion[addr]
        return False
    else:
        print "块循环次数",addr, blockLoopOrRecursion[addr]
        return True

def incCountOfBlock(addr):
    if addr not in blockLoopOrRecursion.keys():
        blockLoopOrRecursion[addr] = 1
    else:
        blockLoopOrRecursion[addr] = blockLoopOrRecursion[addr] + 1

def reachMaxCountOfFunction(addr):
    global maxLoopOrRecursion
    if addr not in funcLoopOrRecursion.keys():
        funcLoopOrRecursion[addr] = 1
    else:
        funcLoopOrRecursion[addr] = funcLoopOrRecursion[addr] + 1
    if funcLoopOrRecursion[addr] <= maxLoopOrRecursion:
        print "函数递归次数",addr, funcLoopOrRecursion[addr],False
        return False
    else:
        print "函数递归次数",addr, funcLoopOrRecursion[addr],True
        return True

def isUserFunc(addr):
    print "hanshu:", addr
    if addr in allUserFuncs:
        return True
    else:
        return False

def emulateFunctionAgain(db,startAddr,item):
    global stackStartList
    stackStartList = []
    name = item["name"]
    stackArgs = item["stackArgs"]#list
    registerArgs = item["registerArgs"]#list
    initEbpAndEsp()  
    setVirtualReturnAddress()
    globalSpace.clear()#这行和下一行换了位置
    randomValueCondition = {}
    randomValueCondition["name"] = name
    randomValueList = randomInput.getEmulationArgs()
    initArgs(registerArgs,stackArgs,randomValueList,startAddr)  
    funcLoopOrRecursion.clear()
    blockLoopOrRecursion.clear()
    consts = database.findAllConsts(db)
    loadConsttoMemory(consts)
    emulateFunction(db,startAddr)
    
def initialRegisterArgsState(startAddr):
    global functionArgs
    global registerArgsState#记录当前函数的寄存器参数使用情况
    if startAddr in functionArgs.keys():
        registerArgsState[startAddr] = functionArgs[startAddr][0]#dict值为list，list的第一个元素为寄存器参数list，有可能是空的list

def emulateFunction(db,startAddr):
    global esp
    global ebp
    global switchFlag
    global currentInstr
    global currentState
    global nextStartAddr#调用进入的函数开始地址
    global currentStartAddr
    global functionInfo
    global signatureLength
    initialRegisterArgsState(startAddr)
    nextStartAddr = startAddr
    #if not ebpBased[startAddr]:#不是ebp-based
    stackStartList.append(esp)
    if isUserFunc(startAddr) and reachMaxCountOfFunction(startAddr):#判断递归的可能有些问题，这里只是简单计数了函数的执行次数，可能需要用递归的深度，暂时还没有用到深度
        addrAfterCall = memorySpace[esp]#获取下一个要执行的地址
        esp = esp + 4#将压入的下一个语句的执行地址清空
        globalSpace[registerOffset.x86Offset[int(24)]] = esp
        globalSpace[registerOffset.x86Offset[68]] = addrAfterCall
        return "self-define return"
    globalSpace["ebp"]=ebp
    globalSpace["esp"]=esp
    exit = False
    blockAddr = startAddr
    currentStartAddr = startAddr
    endAddr = 0
    while(not exit):
        global currentEmulatedBlock
        currentEmulatedBlock = blockAddr
        #incCountOfBlock(blockAddr)
        findCondition = {}
        findCondition["start"] = blockAddr
        print "blockAddr",blockAddr
        block = database.findOneBlock(db,findCondition)
        if block == None:
            libCondition = {}
            libCondition["start"] = blockAddr
            libFunction = database.findOneLib(db,libCondition)
            if libFunction is not None:
                signatureLength = signatureLength + 1
                fwrite.write("LC " + libFunction["name"] + "\n")
                exit = processLibFunc(libFunction["name"])
                if exit == "exit":
                    currentState = "exit"
                    return "library exit"
                return "library return"#currentState = "Ijk_Ret"可能也需要加到return前面，如openssl的SortFnByName函数最后是一个jmp _strcmp
            else:#新增的分支，为了识别函数最后一条语句是align 10h这样的情形,还有jump eax的情形，如openssl的ui_close函数
                currentState = "Ijk_Ret"
                return "library return"
        endAddr = block["end"]
        binaryInstrs = eval(block["hexInstrs"])
        blockIR,jumpKind,nextIP = convertToIR.constructIR(binaryInstrs,blockAddr)
        global currentNextIP
        currentNextIP = getValue(nextIP)
        resultType = emulateIR(blockIR)
        if resultType == "Ijk_Boring":
            currentState = "Ijk_Boring"
            endAddr = int(block["end"])
            if globalSpace[registerOffset.x86Offset[68]]==0:                
                globalSpace[registerOffset.x86Offset[68]] = int(str(nextIP),16)
            blockAddr = globalSpace[registerOffset.x86Offset[68]]
        else:
            currentState = jumpKind
            if jumpKind == "Ijk_Ret":
                exit = True
                setReturnAddr(nextIP)
                signatureLength = signatureLength + 1
                if "eax" in globalSpace.keys():
                    if isPointer(globalSpace["eax"]):
                        writeIO("r", "pointer")
                    else:
                        writeIO("r",globalSpace["eax"])#函数返回值
                else:
                    writeIO("r", sys.maxint)#很可能该函数没有返回值，但是仍然为其赋值，因为目前不知道是否一个函数有返回值
                return "self-define return"
            elif jumpKind == "Ijk_Call":
                nextAddr = getValue(nextIP)
                returnType = emulateFunction(db,nextAddr)
                currentStartAddr = startAddr
                stackStartList.pop()#代表退出被调的函数
                if returnType == "library return":
                    esp = esp + 4#将压入的下一个语句的执行地址清空
                    global stackStart
                    stackStart = esp
                    globalSpace[registerOffset.x86Offset[int(24)]] = esp
                    condition = {}
                    condition["startAddr"] = blockAddr
                    cfgInfo = database.findOneCfg(db,condition)
                    if cfgInfo["num"] != 0:
                        blockAddr = endAddr
                        print "blockAddr:",blockAddr
                        print "startAddr:",startAddr
                        if blockAddr >= functionInfo[startAddr]:#为了防止函数最后一条语句为call 未知的函数时，避免发生仿真越界的现象。example:wget-gcc-O0 abort_run_with_timeout 在call _siglongjmp后越界
                            return#clang-O1中会出现startAddr并非真正函数开始地址的情况，还没定位出问题是什么，情况比较少见
                    else:
                        return
                elif returnType == "library exit":
                    return
                else:
                    blockAddr = globalSpace[registerOffset.x86Offset[68]]
            elif jumpKind == "Ijk_Boring":
                if switchFlag:
                    globalSpace["eip"] = switchJump[currentInstr]
                    blockAddr = switchJump[currentInstr]
                    switchFlag = False
                else:
                    blockAddr = getValue(nextIP)
            elif jumpKind == "Ijk_NoDecode":#无法译解
                blockAddr = int(endAddr)
                pass
            else:
                print "other in emulateFunction"
                
def loadConsttoMemory(consts):
    global constsSpace
    constsSpace.clear()
    for const in consts:
        addr = const["addr"]
        value = const["value"]
        constsSpace[addr]=value

def initEbpAndEsp():
    global esp
    global ebp
    ebp = 178956976
    esp = 178956970
    
def initSegment(db):
    condition = {}
    condition["name"] = "data"
    result = database.findOneSegment(db,condition)
    if result == None:
        segment.dataSegment.append(-1)
        segment.dataSegment.append(-1)
    else:
        segment.dataSegment.append(result["start"])
        segment.dataSegment.append(result["end"])
    condition.clear()    
    condition["name"] = "rodata"
    result = database.findOneSegment(db,condition)
    if result == None:
        segment.rodataSegment.append(-1)#可能程序就不包含.rodata区域
        segment.rodataSegment.append(-1)
    else:
        segment.rodataSegment.append(result["start"])
        segment.rodataSegment.append(result["end"])
    condition.clear()
    condition['name'] = "bss"
    result = database.findOneSegment(db,condition)
    if result == None:
        segment.bssSegment.append(-1)
        segment.bssSegment.append(-1)
    else:
        segment.bssSegment.append(result["start"])
        segment.bssSegment.append(result["end"])
    condition.clear()
    condition['name'] = "text"
    result = database.findOneSegment(db,condition)
    segment.codeSegment.append(result["start"])
    segment.codeSegment.append(result["end"])

def initialUserFuncs(db):
    global functionInfo#开始地址作为键，结束地址作为值
    funcs = database.findAllFunctions(db)
    for item1 in funcs:
        addr = item1["start"]
        allUserFuncs.add(addr)
        endAddr = item1["end"]
        functionInfo[addr] = endAddr
    funcs.close()

def initialPushAndCall(db):
    global pushAndCallList
    tempLists = database.findAllPushAndCall(db)
    for item in tempLists:
        pushAndCallList = item["addrs"]
    print "PushAndCall",pushAndCallList  

def loadSwitchJump(db):
    switchJump
    switchs = database.findAllSwitchs(db)
    for switch in switchs:
        switchJump[switch["stmtAddr"]] = switch["firstTarget"]

def getPath():
    return os.path.dirname(os.path.realpath(__file__)).strip()

def createSignatureDirectory(currentPath,directoryName):
    sysstr = platform.system()
    directory = currentPath
    if(sysstr =="Windows"):
        directory = directory + "\\" + directoryName
    elif(sysstr == "Linux"):
        directory = directory + "/" + directoryName
    else:
        directory = directory + "/" + directoryName
    isExists=os.path.exists(directory)
    if isExists:
        shutil.rmtree(directory)
    os.mkdir(directory)
    return directory

def generateFilePath(currentPath,fileName):
    sysstr = platform.system()
    filePath = currentPath
    if(sysstr =="Windows"):
        filePath = filePath + "\\" + fileName + ".txt"
    elif(sysstr == "Linux"):
        filePath = filePath + "/" + fileName + ".txt"
    else:
        filePath = filePath + "/" + fileName + ".txt"
    return filePath    

def initialEbpBased(funcs):
    for fun in funcs:        
        ebpBased[fun["start"]] = fun["ebpBased"]

def initialRegisterArgs(funcs):
    global functionArgs
    for func in funcs:
        tempList = []
        tempList.append(func["registerArgs"])#tempList的第一个元素是寄存器参数列表
        tempList.append(func["stackArgs"])#tempList的第二个元素是栈参数列表
        functionArgs[func["start"]] = tempList
        

def resetAllGlobalVariables():
    ls = os.linesep
    global currentEmulatedBlock,currentNextIP,maxLoopOrRecursion,funcLoopOrRecursion,blockLoopOrRecursion,priorLoopFlag,allUserFuncs
    global stackStart,stackStartList,stackEnd,stackArgs,registerArgs,temporarySpace,globalSpace,memorySpace,constsSpace,switchJump
    global ebpBased,switchFlag,currentInstr,currentState,nextStartAddr,currentStartAddr,ebp,esp,nan,emulateAll,emulateAddr,emulateFunctions
    global childPath,pushAndCallList,functionInfo,signatureLength,argsDistributionIndex,randomValueList_same,functionArgs,registerArgsState
    global isVulnerabilityProgram,programName,fileName,db,fwrite
    currentEmulatedBlock = 0#用块的开始地址表示
    currentNextIP = 0#用块的开始地址表示，循环两个分支一个地址更高，一个地址更低（会包含等于的情况）
    maxLoopOrRecursion = 5
    funcLoopOrRecursion = {}#递归计数使用
    blockLoopOrRecursion = {}#块循环计数使用
    priorLoopFlag = {}
    allUserFuncs = set()
    stackStart = 0#ebp-based 函数使用，根据ebp指定,不用这个了，因为即使是ebp-based的函数也可能没有put(ebp)这样的IR出现
    stackStartList = []#非 ebp-based 函数使用，根据函数开始时的esp指定
    stackEnd = 0#无论是否是ebp-based的函数均可使用,永远有esp指定
    stackArgs = []
    registerArgs = []
    temporarySpace = {}
    globalSpace = {}
    memorySpace= {}
    constsSpace = {}
    switchJump = {}
    ebpBased = {}
    switchFlag = False
    currentInstr = 0
    currentState = ""
    nextStartAddr = 0
    currentStartAddr = 0
    ebp = 178956976
    esp = 178956970
    nan = float('nan')
    emulateAll = False
    emulateAddr = 0
    emulateFunctions = set()
    childPath = "signature"
    pushAndCallList = []
    functionInfo = {}
    signatureLength = 0
    argsDistributionIndex = 0
    randomValueList_same = []
    functionArgs = {}
    registerArgsState = {}
    isVulnerabilityProgram = False
    programName = ""
    fileName = ""
    db = 0
    fwrite = 0

def emulateSpecifiedFunction(directory,proName,fiName,funcName,calledFrom = 1):#calledFrom=1指的是从读入候选文件时仿真的，calledFrom=2指的是为漏洞生成签名
    resetAllGlobalVariables()
    global programName,fileName,isVulnerabilityProgram
    programName = proName
    fileName = fiName
    global db,fwrite

    if calledFrom == 2:
        isVulnerabilityProgram = True
    print isVulnerabilityProgram,programName,fileName
    db,client = database.connectDB(isVulnerabilityProgram,False,programName,fileName)
    functions = database.findAllFunctions(db)
    initialUserFuncs(db)
    initialPushAndCall(db)
    initialEbpBased(copy.deepcopy(functions))
    initialRegisterArgs(copy.deepcopy(functions))
    initSegment(db)
    loadSwitchJump(db)
    fwrite = 0
    fwrite1 = open("function.txt",'a')    
    starttime = datetime.datetime.now()
    fwrite1.write("start time:" + str(starttime) + "\n")
    functionCondition = {}
    functionCondition["name"] = funcName
    item = database.findOneFunction(db,functionCondition)
    if item == None:#表示该路径下没有这个函数
        fwrite_wrongpath = open("wrong_function_path.txt",'a')
        fwrite_wrongpath.write("can not find this function" + "\tprogram name:" + proName + "\tfile name:" + fiName + "\tfunction name:" + funcName + "\n")
        fwrite_wrongpath.close()
        return "wrong"
    try:
        global signatureLength
        global argsDistributionIndex
        global globalSpace
        global emulateFunctions
        signatureLength = 0    
        argsDistributionIndex = 0
        startAddr = item["start"]
        name = item["name"]
        stackArgs = item["stackArgs"]#list
        registerArgs = item["registerArgs"]#list
        initEbpAndEsp()  
        setVirtualReturnAddress()
        globalSpace.clear()#这行和下一行换了位置
        randomValueCondition = {}
        randomValueCondition["name"] = "sameRandomValueList"
        randomValueList = randomInput.getEmulationArgs()
        initArgs(registerArgs,stackArgs,randomValueList,startAddr)  
        funcLoopOrRecursion.clear()
        blockLoopOrRecursion.clear()
        consts = database.findAllConsts(db)
        loadConsttoMemory(consts)
        fileWritePosition = generateFilePath(directory, programName + "+" + fileName + "+" + item["name"])
        fwrite = open(fileWritePosition, 'w')
        print "仿真函数", hex(item["start"]),item["start"],item["name"]
        emulateFunctions.add(startAddr)
        emulateFunction(db, startAddr)
        while signatureLength < 20:
            argsDistributionIndex = argsDistributionIndex + 1
            emulateFunctionAgain(db,startAddr,item)
    except BaseException,e:
        if startAddr in emulateFunctions:
            print "仿真失败"
            fwrite1.write(item["name"]+"    " + "fail" + str(startAddr) + "\n")
            fwrite1.flush()
            print 'str(Exception):\t', str(Exception)
            print 'str(e):\t\t', str(e)
            print 'repr(e):\t', repr(e)
            print 'e.message:\t', e.message
            print 'traceback.print_exc():'; traceback.print_exc()
            print 'traceback.format_exc():\n%s' % traceback.format_exc()
            fwrite.flush()
            fwrite.close()
    else:
        if startAddr in emulateFunctions:
            global currentState
            print "仿真成功"
            print item["name"], "    ", "success ", currentState
            fwrite1.write(item["name"]+"    " + "success " + currentState + "\n")
            fwrite1.flush()
            fwrite.flush()
            fwrite.close()
    functions.close()
    print ">>>>>Emulation end!<<<<<"
    endtime = datetime.datetime.now()
    fwrite1.write("end time:" + str(endtime) + "\n")
    timeDiff = (endtime - starttime).seconds
    print type(timeDiff),timeDiff
    fwrite1.write("time diff:" + str(timeDiff) + "\n")
    fwrite1.close()
    database.closeConnect(client)
    client = None
    
def parseArgs(args):
    global emulateAll,programName
    global emulateAddr,fileName
    global childPath,isVulnerabilityProgram
    argList = args[1:]
    presetArgs = ["--childPath","--addr","--type","--path","--file"]
    requiredArgs = ["--path","--file"]
    acquiredArgs = []
    for arg in argList:
        tempList = arg.split('=')
        acquiredArgs.append(tempList[0])
    for arg in requiredArgs:
        if arg not in acquiredArgs:
            print "请指定--path=programName 和 --file=fileName 参数"
            exit()
    for i in range(len(argList)):
        arg = argList[i]
        index = arg.find("=")
        if index == -1:
            print "参数设置不合理，\'=\'左右没有空格"
            exit()
        leftSide = arg[0:index]
        rightSide = arg[index+1:]
        if leftSide not in presetArgs:
            print "没有参数[ ",i," ],请重新指定--all,--childPath参数"
            exit()

        if leftSide == "--childPath":
            childPath = rightSide
        elif leftSide == "--addr":
            emulateAddr = int(rightSide)
            emulateAll = False
        elif leftSide == "--type":
            if rightSide in ["V","v"]:
                isVulnerabilityProgram = True
        elif leftSide == "--path":
            programName = rightSide
        elif leftSide == "--file":
            fileName = rightSide     

if __name__ == '__main__':
    if len(sys.argv) <4:
        print "参数太少了，请指定[--addr=13565443] --childPath=signature-gcc-O0"
        exit()
    else:
        parseArgs(sys.argv)
        global db,fwrite
        currentDirectory = getPath()
        directory = createSignatureDirectory(currentDirectory,childPath)
        db,client = database.connectDB(isVulnerabilityProgram,False,programName,fileName)
        functions = database.findAllFunctions(db)
        initialUserFuncs(db)
        initialPushAndCall(db)
        initialEbpBased(copy.deepcopy(functions))
        initialRegisterArgs(copy.deepcopy(functions))
        initSegment(db)
        loadSwitchJump(db)
        fwrite = 0
        fwrite1 = open("function.txt",'w')    
        starttime = datetime.datetime.now()
        fwrite1.write("start time:" + str(starttime) + "\n")
        for item in functions:    
            try:
                global signatureLength
                global argsDistributionIndex
                global globalSpace
                global emulateFunctions
                signatureLength = 0    
                argsDistributionIndex = 0
                startAddr = item["start"]
                name = item["name"]
                stackArgs = item["stackArgs"]#list
                registerArgs = item["registerArgs"]#list
                initEbpAndEsp()  
                setVirtualReturnAddress()
                globalSpace.clear()#这行和下一行换了位置
                randomValueCondition = {}
                randomValueCondition["name"] = "sameRandomValueList"
                randomValueList = randomInput.getEmulationArgs()
                initArgs(registerArgs,stackArgs,randomValueList,startAddr)  
                funcLoopOrRecursion.clear()
                blockLoopOrRecursion.clear()
                consts = database.findAllConsts(db)
                loadConsttoMemory(consts)
                if emulateAll == False:
                    if startAddr == emulateAddr:
                        fileWritePosition = generateFilePath(directory,item["name"])
                        fwrite = open(fileWritePosition, 'w')
                        print "仿真函数", hex(item["start"]),item["start"],item["name"]
                        emulateFunctions.add(startAddr)
                        emulateFunction(db,startAddr)
                        while signatureLength < 20:
                            argsDistributionIndex = argsDistributionIndex + 1
                            emulateFunctionAgain(db,startAddr,item)
                else:
                    fileWritePosition = generateFilePath(directory,item["name"])
                    fwrite = open(fileWritePosition, 'w')
                    print "仿真函数", hex(item["start"]),item["start"],item["name"]
                    emulateFunctions.add(startAddr)
                    emulateFunction(db, startAddr)
                    while signatureLength < 20:
                        argsDistributionIndex = argsDistributionIndex + 1
                        emulateFunctionAgain(db,startAddr,item)
            except BaseException,e:
                print "仿真失败"
                if startAddr in emulateFunctions:
                    print "仿真失败"
                    fwrite1.write(item["name"]+"    " + "fail" + str(startAddr) + "\n")
                    fwrite1.flush()
                    print 'str(Exception):\t', str(Exception)
                    print 'str(e):\t\t', str(e)
                    print 'repr(e):\t', repr(e)
                    print 'e.message:\t', e.message
                    print 'traceback.print_exc():'; traceback.print_exc()
                    print 'traceback.format_exc():\n%s' % traceback.format_exc()
                    fwrite.flush()
                    fwrite.close()
            else:
                if startAddr in emulateFunctions:
                    global currentState
                    print "仿真成功"
                    print item["name"], "    ", "success ", currentState
                    fwrite1.write(item["name"]+"    " + "success " + currentState + "\n")
                    fwrite1.flush()
                    fwrite.flush()
                    fwrite.close()
        functions.close()
        print ">>>>>Emulation end!<<<<<"
        endtime = datetime.datetime.now()
        fwrite1.write("end time:" + str(endtime) + "\n")
        timeDiff = (endtime - starttime).seconds
        print type(timeDiff),timeDiff
        fwrite1.write("time diff:" + str(timeDiff) + "\n")
        fwrite1.close()
        database.closeConnect(client)
        client = None