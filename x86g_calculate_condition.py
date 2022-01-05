#-*- coding: utf-8 -*-
from x86_eflags_defs import *
from x86_op_condition import *
from ctypes import *

def getRes_New(bits,res):
    if bits == 8:
        return int((res)&255)
    elif bits == 16:
        return int((res)&65535)
    elif bits == 32:
        return int((res)&4294967295L)

def actions_add(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    argL = int(CC_DEP1&4294967295L)
    argR = int(CC_DEP2&4294967295L)
    res = int((argL + argR)&4294967295L)
    res_new = getRes_New(bits,res)
    argL_new = getRes_New(bits,argL)
    if res_new < argL_new:
        cf = 1
    pf = parity_table[int(res&255)]
    af = (res ^ argL ^ argR) & 0x10
    if res_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(res, 8 - bits) & 0x80
    of = lshift((argL ^ argR ^ (-1)) & (argL ^ res),12 - bits) & X86G_CC_MASK_O
    return cf | pf | af | zf | sf | of

def actions_sub(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    argL = int(CC_DEP1&4294967295L)
    argR = int(CC_DEP2&4294967295L)
    res = int((argL - argR)&4294967295L)
    res_new = getRes_New(bits,res)
    argL_new = getRes_New(bits,argL)
    argR_new = getRes_New(bits, argR)
    if argL_new < argR_new:
        cf = 1
    pf = parity_table[int(res&255)]
    af = (res ^ argL ^ argR) & 0x10
    if res_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(res, 8 - bits) & 0x80
    of = lshift(((argL ^ argR) ^ (argL ^ res)) & (argL ^ res),12 - bits) & X86G_CC_MASK_O
    return cf | pf | af | zf | sf | of

def actions_adc(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    oldC = int(CC_NDEP & X86G_CC_MASK_C & 4294967295L)
    argL = int(CC_DEP1&4294967295L)
    argR = int((CC_DEP2^oldC)&4294967295L)
    res = int((argL + argR + oldC)&4294967295L)
    res_new = getRes_New(bits,res)
    argL_new = getRes_New(bits,argL)
    if oldC == 0:
        if res_new < argL_new:
            cf = 1
    else:
        if res_new <= argL_new:
            cf = 1
    pf = parity_table[int(res&255)]
    af = (res ^ argL ^ argR) & 0x10
    if res_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(res, 8 - bits) & 0x80
    of = lshift((argL ^ argR ^ (-1)) & (argL ^ res),12 - bits) & X86G_CC_MASK_O
    return cf | pf | af | zf | sf | of
        
def actions_sbb(bits,CC_DEP1,CC_DEP2,CC_NDEP):        
    SIGN_MASK = 1 << (bits -1)
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    oldC = int(CC_NDEP & X86G_CC_MASK_C & 4294967295L)
    argL = int(CC_DEP1&4294967295L)
    argR = int((CC_DEP2 ^ oldC)&4294967295L)
    res = int((argL - argR - oldC)&4294967295L)
    res_new = getRes_New(bits,res)
    argL_new = getRes_New(bits,argL)
    argR_new = getRes_New(bits, argR)
    if oldC == 0:
        if argL_new < argR_new:
            cf = 1
    else:
        if argL_new <= argR_new:
            cf = 1
    pf = parity_table[int(res&255)]
    af = (res ^ argL ^ argR) & 0x10
    if res_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(res, 8 - bits) & 0x80
    of = lshift((argL ^ argR ) & (argL ^ res),12 - bits) & X86G_CC_MASK_O
    return cf | pf | af | zf | sf | of

def actions_logic(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = parity_table[int(CC_DEP1&255)]
    af = 0
    CC_DEP1_new = getRes_New(bits, CC_DEP1)
    if CC_DEP1_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(CC_DEP1, 8 - bits) & 0x80    
    return cf | pf | af | zf | sf | of

def actions_inc(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    DATA_MASK = 0
    if bits == 8:
        DATA_MASK = 0xFF
    elif bits == 16:
        DATA_MASK = 0xFFFF
    else:
        DATA_MASK = 0xFFFFFFFF
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    res = int(CC_DEP1&4294967295L)
    argL = int((res - 1)&4294967295L)
    argR = 1
    res_new = getRes_New(bits,res)
    cf = int(CC_NDEP & X86G_CC_MASK_C&4294967295L)
    pf = parity_table[int(res&255)]
    af = (res ^ argL ^ argR) & 0x10
    if res_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(res, 8 - bits) & 0x80
    if (res & DATA_MASK) == SIGN_MASK:
        of = 1<<11
    else:
        of = 0<<11
    return cf | pf | af | zf | sf | of

def actions_dec(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    DATA_MASK = 0
    if bits == 8:
        DATA_MASK = 0xFF
    elif bits == 16:
        DATA_MASK = 0xFFFF
    else:
        DATA_MASK = 0xFFFFFFFF
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    res = int(CC_DEP1&4294967295L)
    argL = int((res + 1)&4294967295L)
    argR = 1
    res_new = getRes_New(bits,res)
    cf = int(CC_NDEP & X86G_CC_MASK_C & 4294967295L)
    pf = parity_table[int(res&255)]
    af = (res ^ argL ^ argR) & 0x10
    if res_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(res, 8 - bits) & 0x80
    if (res & DATA_MASK) == (SIGN_MASK - 1):
        of = 1<<11
    else:
        of = 0<<11
    return cf | pf | af | zf | sf | of

def actions_shl(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    DATA_MASK = 0
    if bits == 8:
        DATA_MASK = 0xFF
    elif bits == 16:
        DATA_MASK = 0xFFFF
    else:
        DATA_MASK = 0xFFFFFFFF
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    res = int(CC_DEP1&4294967295L)
    argL = int((res + 1)&4294967295L)
    argR = 1
    CC_DEP1_new = getRes_New(bits,CC_DEP1)
    cf = int((CC_NDEP >> (bits -1)) & X86G_CC_MASK_C & 4294967295L)
    pf = parity_table[int(CC_DEP1&255)]
    af = 0
    if CC_DEP1_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(CC_DEP1, 8 - bits) & 0x80
    of = lshift(CC_DEP2 ^ CC_DEP1,12-bits) & X86G_CC_MASK_O
    return cf | pf | af | zf | sf | of

def actions_shr(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    DATA_MASK = 0
    if bits == 8:
        DATA_MASK = 0xFF
    elif bits == 16:
        DATA_MASK = 0xFFFF
    else:
        DATA_MASK = 0xFFFFFFFF
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    res = int(CC_DEP1&4294967295L)
    argL = int((res + 1)&4294967295L)
    argR = 1
    CC_DEP1_new = getRes_New(bits,CC_DEP1)
    cf = int((CC_DEP2 & 1) & 4294967295L)
    pf = parity_table[int(CC_DEP1&255)]
    af = 0
    if CC_DEP1_new == 0:
        zf = 1<<6
    else:
        zf = 0<<6
    sf = lshift(CC_DEP1, 8 - bits) & 0x80
    of = lshift(CC_DEP2 ^ CC_DEP1,12-bits) & X86G_CC_MASK_O
    return cf | pf | af | zf | sf | of

def actions_rol(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    DATA_MASK = 0
    if bits == 8:
        DATA_MASK = 0xFF
    elif bits == 16:
        DATA_MASK = 0xFFFF
    else:
        DATA_MASK = 0xFFFFFFFF
    fl = (CC_NDEP & ~(X86G_CC_MASK_O | X86G_CC_MASK_C)) | (X86G_CC_MASK_C & CC_DEP1)|(X86G_CC_MASK_O & (lshift(CC_DEP1,11-(bits-1))^ lshift(CC_DEP1, 11)))
    return int(fl & 4294967295L)

def actions_ror(bits,CC_DEP1,CC_DEP2,CC_NDEP):
    SIGN_MASK = 1 << (bits -1)
    DATA_MASK = 0
    if bits == 8:
        DATA_MASK = 0xFF
    elif bits == 16:
        DATA_MASK = 0xFFFF
    else:
        DATA_MASK = 0xFFFFFFFF
    f1 = (CC_NDEP & ~(X86G_CC_MASK_O | X86G_CC_MASK_C))|(X86G_CC_MASK_C & (CC_DEP1 >> (bits-1)))|(X86G_CC_MASK_O & (lshift(CC_DEP1,11-(bits-1)) ^ lshift(CC_DEP1, 11-(bits-1)+1)))
    return int(f1 & 4294967295L)

#ACTIONS_UMUL( 32, UInt, toUInt, ULong,  idULong );
def actions_umul(bits,CC_DEP1,CC_DEP2,CC_NDEP,DATA_UTYPE, NARROWtoU, DATA_U2TYPE, NARROWto2U):
    SIGN_MASK = 1 << (bits -1)
    DATA_MASK = 0
    if bits == 8:
        DATA_MASK = 0xFF
    elif bits == 16:
        DATA_MASK = 0xFFFF
    else:
        DATA_MASK = 0xFFFFFFFF
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    af = 0
    hi = 0
    lo = 0
    rr = 0
    CC_DEP1_1 = 0
    CC_DEP2_1 = 0
    if DATA_UTYPE == "UInt":
        CC_DEP1_1 = c_uint32(CC_DEP1).value
        CC_DEP2_1 = c_uint32(CC_DEP2).value
        result_1 = CC_DEP1_1 * CC_DEP2_1
        lo = c_uint32(result_1).value
    elif DATA_UTYPE == "UShort":
        CC_DEP1_1 = c_ushort(CC_DEP1).value
        CC_DEP2_1 = c_ushort(CC_DEP2).value
        result_1 = CC_DEP1_1 * CC_DEP2_1
        lo = c_ushort(result_1).value
    elif DATA_UTYPE == "UChar":
        CC_DEP1_1 = c_ubyte(CC_DEP1).value
        CC_DEP2_1 = c_ubyte(CC_DEP2).value
        result_1 = CC_DEP1_1 * CC_DEP2_1
        lo = c_ubyte(result_1).value
    if DATA_U2TYPE == "ULong":
        CC_DEP1_2 = c_ulonglong(CC_DEP1_1).value
        CC_DEP2_2 = c_ulonglong(CC_DEP2_1).value
        result_2 = CC_DEP1_2 * CC_DEP2_2
        rr = c_ulonglong(result_2).value
    elif DATA_U2TYPE == "UInt":
        CC_DEP1_2 = c_uint32(CC_DEP1_1).value
        CC_DEP2_2 = c_uint32(CC_DEP2_1).value
        result_2 = CC_DEP1_2 * CC_DEP2_2
        rr = c_uint32(result_2).value
    elif DATA_U2TYPE == "UShort":
        CC_DEP1_2 = c_ushort(CC_DEP1_1).value
        CC_DEP2_2 = c_ushort(CC_DEP2_1).value
        result_2 = CC_DEP1_2 * CC_DEP2_2
        rr = c_ushort(result_2).value
    if DATA_UTYPE == "UInt":
        hi = c_uint32(rr >> bits).value
    elif DATA_UTYPE == "UShort":
        hi = c_ushort(rr >> bits).value        
    elif DATA_UTYPE == "UChar":
        hi = c_ubyte(rr >> bits).value
    if hi != 0:
        cf = 1
    pf = parity_table[int(c_ubyte(lo).value)]
    if lo == 0:
        zf = 1 << 6
    else:
        zf = 0 << 6
    sf = lshift(lo,8 - bits) & 0x80
    of = cf << 11
    return cf | pf | af | zf | sf | of
    
    
#Calculate all the 6 flags from the supplied thunk parameters. Worker function, not directly called from generated code. 
def x86g_calculate_eflags_all_WRK(cc_op,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal):
    op_str = X86CCop[cc_op]
    if op_str == "X86G_CC_OP_COPY":
        return cc_dep1_formal & (X86G_CC_MASK_O | X86G_CC_MASK_S | X86G_CC_MASK_Z | X86G_CC_MASK_A | X86G_CC_MASK_C | X86G_CC_MASK_P)
    elif op_str == "X86G_CC_OP_ADDB":
        return actions_add(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_ADDW":
        return actions_add(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_ADDL":
        return actions_add(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_ADCB":
        return actions_adc(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_ADCW":
        return actions_adc(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_ADCL":
        return actions_adc(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SUBB":
        return actions_sub(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SUBW":
        return actions_sub(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SUBL":
        return actions_sub(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SBBB":
        return actions_sbb(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SBBW":
        return actions_sbb(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SBBL":
        return actions_sbb(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_LOGICB":
        return actions_logic(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_LOGICW":
        return actions_logic(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_LOGICL":
        return actions_logic(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_INCB":
        return actions_inc(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_INCW":
        return actions_inc(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_INCL":
        return actions_inc(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_DECB":
        return actions_dec(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_DECW":
        return actions_dec(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_DECL":
        return actions_dec(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SHLB":
        return actions_shl(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SHLW":
        return actions_shl(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SHLL":
        return actions_shl(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SHRB":
        return actions_shr(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SHRW":
        return actions_shr(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_SHRL":
        return actions_shr(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_ROLB":
        return actions_rol(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_ROLW":
        return actions_rol(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_ROLL":
        return actions_rol(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_RORB":
        return actions_ror(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_RORW":
        return actions_ror(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_RORL":
        return actions_ror(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal)
    elif op_str == "X86G_CC_OP_UMULB":
        #actions_umul(8)
        return actions_umul(8,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal,"UChar", "toUChar", "UShort","toUShort")
    elif op_str == "X86G_CC_OP_UMULW":
        return actions_umul(16,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal,"UShort", "toUShort", "UInt","toUInt")
    elif op_str == "X86G_CC_OP_UMULL":
        return actions_umul(32,cc_dep1_formal,cc_dep2_formal,cc_ndep_formal,"UInt", "toUInt", "ULong","idULong")
    elif op_str == "X86G_CC_OP_SMULB":
        pass
    elif op_str == "X86G_CC_OP_SMULW":
        pass
    elif op_str == "X86G_CC_OP_SMULL":
        pass
    else:
        raise BaseException("other operation in x86g_calculate_condition")

#/* Given fpround as an IRRoundingMode value, create a suitable x87 native format FPU control word. */
def x86g_create_fpucw(value):
    value = c_uint32(value).value
    value = value & 3
    return (0x037F | (value << 10))

def x86g_check_fldcw(value):
    value = c_uint32(value).value
    rmode = (value >> 10) & 3
    ew = 0 #VexEmNote ew = EmNote_NONE;/* Detect any required emulation warnings. */
    if ((value & 0x3F) != 0x3F):
        ew = 1#/* unmasking x87 FP exceptions is not supported */
    elif (((value >> 8) & 3) != 3):
        ew = 2#/* unsupported precision */
    
    return (c_ulonglong(ew).value << 32) | (c_ulonglong(rmode).value)

#returns 1 or 0
def x86g_calculate_condition(cond,cc_op,cc_dep1,cc_dep2,cc_ndep):
    eflags = x86g_calculate_eflags_all_WRK(cc_op,cc_dep1,cc_dep2,cc_ndep)
    of = 0
    sf = 0
    zf = 0
    cf = 0
    pf = 0
    inv = cond & 1
    con_str = X86Condcode[cond]
    if con_str == "X86CondO" or con_str == "X86CondNO":#前者of == 1
        of = eflags >> X86G_CC_SHIFT_O
        return 1&(inv ^ of)
    elif con_str == "X86CondNZ" or con_str == "X86CondZ":#后者zf == 1
        zf = eflags >> X86G_CC_SHIFT_Z
        return 1 & (inv ^ zf)
    elif con_str == "X86CondNB" or con_str == "X86CondB":#后者cf == 1
        cf = eflags >> X86G_CC_SHIFT_C
        return 1 & (inv ^ cf)
    elif con_str == "X86CondNBE" or con_str == "X86CondBE":#后者cf or zf == 1
        cf = eflags >> X86G_CC_SHIFT_C
        zf = eflags >> X86G_CC_SHIFT_Z
        return 1 & (inv ^ (cf | zf))
    elif con_str == "X86CondNS" or con_str == "X86CondS": #h后者 sf == 1
        sf = eflags >> X86G_CC_SHIFT_S
        return 1 & (inv ^ sf)
    elif con_str == "X86CondNP" or con_str == "X86CondP":#后者pf == 1
        pf = eflags >> X86G_CC_SHIFT_P
        return 1 & (inv ^ pf)
    elif con_str == "X86CondNL" or con_str == "X86CondL":#后者sf xor of == 1
        sf = eflags >> X86G_CC_SHIFT_S
        of = eflags >> X86G_CC_SHIFT_O
        return 1 & (inv ^ (sf ^ of))
    elif con_str == "X86CondNLE" or con_str == "X86CondLE":#后者((SF xor OF) or ZF)  == 1
        sf = eflags >> X86G_CC_SHIFT_S
        of = eflags >> X86G_CC_SHIFT_O
        zf = eflags >> X86G_CC_SHIFT_Z
        return 1 & (inv ^ ((sf ^ of) | zf))
    else:
        raise BaseException("x86_caculate_condition exception")
         
def x86g_calculate_eflags_all(cc_op,cc_dep1,cc_dep2,cc_ndep):
    return x86g_calculate_eflags_all_WRK ( cc_op, cc_dep1, cc_dep2, cc_ndep )

def x86g_calculate_eflags_c(cc_op,cc_dep1,cc_dep2,cc_ndep):
    op_str = X86CCop[cc_op]
    if op_str == "X86G_CC_OP_LOGICL" or op_str == "X86G_CC_OP_LOGICW" or op_str == "X86G_CC_OP_LOGICB":
        return 0
    elif op_str == "X86G_CC_OP_SUBL":
        cc_dep1_new = int(cc_dep1 & 4294967295L)
        cc_dep2_new = int(cc_dep2 & 4294967295L)
        if cc_dep1_new < cc_dep2_new:
            return X86G_CC_MASK_C
        else:
            return 0
    elif op_str == "X86G_CC_OP_SUBW":
        value1 = int((cc_dep1 & 0xFFFF) & 4294967295L)
        value2 = int((cc_dep2 & 0xFFFF) & 4294967295L)
        if value1 < value2:
            return X86G_CC_MASK_C
        else:
            return 0
    elif op_str == "X86G_CC_OP_SUBB":
        value1 = int((cc_dep1 & 0xFF) & 4294967295L)
        value2 = int((cc_dep2 & 0xFF) & 4294967295L)
        if value1 < value2:
            return X86G_CC_MASK_C
        else:
            return 0    
    elif op_str == "X86G_CC_OP_INCL" or op_str == "X86G_CC_OP_DECL":
        return cc_ndep & X86G_CC_MASK_C
    else:
        return x86g_calculate_eflags_all_WRK(cc_op,cc_dep1,cc_dep2,cc_ndep) & X86G_CC_MASK_C