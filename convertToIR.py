#-*- coding: utf-8 -*-

import pyvex
import archinfo

def constructIR(binaryInst,address,arc = "x86",endness = "LE"):
    ar = archinfo.ArchX86()
    if arc == "x86":
        ar = archinfo.ArchX86()
    elif arc == "mips32":
        if endness == "LE":
            ar = archinfo.ArchMIPS32(archinfo.Endness.LE)
        else:
            ar = archinfo.ArchMIPS32(archinfo.Endness.BE)
    elif arc == "arm":
        ar = archinfo.ArchARM(archinfo.Endness.LE)
    irsb = pyvex.IRSB(data = binaryInst,mem_addr = address,arch = ar)
    stmts = irsb.statements    
    irsb.pp()
    return stmts,irsb.jumpkind,irsb.next

def constructIRForAllPlatform(binaryInst,address,ar):
    irsb = pyvex.IRSB(data = binaryInst,mem_addr = address,arch = ar)
    stmts = irsb.statements    
    irsb.pp()
    return stmts,irsb.jumpkind,irsb.next