#-*- coding: utf-8 -*-

import pyvex
import archinfo

def constructIR(binaryInst,address,arc = "x86",endness = "LE"):
    #print "------------start converting IR for ",address,"---------------"
    #print type(binaryInst)
    #print binaryInst
    #print type(address)
    #print hex(address)
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
    #for stmt in irsb.statements:
        #print type(stmt),stmt.pp()
        #for i in stmt.expressions:
            #print type(i),i
    #for stmt in stmts:
        #print "type",type(stmt)
        #print stmt.pp()    
    #print irsb1.instructions
    return stmts,irsb.jumpkind,irsb.next

def constructIRForAllPlatform(binaryInst,address,ar):
    #print "------------start converting IR for ",address,"---------------"
    #print type(binaryInst)
    #print binaryInst
    #print type(address)
    #print hex(address)
    #ar = archinfo.ArchX86()
    irsb = pyvex.IRSB(data = binaryInst,mem_addr = address,arch = ar)
    stmts = irsb.statements    
    irsb.pp()
    #for stmt in irsb.statements:
        #print type(stmt),stmt.pp()
        #for i in stmt.expressions:
            #print type(i),i
    #for stmt in stmts:
        #print "type",type(stmt)
        #print stmt.pp()    
    #print irsb1.instructions
    return stmts,irsb.jumpkind,irsb.next