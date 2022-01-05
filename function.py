functionMap = {}
identifiedVisited = {}
identifiedVisited_stack = {}
args = {}#functionName:(stackArgsList, registerArgsList)
args_stack = {}
lib_function = {}
class Function(object):
    def __init__(self,startAddr, registerArg, registerArgLen, jumptable, stackArg,stackAddr=None, stackLen=None, blocks=None, stackArgLen = None):
        self.startAddr = startAddr
        self.stackAddr = None
        self.stackLen = None
        self.blocks = None
        self.stackArg = stackArg
        self.stackArgLen = None
        self.registerArg = registerArg