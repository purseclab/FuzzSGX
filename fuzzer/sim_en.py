#Import angr
import angr,claripy


class sgx_is_within_enclave(angr.SimProcedure):
    def run(self):
        return 1

class abort(angr.SimProcedure):
    NO_RET = True
    def run(self):
        self.exit(1)

class sgx_lfence(angr.SimProcedure):
    def run(self):
        return

class sgx_is_outside_enclave(angr.SimProcedure):
    def run(self):
        return 1

class printf(angr.SimProcedure):
    def run(self):
        return

class sgx_ocall(angr.SimProcedure):
    def run(self):
        return 0

#Make project
proj = angr.Project('/home/arslan/sgxsdk3/sgxsdk/SampleCode/SampleEnclave/enclave.so')
proj = angr.Project('./enclave.signed.so')
state = proj.factory.entry_state()
if proj.loader.find_symbol("sgx_is_within_enclave"):
    sm = proj.factory.simulation_manager(state)
    func = "sgx_is_within_enclave"
    addr= proj.loader.find_symbol("sgx_is_within_enclave").relative_addr + proj.loader.min_addr
    proj.hook(addr, sgx_is_within_enclave())
    proj.hook_symbol("abort", abort())
    proj.hook_symbol("sgx_lfence", sgx_lfence())
    proj.hook_symbol("sgx_is_outside_enclave", sgx_is_outside_enclave())
    proj.hook_symbol("printf", printf())
    proj.hook_symbol("sgx_ocall", sgx_ocall())



#Get CFG
cfg = proj.analyses.CFGFast()
cfg.normalize()

#Get call syntax
val = claripy.BVS('val', 64)
val = val.reversed
ptr_val = angr.PointerWrapper(val)
size = claripy.BVS('size', 32)
char_val = claripy.BVS("char_val", 8)


struct_val = claripy.BVS('struct', 128)
struct_val_ptr = angr.PointerWrapper(struct_val)

array_size = 32 * 4
array = claripy.BVS('arr', array_size)


foo0 = claripy.BVS('foo0', 64)
foo1 = claripy.BVS('foo1', 64)

floatarg = claripy.FPS('float1', claripy.FSORT_DOUBLE)
array_ptr = angr.PointerWrapper(array)
val2 = claripy.BVS('val2', 32)
ptr_val2 = angr.PointerWrapper(val2)

enum = claripy.BVS('val2', 32)
enum2 = claripy.BVS('val2', 32)
ptr_val2 = angr.PointerWrapper(enum2)
val3 =claripy.BVS('val3', 32)
#args = [ptr_val, val2]
arg0 = claripy.BVS('val2', 8*16)
arg0_ptr = angr.PointerWrapper(arg0)
arg1 = claripy.BVS('val3', 8*8)
cs  = proj.factory.call_state(cfg.kb.functions["sgxsd_enclave_server_stop"].addr, arg0_ptr, arg1)
csm = proj.factory.simgr(cs, veritesting = True)


while len(csm.active) == 1:
	proj.factory.block(csm.active[0].addr).pp()
	csm.step()


while len(csm.deadended) == 0:
    csm.step()        
    proj.factory.block(csm.active[0].addr).pp()


while len(csm.active) > 0:
    print(csm)
    csm.step()



sols=[]
val = val.reversed
low = 0
high = 31
array[high:low]
i = 0
for deadended in csm.deadended:
    print ("Next Path ________")
    for chunk in array.chop(8):
        chunk = chunk.reversed
        print (deadended.solver.eval(chunk))

for deadended in csm.deadended:
    print (deadended.solver.eval(floatarg))

#for deadended in csm.deadended:
#    print deadended.solver.eval(foo1)

#for deadended in csm.deadended:
#    sols.append(deadended.solver.eval(char_val))

#for i in range(0,array.size()):
#    for deadended in csm.deadended:
#        print deadended.solver.eval(array[i])


#for deadended in csm.deadended:
#    print deadended.solver.eval(val)
