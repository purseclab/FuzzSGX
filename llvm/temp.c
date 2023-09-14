/*
 * temp.c
 *
 *  Created on: Nov 16, 2019
 *      Author: arslan
 */




	if (insn->getOpcode() == Instruction::Store) {
		if (auto str = dyn_cast < StoreInst > (insn)) {
			if (str->isVolatile()) {
				errs() << "Volatile Store" << *str << "\n";
				str->getOperand(0);
			}
		}
		int num_users = 0;
		llvm::Value *dest = insn->getOperand(1);
		for (auto U : dest->users())   // U is of type User*
			num_users++;
		if (num_users > 1) {
			llvm::Value *cast = insn->getOperand(0);
			if (llvm::ConstantExpr *C = dyn_cast < llvm::ConstantExpr > (cast)) {
				const APInt intval;
				(C->getIntegerValue(cast->getType(), intval));
				Value *tmp = C->getOperand(0);
				if (ConstantInt *CI = dyn_cast < llvm::ConstantInt > (tmp)) {
					errs() << "Local IO access found to:" << CI->getValue().getLimitedValue() << "\n";
				}
			}
		}
		/* At higher optimizations this happens */
		if (llvm::ConstantExpr *C = dyn_cast < llvm::ConstantExpr > (dest)) {
			const APInt intval;
			Value *tmp = C->getOperand(0);
			if (ConstantInt *CI = dyn_cast < llvm::ConstantInt > (tmp)) {
				errs() << "Local IO access found to:" << CI->getValue().getLimitedValue() << "\n";
				LLVMContext & C = insn->getContext();
				MDNode *N = MDNode::get(C, MDString::get(C, std::to_string(CI->getValue().getLimitedValue())));
				insn->setMetadata("acl:", N);
			}
		}
	}

	if (llvm::ConstantExpr *C = dyn_cast < llvm::ConstantExpr > (ce)) {
		Value *tmp = C->getOperand(0);
		if (ConstantInt *CI = dyn_cast < llvm::ConstantInt > (tmp)) {
			errs() << "Field IO access found to:" << CI->getValue().getLimitedValue() + mem_offset << "\n";
		}
	}
	if (GlobalVariable *gv = dyn_cast < GlobalVariable > (ce)) {
		if (llvm::ConstantExpr *C = dyn_cast < llvm::ConstantExpr > (gv->getInitializer())) {
			Value *tmp = C->getOperand(0);
			if (ConstantInt *CI = dyn_cast < llvm::ConstantInt > (tmp)) {
				errs() << "GLOBAL Field IO access found to:" << CI->getValue().getLimitedValue() + mem_offset << "\n";
			}
		}
	}
				for (Use &U : insn->operands()) {
					/* We are only interested in Load or store to memory */
					Value *v = U.get();
					if (GlobalVariable *gv = dyn_cast < GlobalVariable > (v)) {
						if (llvm::ConstantExpr *C = dyn_cast < llvm::ConstantExpr > (gv->getInitializer())) {
							const APInt intval;
							Value *tmp = C->getOperand(0);
							if (ConstantInt *CI = dyn_cast < llvm::ConstantInt > (tmp)) {
								errs() << "GLOBAL IO access found to:" << CI->getValue().getLimitedValue() << "\n";
							}
						}
					}
				}

				if (auto CE = dyn_cast < llvm::IntToPtrInst > (insn)) {
					errs() << "Cannot determine memory at compile time, Pointer Access not allowed : \nvim "
							<< CE->getFunction()->getParent()->getSourceFileName() << " +" << CE->getDebugLoc().getLine() << "\n";
				}

				/* We don't modify code return false */
				return false;
