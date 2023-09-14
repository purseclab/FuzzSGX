//===- Hello.cpp - Example code from "Writing an LLVM Pass" ---------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file implements two versions of the LLVM "Hello World" pass described
// in docs/WritingAnLLVMPass.html
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/Function.h"
#include "llvm/Pass.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Module.h"
#include "llvm/Analysis/CallGraph.h"
#include <string.h>
#include <map>
#include <set>
#include <list>
#include <fstream>
using namespace llvm;
#define DEBUG_APIMOD
#undef DEBUG_APIMOD

/* Structure to search for dependencies */
typedef struct depList {
	llvm::Value * val;
	llvm::Function * callee;
	int argnum;
	int nested_argnum;
	int last_arg;
} DependencyListNode;

typedef struct argrel {
	llvm::Function * callee;
	int argnum;
} ArgumentRelation;

typedef struct funchouser {
	ArgumentRelation cur;
	std::list<ArgumentRelation> lineage;
} FuncHouser;
/* Structure to search for Chains */
typedef struct depChain {
	llvm::Value * val;
	std::list<FuncHouser> callee;
} DependencyChain;

/* Known chains to mankind */
std::list<DependencyChain> chains;

/* Global ID */
llvm::Value * global_identifier = NULL;

#define DEBUG_TYPE "hello"
#define DEBUG
#undef  DEBUG

cl::opt<std::string> DatabaseFilename("interface", cl::Required, cl::desc("Specify ecall interface database"), cl::value_desc("file.dat"));
int init =0;
std::map <std::string, int> pubEcalls; // Public Ecalls
std::map <std::string, int> procFuncs; // Functions processed
std::map <llvm::Value *, std::set<unsigned long long> > depCluster; // Value is a set to llvm::Function * in disguise


namespace {
	// Hello2 - The second implementation with getAnalysisUsage implemented.
	struct APIMODAnalysis: public ModulePass {
		static char ID;
		APIMODAnalysis() : ModulePass(ID) {}
#if 0
		struct APtrComp
		{
			bool operator()(const llvm::Function * lhs, const llv::Function* rhs) const  { /* implement logic here */ }
		};
#endif


		public:
		void getIDFromValue(llvm::Function * func, llvm::Value  * value, int argnum,std::list<DependencyListNode> * currList) {
			if(auto* ci = dyn_cast<ConstantData>(value)) {
				//TODO: Get constants in the chain
#ifdef DEBUG_APIMOD
				errs() << ",";
#else 
				ci = ci;
#endif 
			}
			/* See if a variable */
			else if (auto li = dyn_cast<llvm::LoadInst>(value)) {
				llvm::Value *src = li->getOperand(0);
				//errs() << src << ",";
				//See if it s a global variable
				if (auto glbl = dyn_cast<llvm::GlobalVariable> (src)) {
					/* First global variable we see is probably the global identifier */
					if (global_identifier == NULL) {
						global_identifier = glbl;
#ifdef DEBUG
						errs() << global_identifier << "\n";
#endif 
						return;
					} else if (global_identifier == glbl) {
						return;
					}

					DependencyListNode node;
					node.val = glbl;
					node.callee = func;
					node.argnum = argnum;
					currList->push_back(node);
#ifdef DEBUG_APIMOD
					errs() << "Putting in node with val:" << node.val << "\n";
					errs() << "Global Var:"<<glbl<< ",";
#endif
				}
				//See if a
				else if (auto gep = dyn_cast<llvm::GetElementPtrInst> (src)) {
					auto val = gep->getPointerOperand();
					val = gep->getOperand(0);
					DependencyListNode node;
					node.val = val;
					node.callee = func;
					node.argnum = argnum;
					currList->push_back(node);
#ifdef DEBUG_APIMOD
					errs() << "Putting12 in node with val:" << node.val << "\n";
					errs() << "Array Var:" <<val << ",";
#endif
				}
				//more specific case
				//Just dump it in case you missed sth
				else {
					src->dump();
					errs() << "THIS IS AN ERROR: We did not know" << *src->getType();
				}

			}
			/* Direct reference to the structure */
			else if (auto gep = dyn_cast<llvm::GetElementPtrInst> (value)) {
				auto val = gep->getPointerOperand();
				val = gep->getOperand(0);
				DependencyListNode node;
				node.val = val;
				node.callee = func;
				node.argnum = argnum;
				currList->push_back(node);
#ifdef DEBUG_APIMOD
				errs() << "Putting in node with val:" << node.val << "\n";
				//node.val->dump();
				errs() << "Array Var:" <<val;
#endif

			}
			/* */
			else if (auto alloc = dyn_cast<llvm::AllocaInst>(value)) {
#ifdef DEBUG_APIMOD
				errs() << "Local Val:" << alloc << ",of type:" << value->getType()->isPointerTy();
#endif
				/* See if it is pass by reference, we don't 
				 * count pass by value as a relation */
				if (value->getType()->isPointerTy()) {
					DependencyListNode node;
					node.val = alloc;
					node.callee = func;
					node.argnum = argnum;
#ifdef DEBUG_APIMOD
					errs() << "Putting in node with val:" << node.val <<"argnum:"<<node.argnum<< "\n";
#endif
					currList->push_back(node);
				}
			}
			else if (auto ncall = dyn_cast<llvm::CallInst>(value)) {
				DependencyListNode node;
				node.val = NULL;
				node.callee = func;
				node.argnum = argnum;
				currList->push_back(node);
#ifdef DEBUG_APIMOD
				errs() << "Nested Call bindings:" <<ncall->getCalledFunction()->getName();
#endif
				parseArgsFromCall(ncall, currList);
			}
			/* See if it is a cast */
			else if (auto cast=dyn_cast <llvm::BitCastInst> (value)) {
#ifdef DEBUG_APIMOD
				errs() << "Cast from:";
#endif
				Value * castFrom = cast->getOperand(0);
				getIDFromValue(func,castFrom,argnum, currList);
			}
			else {
				errs() << "Error: WEe did not know";
				value->dump();
			}
		}

		void parseArgsFromCall(llvm::CallInst * call, std::list<DependencyListNode> * currList) {
			int argcounter =0;
			for (auto args = call->arg_begin(); args != call->arg_end(); args++, argcounter++) {
				auto value = args->get();
				/* If its not the global identifier continue */
				getIDFromValue(call->getCalledFunction(), value, argcounter, currList);
			}
#ifdef DEBUG_APIMOD
			errs() << "\n";
#endif 
			DependencyListNode node;
			node.val = call;
			node.callee = call->getCalledFunction();
			node.argnum = -1;
#ifdef DEBUG_APIMOD 
			errs() << "Putting in node with val:" << node.val <<"argnum:"<<node.argnum<< "\n";
#endif
			currList->push_back(node);

		}


		bool runOnFunction(Function &F) {
#if 0
			if (!init) {
				std::ifstream paramFile;
				paramFile.open(DatabaseFilename);
				std::string key;
				std::string line;
				while ( paramFile.good()) {
					std::getline(paramFile, line);
					if (line.length() == 0) continue;
					pubEcalls[line] = 1; // input them into the map
				}
				init = 1;
			}
#endif 

		}


		// We don't modify the program, so we preserve all analyses.
		void getAnalysisUsage(AnalysisUsage &AU) const override {
			AU.addRequired<CallGraphWrapperPass>();
			AU.setPreservesAll();
		}

		bool runOnModule(Module &M) override {
			auto &functionList = M.getFunctionList();
			for (auto &function : functionList) {
				//runOnFunction(function);
			}

			for (auto &Global : M.getGlobalList()) {
#ifdef DEBUG_API
				errs() << Global.getName() << " users:\n";
#endif
				//std::set<unsigned long long> Set;

				for(auto U : Global.users()){  // U is of type User*

					if (auto I = dyn_cast<Instruction>(U)){
						// an instruction uses V
#ifdef DEBUG_API 
						errs() << "*" << I->getFunction()->getName() << "\n";
#endif
						depCluster[&Global].insert((unsigned long long)I->getFunction());
					}
				}
				//depCluster[&Global] = Set;
				//errs() << "*********************************** \n";
			}

			for (auto const& pair: depCluster) {
				if (!pair.second.empty()) {
					errs() << pair.first->getName() << ": ";
					for (auto elem : pair.second){
						llvm::Function * hack = (llvm::Function *) elem;
						errs() << hack->getName() << ",";
					}
					errs() << "\n";
				}
			}

			return false;
		}
	}
	;
}
char APIMODAnalysis::ID = 0;
static RegisterPass<APIMODAnalysis> Y("APIMODAnalysis", "API Model Extraction Pass (with getAnalysisUsage implemented)");
