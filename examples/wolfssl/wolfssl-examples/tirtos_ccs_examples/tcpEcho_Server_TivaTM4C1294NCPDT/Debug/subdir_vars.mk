################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CMD_SRCS += \
../EK_TM4C1294XL.cmd 

CFG_SRCS += \
../tcpEcho.cfg 

C_SRCS += \
../EK_TM4C1294XL.c \
../tcpEcho.c 

OBJS += \
./EK_TM4C1294XL.obj \
./tcpEcho.obj 

C_DEPS += \
./EK_TM4C1294XL.pp \
./tcpEcho.pp 

GEN_MISC_DIRS += \
./configPkg/ 

GEN_CMDS += \
./configPkg/linker.cmd 

GEN_OPTS += \
./configPkg/compiler.opt 

GEN_FILES += \
./configPkg/linker.cmd \
./configPkg/compiler.opt 

GEN_FILES__QUOTED += \
"configPkg\linker.cmd" \
"configPkg\compiler.opt" 

GEN_MISC_DIRS__QUOTED += \
"configPkg\" 

C_DEPS__QUOTED += \
"EK_TM4C1294XL.pp" \
"tcpEcho.pp" 

OBJS__QUOTED += \
"EK_TM4C1294XL.obj" \
"tcpEcho.obj" 

C_SRCS__QUOTED += \
"../EK_TM4C1294XL.c" \
"../tcpEcho.c" 

GEN_CMDS__FLAG += \
-l"./configPkg/linker.cmd" 

GEN_OPTS__FLAG += \
--cmd_file="./configPkg/compiler.opt" 


