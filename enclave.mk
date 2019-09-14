######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_SSL ?= /opt/intel/sgxssl
OPENSSL_PATH ?= /usr/local/ssl
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 0
SGX_PRERELEASE ?= 1

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	$(error x86 build is not supported, only x64!!)
else
	SGX_COMMON_CFLAGS := -m64 -Wall
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif



ifeq ($(SGX_DEBUG), 1)
    ifeq ($(SGX_PRERELEASE), 1)
        $(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
    endif
endif

ifeq ($(SGX_DEBUG), 1)
    SGX_COMMON_CFLAGS += -O0 -g
    SGX_SSL_LIB := $(SGX_SSL)/lib64
else
    SGX_COMMON_CFLAGS += -O2
    SGX_SSL_LIB := $(SGX_SSL)/lib64
endif

######## Enclave ########

Enclave_Version_Script := enclave/crypto_engine.lds

ifneq ($(SGX_MODE), HW)
    # simulation mode
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif

Enclave_Cpp_Files := enclave/enclave.cpp
Enclave_Include_Paths := -Ipkcs11 -Icryptoki -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc -I$(SGX_SSL)/include

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -fstack-protector-strong $(Enclave_Include_Paths) -include "tsgxsslio.h"
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++ -std=c++11

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	-L$(SGX_SSL_LIB) \
	-Wl,--whole-archive -lsgx_tsgxssl -Wl,--no-whole-archive -lsgx_tsgxssl_crypto \
	-L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tcrypto -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections \
	-Wl,--version-script=$(Enclave_Version_Script)

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := PKCS11_crypto_engine.so
Signed_Enclave_Name := PKCS11_crypto_engine.signed.so
Enclave_Config_File := enclave/enclave.config.xml

ifeq ($(SGX_MODE), HW)
    ifeq ($(SGX_DEBUG), 1)
        Build_Mode = HW_DEBUG
    else ifeq ($(SGX_PRERELEASE), 1)
        Build_Mode = HW_PRERELEASE
    else
        Build_Mode = HW_RELEASE
	endif
else
    ifeq ($(SGX_DEBUG), 1)
        Build_Mode = SIM_DEBUG
    else ifeq ($(SGX_PRERELEASE), 1)
        Build_Mode = SIM_PRERELEASE
    else
        Build_Mode = SIM_RELEASE
    endif
endif

.PHONY: all

ifeq ($(Build_Mode), HW_RELEASE)
all: $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the ESigner."
	@echo "To sign the ESigner use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -ESigner $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the ESigner using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1."
else
all: $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

enclave/crypto_engine_t.c: $(SGX_EDGER8R) enclave/crypto_engine.edl
	@cd enclave && $(SGX_EDGER8R) --trusted ../enclave/crypto_engine.edl --search-path ../enclave --search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "Edger8r generates trusted proxy  =>  $@"

enclave/crypto_engine_t.o: enclave/crypto_engine_t.c
	@$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "C compile   <=  $<"

enclave/%.o: enclave/%.cpp
	@$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "C++ compile  <=  $<"

$(Enclave_Name): enclave/crypto_engine_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "Linking =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	@echo "Signing enclave =>  $@"
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/crypto_engine_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)

.PHONY: clean

clean:
	@rm -f $(Enclave_Name) $(Signed_Enclave_Name) $(Enclave_Cpp_Objects) enclave/crypto_engine_t.*