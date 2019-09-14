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

######## App ########

ifneq ($(SGX_MODE), HW)
    # simulation mode
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := pkcs11/CryptoEntity.cpp pkcs11/pkcs11.cpp pkcs11/TestApp.cpp
App_Include_Paths := -Ipkcs11 -I$(SGX_SDK)/include -I$(OPENSSL_PATH)/include

App_C_Flags := $(SGX_COMMON_CFLAGS) -fPIC -Wno-attributes $(App_Include_Paths)

ifeq ($(SGX_DEBUG), 1)
	App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
	# release mode
	App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags) -std=c++11 -fpermissive
App_Link_Flags := $(SGX_COMMON_CFLAGS) -L$(SGX_LIBRARY_PATH) \
    -L$(OPENSSL_PATH)/lib -L$(SGX_SSL_LIB) \
    -Wl,--start-group -lcrypto -lssl -ldl -Wl,--end-group \
    -lsgx_usgxssl -lsgx_uae_service \
    -l$(Urts_Library_Name) -lpthread 

ifneq ($(SGX_MODE), HW)
    # simulation mode
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := App

.PHONY: all

all: $(App_Name)

pkcs11/crypto_engine_u.c: $(SGX_EDGER8R) enclave/crypto_engine.edl
	@cd pkcs11 && $(SGX_EDGER8R) --untrusted ../enclave/crypto_engine.edl --search-path ../enclave --search-path $(SGX_SDK)/include --search-path $(SGX_SSL)/include
	@echo "Edger8r generates untrusted proxy =>  $@"

pkcs11/pkcs11_module_u.o: pkcs11/crypto_engine_u.c
	@$(CC) $(App_C_Flags) -c $< -o $@
	@echo "C compile   <=  $<"

pkcs11/%.o: pkcs11/%.cpp
	@$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "C++ compile  <=  $<"

$(App_Name): pkcs11/pkcs11_module_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "Linking =>  $@"

.PHONY: clean

clean:
	@rm -f $(App_Name) $(App_Cpp_Objects) pkcs11/pkcs11_module_u.*
