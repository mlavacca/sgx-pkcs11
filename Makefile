all:
	$(MAKE) -f enclave.mk all
	$(MAKE) -f app.mk all
clean:
	$(MAKE) -f app.mk clean
	$(MAKE) -f enclave.mk clean
