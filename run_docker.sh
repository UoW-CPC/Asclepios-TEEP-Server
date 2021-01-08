docker run --device /dev/sgx/provision --device /dev/sgx/enclave --rm -ti asclepios \
   sh -c "cd /root/asclepios-teep; . /root/.bashrc; (python -c 'import simple; simple.start_server()' & sleep 1; python -c 'import simple; simple.sealingtest()' ; wait)"
