REMOTE_HOST=3.139.88.71

setup:
	sudo apt update
	sudo apt install nodejs
	sudo apt install npm
	sudo apt install build-essential
	sudo apt-get install libgmp-dev
	sudo apt-get install libsodium-dev
	sudo apt-get install nasm
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	git clone https://github.com/nalinbhardwaj/circom.git && cd circom && git checkout pasta
	cargo install --path circom
	cd ..
	git clone https://github.com/iden3/rapidsnark && cd rapidsnark
	npm install
	git submodule init
	git submodule update
	npx task createFieldSources
	npx task buildProver
	cd ..


sync_out:
	rsync -arv --exclude='target' --exclude='nova-scotia-backup' --exclude='build' --exclude='node_modules'  ./* ubuntu@$(REMOTE_HOST):~/recursive-zk-bridge

sync_in:
	rsync -arv --exclude='target' --exclude='nova-scotia-backup' --exclude='build' --exclude='node_modules' ubuntu@$(REMOTE_HOST):~/recursive-zk-bridge/* .
