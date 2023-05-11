REMOTE_HOST=18.224.69.206

setup:
	sudo apt update
	sudo apt install build-essential libgmp-dev libsodium-dev nasm nlohmann-json3-dev
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	sudo apt install nodejs npm
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
	sudo sysctl -w vm.max_map_count=655300


sync_out:
	rsync -arv --exclude='target' --exclude='nova-scotia-backup' --exclude='build' --exclude='node_modules'  ./* ubuntu@$(REMOTE_HOST):~/recursive-zk-bridge

sync_in:
	rsync -arv --exclude='target' --exclude='nova-scotia-backup' --exclude='build' --exclude='node_modules' ubuntu@$(REMOTE_HOST):~/recursive-zk-bridge/* .
