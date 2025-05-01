.PHONY: strace ebpf clean

strace:
	@echo "Running full strace pipeline..."
	SESSION=$$(python3 src/collector.py --mode strace --parallel | awk -F '::' '/SESSION_PATH/ {print $$2}') && \
	echo "Using session: $$SESSION" && \
	python3 src/processor.py --session $$SESSION --mode strace && \
	python3 src/queries.py --session $$SESSION

ebpf:
	@echo "Running full eBPF pipeline..."
	SESSION=$$(python3 src/collector.py --mode ebpf --parallel | awk -F '::' '/SESSION_PATH/ {print $$2}') && \
	echo "Using session: $$SESSION" && \
	python3 src/processor.py --session $$SESSION --mode ebpf && \
	python3 src/queries.py --session $$SESSION

clean:
	rm -rf data/*
