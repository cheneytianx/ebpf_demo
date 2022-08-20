DIR=
APP=
STEM=$(DIR)/$(APP)


STEM: $(STEM).skel.h $(STEM).c
	clang $(STEM).c -lelf -lbpf -o $(STEM)

$(STEM).skel.h: $(STEM).bpf.o
	bpftool gen skeleton $< > $@

$(STEM).bpf.o: $(STEM).bpf.c
	clang -O2 -g -target bpf -D__TARGET_ARCH_x86_64 -c $< -o $@

.PHONY: vmlinux
vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
