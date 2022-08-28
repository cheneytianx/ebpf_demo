APP=count
APP: $(APP)_bpfel.go $(APP).go
	go build -o ${$@}

$(APP)_bpfel.go: $(APP).bpf.c
	go generate