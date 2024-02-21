### 一些链接
- https://zhuanlan.zhihu.com/p/449814348
- https://arthurchiao.art/blog/bpf-portability-and-co-re-zh/
- https://arthurchiao.art/blog/lifetime-of-bpf-objects-zh/
- https://arthurchiao.art/blog/understanding-tc-da-mode-zh/
- https://arthurchiao.art/blog/cloudflare-arch-and-bpf-zh/
- https://davidlovezoe.club/wordpress/archives/1044
- https://github.com/xdp-project/xdp-cpumap-tc/tree/master

### 常用的网络脚本
#### 网络包过滤
```
tcpdump -i eth0 ip6 and udp dst port 53
```

### docker
#### image build
```
apt-get update
apt-get install -y make clang llvm vim git
```
#### docker run 
```
docker run --privileged --rm -it -v `pwd`:/root ubuntu_dns:latest bash
```

#### 下载工具
```
git clone --recurse-submodules https://github.com/libbpf/bpftool.git
cd bpftool/src
make -j$(nproc)
sudo ./bpftool prog
```

```
<!-- 基于bpftool生成vmlinux.h文件 -->
./bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

```
<!-- 编译 -->
clang trace.c -target bpf -I /usr/include/bpf -Wall -D DEBUG -O2 -c -o trace.o

<!-- 加载到某个网卡 -->
ip link set dev enp5s0f1 xdpdrv obj trace.o sec xdp
<!-- 卸载网卡 -->
ip l set dev enp5s0f1 xdp off
<!-- 查看打印日志 -->


<!-- 查看编译后的结果 -->
llvm-objdump -d trace.o

```

```
bpf_xdp_adjust_tail的最大值是1433，原本的包大小是80.
```

#### bpf helper函数
- 链接：https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
```
<!-- 获取ctx的长度 -->
bpf_xdp_get_buff_len() 

```

#### bpftool常用函数
- bpftool map dump id 873  // 查看某个id为873的map的内容
- bpftool map  // 查看所有的map 

#### Q&A

1. libbpf: map 'name_maps': invalid pinning value 2.


2. libbpf: BTF is required, but is missing or corrupted.
    - 解决方案：编译的时候加-g解决，如下：
    ```
    clang \
                -g \
                -target bpf \
                -I /usr/include/bpf \
                -Wall $(BPF_EXTRA_FLAGS) \
                -O2 -c -o trace.o $<
    ```
3. error: Looks like the BPF stack limit of 512 bytes is exceeded. Please move large on stack variables into BPF per-cpu array map.



#### bpf的生命週期
- create -> refcnt=1
- attach -> refcnt++
- detach -> refcnt--
- pin -> refcnt++
- unpin -> refcnt--
- unlink -> refcnt--
- close -> refcnt--

#### 单xdp记录打流（只用了一個核）
```
      ports |               0 
 -----------------------------------------------------------------------------------------
   opackets |       142624693 
     obytes |     12123099245 
   ipackets |        91177024 
     ibytes |      9208879424 
    ierrors |               0 
    oerrors |               0 
      Tx Bw |       4.70 Gbps 

-Global stats enabled 
 Cpu Utilization : 99.7  %  1.2 Gb/core 
 Platform_factor : 1.0  
 Total-Tx        :       4.70 Gbps  
 Total-Rx        :       3.58 Gbps  
 Total-PPS       :       6.91 Mpps  
 Total-CPS       :       6.91 Mcps  

 Expected-PPS    :      10.00 Mpps  
 Expected-CPS    :      10.00 Mcps  
 Expected-BPS    :       6.80 Gbps  

 Active-flows    :        0  Clients :    65528   Socket-util : 0.0000 %    
 Open-flows      : 142629056  Servers :      248   Socket :        8 Socket/Clients :  0.0 
 Total_queue_full: 122952768         
 drop-rate       :       1.12 Gbps   
 current time    : 22.7 sec  
 test duration   : 86377.3 sec 
```
