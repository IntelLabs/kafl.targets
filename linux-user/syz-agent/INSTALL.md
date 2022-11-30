## Install Go

Need a recent version of Go: https://go.dev/doc/install

Global install:

```
wget -c https://go.dev/dl/go1.19.3.linux-amd64.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf go1.19.3.linux-amd64.tar.gz
sudo ln -s /usr/local/go/bin/go /usr/local/bin/go
sudo ln -s /usr/local/go/bin/gofmt /usr/local/bin/gofmt
```

Local install:

```
wget https://dl.google.com/go/go1.17.6.linux-amd64.tar.gz
tar -xf go1.17.6.linux-amd64.tar.gz
export GOROOT=`pwd`/go
export PATH=$GOROOT/bin:$PATH
```

Confirm installation:

```
which go
> /usr/local/bin/go
go version
> go version go1.19.3 linux/amd64
```

## Install Syzkaller

Syzkaller for Linux setup: https://github.com/google/syzkaller/blob/master/docs/linux/setup.md

```
git clone -b kafl-agent https://github.com/il-steffen/syzkaller.git
MAKEFLAGS="" make -C syzkaller
```

Confirm build:

```
cd syzkaller/bin/linux_amd64
ldd syz-stress syz-executor
> syz-stress:
>         not a dynamic executable
> syz-executor:
>         statically linked
```


## Build kAFL Agent + initrd
