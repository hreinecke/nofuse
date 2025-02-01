package main

import (
	"context"
	"flag"
	"fmt"
	"strings"
	"go.etcd.io/etcd/client/v3"
	"time"
	"errors"
)

type etcdContext struct {
	host, prefix, node_name, configfs string
}

func (ctx *etcdContext) path(key string) (string, error) {
	attr, ok := strings.CutPrefix(key, ctx.prefix)
	if ok {
		if strings.HasPrefix(attr, "ports") {
			match := fmt.Sprintf("ports/%v:", ctx.node_name)
			suf, ok := strings.CutPrefix(attr, match)
			if ok {
				pathname := fmt.Sprintf("%s%s", ctx.configfs, suf)
				return pathname, nil
			} else {
				return "", errors.New("node mismatch")
			}
		} else {
			pathname := fmt.Sprintf("%s%s", ctx.configfs, attr)
			return pathname, nil
		}
	} else {
		return "", errors.New("invalid prefix")
	}
}

func main() {
	etcdHost := flag.String("etcdHost", "localhost:2379", "etcd host")
	etcdWatchKey := flag.String("prefix", "nofuse", "etcd key to watch")

	flag.Parse()

	ctx := etcdContext{host: *etcdHost,
	       	prefix: *etcdWatchKey,
		configfs: "/sys/kernel/config/nvmet"}
	fmt.Println("connecting to etcd - " + ctx.host)

	etcd, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"http://" + ctx.host},
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("watchin etcd - " + ctx.host + " prefix " + ctx.prefix)

	defer etcd.Close()

	watchChan := etcd.Watch(context.Background(), ctx.prefix,
		clientv3.WithPrefix())
	fmt.Println("set WATCH on " + ctx.prefix)

	for watchResp := range watchChan {
		for _, event := range watchResp.Events {
			p, err := ctx.path(string(event.Kv.Key[:]))
			if err == nil {
				fmt.Printf("Event %s key %q value %q path %s\n",
					event.Type, event.Kv.Key, event.Kv.Value, p)
			}
		}
	}
}
