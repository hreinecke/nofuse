/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * portd.c
 * Manage discovery ports by watching keys in etcd
 *
 * Copyright (c) 2024 Hannes Reinecke <hare@suse.de>
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include <json-c/json.h>

#include "common.h"
#include "etcd_client.h"

bool ep_debug;
bool cmd_debug;
bool port_debug;
bool tcp_debug;
bool etcd_debug;
bool curl_debug;

int stopped = 0;

static int parse_port_key(char *key, unsigned int *portid,
			  char **attr, char **subsys, unsigned int *ana_grpid)
{
	char *p, *s, *port, *eptr = NULL;
	unsigned long id;

	/* prefix */
	p = strtok_r(key, "/", &s);
	if (!p)
		return -EINVAL;
	/* 'ports' */
	p = strtok_r(NULL, "/", &s);
	if (!p)
		return -EINVAL;
	port = strtok_r(NULL, "/", &s);
	if (!port)
		return -EINVAL;
	id = strtoul(port, &eptr, 10);
	if (id == ULONG_MAX || port == eptr)
		return -EDOM;
	*portid = id;
	*attr = strtok_r(NULL, "/", &s);
	if (!*attr) {
		*portid = 0;
		return -EINVAL;
	}
	if (!strcmp(*attr, "subsystems")) {
		*subsys = strtok_r(NULL, "/", &s);
		if (!*subsys)
			return -EINVAL;
		p = strtok_r(NULL, "/", &s);
		if (p) {
			*subsys = NULL;
			return -EINVAL;
		}
		*attr = NULL;
	} else if (!strcmp(*attr, "ana_groups")) {
		char *ana_grp;

		ana_grp = strtok_r(NULL, "/", &s);
		if (!ana_grp)
			return -EINVAL;
		id = strtoul(ana_grp, &eptr, 10);
		if (id == ULONG_MAX || ana_grp == eptr)
			return -EINVAL;
		*ana_grpid = id;
		p = strtok_r(NULL, "/", &s);
		if (!p) {
			*ana_grpid = 0;
			return -EINVAL;
		}
		p = strtok_r(NULL, "/", &s);
		if (p) {
			*ana_grpid = 0;
			return -EINVAL;
		}
		*attr = NULL;
	}
	return 0;
}

static void update_ports(struct etcd_ctx *ctx, enum kv_key_op op,
			 char *key, const char *value)
{
	char *key_save, *attr, *subsys = NULL;
	unsigned int portid, ana_grpid = 0;
	int ret;

	key_save = strdup(key);
	if (op != KV_KEY_OP_ADD && op != KV_KEY_OP_DELETE) {
		fprintf(stderr, "Skip unhandled op %d\n", op);
		free(key_save);
		return;
	}
	if (strncmp(key, ctx->prefix, strlen(ctx->prefix))) {
		fprintf(stderr, "Skip invalid prefix '%s'\n", key);
		free(key_save);
		return;
	}
	ret = parse_port_key(key_save, &portid, &attr,
			     &subsys, &ana_grpid);
	if (ret < 0)
		goto out_free;

	if (attr) {
		if (op == KV_KEY_OP_ADD)
			find_and_add_port(ctx, portid);
		else if (!strcmp(attr, "addr_traddr"))
			find_and_del_port(portid);
		else
			printf("%s: skip op %s port %d attr %s\n", __func__,
			       op == KV_KEY_OP_ADD ? "add" : "delete",
			       portid, attr);
	} else if (subsys) {
		struct nofuse_port *port;

		port = find_port(portid);
		if (!port) {
			printf("%s: skip op %s port %d subsys %s, not found\n",
			       __func__, op == KV_KEY_OP_ADD ? "add" : "delete",
			       portid, subsys);
			goto out_free;
		}
		if (op == KV_KEY_OP_ADD) {
			start_port(port);
		} else {
			stop_port(port);
		}
		put_port(port);
	}
out_free:
	free(key_save);
}

static void parse_ports(struct etcd_ctx *ctx,
			struct json_object *resp_obj)
{
	struct nofuse_port *port;

	json_object_object_foreach(resp_obj, key, val_obj) {
		char *path, *attr = NULL, *subsys = NULL;
		unsigned int portid, ana_grpid = 0;
		int ret;

		if (!json_object_is_type(val_obj, json_type_string))
			continue;
		path = strdup(key);
		ret = parse_port_key(path, &portid, &attr, &subsys, &ana_grpid);
		if (ret < 0)
			continue;
		if (subsys) {
			port = find_port(portid);
			if (!port)
				continue;
			printf("start port %d subsys %s\n",
			       portid, subsys);
			start_port(port);
			put_port(port);
		} else if (ana_grpid)
			printf("add port %d ana group %d\n",
			       portid, ana_grpid);
		else {
			find_and_add_port(ctx, portid);
			printf("add port %d attr %s\n",
			       portid, attr);
		}
		free(path);
	}
}

void usage(void) {
	printf("etcd_discovery - decentralized nvme discovery\n");
	printf("usage: etcd_discovery <args>\n");
	printf("Arguments are:\n");
	printf("\t[-h|--host] <host-or-ip>\tHost to connect to\n");
	printf("\t[-p|--port] <portnum>\tetcd client port\n");
	printf("\t[-k|--key_prefix] <prefix>\tetcd key prefix\n");
	printf("\t[-s|--ssl]\tUse SSL connections\n");
	printf("\t[-v|--verbose]\tVerbose output\n");
	printf("\t[-h|--help]\tThis help text\n");
}

int main(int argc, char **argv)
{
	struct option getopt_arg[] = {
		{"port", required_argument, 0, 'p'},
		{"host", required_argument, 0, 'h'},
		{"ssl", no_argument, 0, 's'},
		{"key_prefix", required_argument, 0, 'k'},
		{"verbose", no_argument, 0, 'v'},
		{"help", no_argument, 0, '?'},
	};
	struct json_object *resp;
	char c;
	int getopt_ind;
	struct etcd_ctx *ctx;
	char *prefix;
	int ret = 0;

	ctx = etcd_init(NULL);
	if (!ctx) {
		fprintf(stderr, "cannot allocate context\n");
		exit(1);
	}
	ctx->resp_obj = json_object_new_object();

	while ((c = getopt_long(argc, argv, "ae:p:h:sv?",
				getopt_arg, &getopt_ind)) != -1) {
		switch (c) {
		case 'e':
			free(ctx->prefix);
			ctx->prefix = strdup(optarg);
			break;
		case 'h':
			ctx->host = optarg;
			break;
		case 'p':
			ctx->port = atoi(optarg);
			break;
		case 's':
			ctx->proto = "https";
			break;
		case 'v':
			etcd_debug = true;
			port_debug = true;
			ep_debug = true;
			break;
		case '?':
			usage();
			return 0;
		}
	}

	asprintf(&prefix, "%s/ports", ctx->prefix);
	printf("Using key %s\n", prefix);

	resp = etcd_kv_range(ctx, prefix);
	if (!resp)
		fprintf(stderr, "Failed to retrieve port information\n");
	else {
		parse_ports(ctx, resp);
		json_object_put(resp);
	}

	ctx->resp_obj = json_object_new_object();
	ctx->watch_cb = update_ports;
	ret = etcd_kv_watch(ctx, prefix);
	if (!ret) {
		json_object_object_foreach(ctx->resp_obj,
					   key_obj, val_obj)
			printf("%s: %s\n", key_obj,
			       json_object_get_string(val_obj));
	}

	cleanup_ports();

	free(prefix);
	etcd_exit(ctx);
	return ret < 0 ? 1 : 0;
}
