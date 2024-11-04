/*
 * inode.c
 * SQLite3 configfs emulation
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software Foundation,
 *  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 */
#define _GNU_SOURCE

#define FUSE_USE_VERSION 31

#include <fuse.h>

#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <errno.h>

#include "common.h"
#include "inode.h"

static sqlite3 *inode_db;

static int hosts_ino;
static int subsys_ino;
static int ports_ino;


static int sql_simple_cb(void *unused, int argc, char **argv, char **colname)
{
	   int i;

	   for (i = 0; i < argc; i++) {
		   printf("%s ", colname[i]);
	   }
	   printf("\n");
	   for (i = 0; i < argc; i++) {
		   printf("%s ",
			  argv[i] ? argv[i] : "NULL");
	   }
	   printf("\n");
	   return 0;
}

static int sql_exec_simple(const char *sql_str)
{
	int ret;
	char *errmsg = NULL;

	ret = sqlite3_exec(inode_db, sql_str, sql_simple_cb, NULL, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql_str);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	return ret;
}

struct sql_int_value_parm {
	const char *col;
	int val;
	int done;
};

static int sql_int_value_cb(void *argp, int argc, char **argv, char **colname)
{
	struct sql_int_value_parm *parm = argp;
	int i;

	if (parm->done != 0) {
		parm->done = -ENOTUNIQ;
		return 0;
	}

	for (i = 0; i < argc; i++) {
		char *eptr = NULL;

		if (strcmp(parm->col, colname[i])) {
			printf("%s: ignore col %s\n", __func__,
			       colname[i]);
			continue;
		}
		if (!argv[i]) {
			parm->val = 0;
			parm->done = 1;
			break;
		}
		parm->val = strtol(argv[i], &eptr, 10);
		if (argv[i] == eptr) {
			parm->done = -EDOM;
			break;
		}
		parm->done = 1;
	}
	return 0;
}

static int sql_exec_int(const char *sql, char *col, int *value)
{
	char *errmsg;
	struct sql_int_value_parm parm = {
		.col = col,
		.val = 0,
		.done = 0,
	};
	int ret;

	ret = sqlite3_exec(inode_db, sql, sql_int_value_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		parm.done = -EINVAL;
	}
	if (parm.done < 0)
		fprintf(stderr, "value error for '%s': %s\n", col,
			strerror(-parm.done));
	else
		*value = parm.val;
	return parm.done;
}

struct sql_str_value_parm {
	const char *col;
	char *val;
	int done;
};

static int sql_str_value_cb(void *argp, int argc, char **argv, char **colname)
{
	struct sql_str_value_parm *parm = argp;
	int i;

	if (parm->done != 0) {
		parm->done = -ENOTUNIQ;
		return 0;
	}

	for (i = 0; i < argc; i++) {
		if (strcmp(parm->col, colname[i])) {
			printf("%s: ignore col %s\n", __func__,
			       colname[i]);
			continue;
		}
		if (parm->val) {
			if (!argv[i])
				*parm->val = '\0';
			else
				strcpy(parm->val, argv[i]);
		}
		parm->done = 1;
	}
	return 0;
}

static int sql_exec_str(const char *sql, const char *col, char *value)
{
	char *errmsg;
	struct sql_str_value_parm parm = {
		.col = col,
		.val = value,
		.done = 0,
	};
	int ret;

	ret = sqlite3_exec(inode_db, sql, sql_str_value_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		parm.done = -EINVAL;
	}
	if (parm.done < 0)
		fprintf(stderr, "value error for '%s': %s\n", col,
			strerror(parm.done));
	return parm.done;
}

#define NUM_TABLES 7

static const char *init_sql[NUM_TABLES] = {
"CREATE TABLE inode ( ino INTEGER PRIMARY KEY AUTOINCREMENT, "
"pathname VARCHAR(256) NOT NULL, parent_ino INTEGER, mode INTEGER, "
"ctime TIME, atime TIME, mtime TIME, data_type INTEGER, data_id INTEGER);",
"CREATE TABLE hosts ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
"nqn VARCHAR(223) UNIQUE NOT NULL, genctr INTEGER DEFAULT 0, "
"parent_ino INTEGER, FOREIGN KEY (parent_ino) REFERENCES inode(ino));",
"CREATE TABLE subsystems ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
"nqn VARCHAR(223) UNIQUE NOT NULL, attr_allow_any_host INT DEFAULT 1, "
"attr_firmware VARCHAR(256), attr_ieee_oui VARCHAR(256), "
"attr_model VARCHAR(256), attr_serial VARCHAR(256), attr_version VARCHAR(256), "
"type INT DEFAULT 3, parent_ino INTEGER, ctime TIME, "
"FOREIGN KEY (parent_ino) REFERENCES inode(ino));",
"CREATE TABLE ports ( id INTEGER PRIMARY KEY AUTOINCREMENT,"
"addr_trtype CHAR(32) NOT NULL, addr_adrfam CHAR(32) DEFAULT '', "
"addr_subtype INT DEFAULT 2, addr_treq char(32), "
"addr_traddr CHAR(255) NOT NULL, addr_trsvcid CHAR(32) DEFAULT '', "
"addr_tsas CHAR(255) DEFAULT '', parent_ino INTEGER, "
"ctime TIME, atime TIME, mtime TIME, "
"UNIQUE(addr_trtype,addr_adrfam,addr_traddr,addr_trsvcid), "
"FOREIGN KEY (parent_ino) REFERENCES inode (ino) );"
"CREATE UNIQUE INDEX port_addr ON ports(addr_trtype, addr_adrfam, addr_traddr, addr_trsvcid);",
"CREATE TABLE host_subsys ( host_id INTEGER, subsys_id INTEGER, "
"parent_ino INTEGER, FOREIGN KEY (parent_ino) REFERENCES inode(ino), "
"FOREIGN KEY (host_id) REFERENCES host(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT, "
"FOREIGN KEY (subsys_id) REFERENCES subsys(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT);",
"CREATE TABLE subsys_port ( subsys_id INTEGER, port_id INTEGER, "
"parent_ino INTEGER, FOREIGN KEY (parent_ino) REFERENCES inode(ino), "
"FOREIGN KEY (subsys_id) REFERENCES subsystems(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT, "
"FOREIGN KEY (port_id) REFERENCES ports(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT);",
};

int inode_init(void)
{
	int i, ret;

	for (i = 0; i < NUM_TABLES; i++) {
		ret = sql_exec_simple(init_sql[i]);
		if (ret)
			break;
	}
	return ret;
}

static const char *exit_sql[NUM_TABLES] =
{
	"DROP TABLE subsys_port;",
	"DROP TABLE host_subsys;",
	"DROP INDEX port_addr",
	"DROP TABLE ports;",
	"DROP TABLE subsystems;",
	"DROP TABLE hosts;",
	"DROP TABLE inode;",
};

int inode_exit(void)
{
	int i, ret;

	for (i = 0; i < NUM_TABLES; i++) {
		ret = sql_exec_simple(exit_sql[i]);
	}
	return ret;
}

static char add_root_sql[] =
	"INSERT INTO inode (pathname) VALUES ('%s');";
static char get_root_sql[] =
	"SELECT ino FROM inode WHERE pathname = '%s' AND parent_ino IS NULL;";

int inode_add_root(const char *pathname)
{
	char *sql;
	int ret, value;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret)
		return ret;
	ret = asprintf(&sql, add_root_sql, pathname);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_simple(sql);
	free(sql);
	if (ret)
		goto rollback;

	ret = asprintf(&sql, get_root_sql, pathname);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_int(sql, "ino", &value);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_simple("COMMIT TRANSACTION;");
	if (ret < 0)
		return ret;
	return value;
rollback:
	ret = sql_exec_simple("ROLLBACK TRANSACTION;");
	return ret;
}

int inode_get_root(const char *path)
{
	if (!strcmp(path, "hosts"))
		return hosts_ino;
	if (!strcmp(path, "subsystems"))
		return subsys_ino;
	if (!strcmp(path, "ports"))
		return ports_ino;
	return -1;
}

struct fill_parm_t {
	fuse_fill_dir_t filler;
	const char *prefix;
	void *buf;
};

static int fill_root_cb(void *p, int argc, char **argv, char **colname)
{
	struct fill_parm_t *parm = p;
	int i;

	for (i = 0; i < argc; i++)
		parm->filler(parm->buf, argv[i], NULL,
			     0, FUSE_FILL_DIR_PLUS);
	return 0;
}

static int fill_filter_cb(void *p, int argc, char **argv, char **colname)
{
	struct fill_parm_t *parm = p;
	int i;

	for (i = 0; i < argc; i++) {
		if (strncmp(colname[i], parm->prefix,
			    strlen(parm->prefix)))
			continue;
		parm->filler(parm->buf, colname[i], NULL,
			     0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

static char fill_root_sql[] =
	"SELECT pathname FROM inode WHERE parent_ino IS NULL;";

int inode_fill_root(void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *errmsg;
	int ret;

	ret = sqlite3_exec(inode_db, fill_root_sql, fill_root_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", fill_root_sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	return ret;
}

static char add_inode_sql[] =
	"INSERT INTO inode (pathname, parent_ino, ctime) VALUES ('%s','%d', CURRENT_TIMESTAMP);";
static char get_inode_sql[] =
	"SELECT ino FROM inode WHERE pathname = '%s' AND parent_ino = '%d';";

int inode_add_inode(const char *pathname, int parent_ino)
{
	char *sql;
	int ret, value;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret)
		return ret;
	ret = asprintf(&sql, add_inode_sql, pathname, parent_ino);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_simple(sql);
	free(sql);
	if (ret)
		goto rollback;

	ret = asprintf(&sql, get_inode_sql, pathname, parent_ino);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_int(sql, "ino", &value);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_simple("COMMIT TRANSACTION;");
	if (ret < 0)
		return ret;
	return value;
rollback:
	ret = sql_exec_simple("ROLLBACK TRANSACTION;");
	return ret;
}

static char del_inode_sql[] =
	"DELETE FROM inode WHERE ino = '%d';";

int inode_del_inode(int ino)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_inode_sql, ino);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char find_links_sql[] =
	"SELECT count(id) AS num FROM %s WHERE parent_ino = '%d';";

int inode_find_links(const char *tbl, int parent_ino)
{
	char *sql;
	int ret, value;

	ret = asprintf(&sql, find_links_sql, tbl, parent_ino);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "num", &value);
	free(sql);
	return ret;
}

static char add_host_sql[] =
	"INSERT INTO host (nqn, parent_ino) VALUES ('%s', '%d');";

int inode_add_host(struct nofuse_host *host, int parent_ino)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_host_sql, host->nqn, parent_ino);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	return ret;
}

static char host_get_inode_sql[] =
	"SELECT id AS ino FROM hosts "
	"WHERE nqn = '%s';";

int inode_get_host_ino(const char *host, int *inode)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, host_get_inode_sql, host);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "ino", inode);
	free(sql);
	return ret;
}

static char fill_host_dir_sql[] =
	"SELECT nqn FROM hosts;";

int inode_fill_host_dir(void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *errmsg;
	int ret;

	ret = sqlite3_exec(inode_db, fill_host_dir_sql, fill_root_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", fill_host_dir_sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	return ret;
}

static char del_host_sql[] =
	"DELETE FROM hosts WHERE nqn = '%s';";

int inode_del_host(struct nofuse_host *host)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_host_sql, host->nqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_subsys_sql[] =
	"INSERT INTO subsystems (nqn, attr_allow_any_host, type, parent_ino, ctime) "
	"VALUES ('%s', '%d', '%d', '%d', CURRENT_TIMESTAMP);";

int inode_add_subsys(struct nofuse_subsys *subsys, int parent_ino)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_subsys_sql, subsys->nqn,
		       subsys->allow_any, subsys->type, parent_ino);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char subsys_get_inode_sql[] =
	"SELECT id AS ino FROM subsystems "
	"WHERE nqn = '%s' AND parent_ino = '%d';";

int inode_get_subsys_ino(const char *subsys, int parent_ino, int *inode)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, subsys_get_inode_sql, subsys, parent_ino);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "ino", inode);
	free(sql);
	return ret;
}

static char stat_subsys_sql[] =
	"SELECT unixepoch(ctime) AS tv FROM subsystems WHERE nqn = '%s';";

int inode_stat_subsys(const char *subsysnqn, struct stat *stbuf)
{
	char *sql;
	int ret, timeval;

	ret = asprintf(&sql, stat_subsys_sql, subsysnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return -ENOENT;
	stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
	return 0;
}

static char fill_subsys_dir_sql[] =
	"SELECT nqn FROM subsystems;";

int inode_fill_subsys_dir(void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *errmsg;
	int ret;

	ret = sqlite3_exec(inode_db, fill_subsys_dir_sql, fill_root_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", fill_subsys_dir_sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;

	return ret;
}

static char fill_subsys_sql[] =
	"SELECT * FROM subsystems WHERE nqn = '%s';";

int inode_fill_subsys(const char *nqn, void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = "attr_",
		.buf = buf,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, fill_subsys_sql, nqn);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(inode_db, sql, fill_filter_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else	{
		filler(buf, "allowed_hosts", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "namespaces", NULL, 0, FUSE_FILL_DIR_PLUS);
		ret = 0;
	}
	free(sql);
	return ret;
}

static char get_subsys_attr_sql[] =
	"SELECT %s FROM subsystems WHERE nqn = '%s';";

int inode_get_subsys_attr(const char *nqn, const char *attr, char *buf)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, get_subsys_attr_sql, attr, nqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_str(sql, attr, buf);
	free(sql);
	return ret;
}

static char del_subsys_sql[] =
	"DELETE FROM subsystems WHERE id = '%d';";

int inode_del_subsys(struct nofuse_subsys *subsys)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_subsys_sql, subsys->ino);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_port_sql[] =
	"INSERT INTO ports (addr_trtype, addr_adrfam, addr_treq, addr_traddr, addr_trsvcid, addr_tsas, addr_subtype, ctime)"
	" VALUES ('%s','%s','%s','%s','%s','%s','%d', CURRENT_TIMESTAMP);";

static char select_portid_sql[] =
	"SELECT id FROM ports "
	"WHERE addr_trtype = '%s' AND addr_adrfam = '%s' AND "
	"addr_traddr = '%s' AND addr_trsvcid = '%s';";

static char update_traddr_sql[] =
	"UPDATE ports SET traddr = '%s' "
	"WHERE id = '%d';";

int inode_add_port(struct nofuse_port *port, u8 subtype)
{
	char *sql;
	int ret, portid;

	if (!strlen(port->traddr) && strcmp(port->trtype, "loop")) {
		fprintf(stderr, "no traddr specified\n");
		return -EINVAL;
	}
	if (!strcmp(port->trtype, "tcp") || !strcmp(port->trtype, "rdma")) {
		if (!strlen(port->trsvcid)) {
			fprintf(stderr, "no trsvcid specified\n");
			return -EINVAL;
		}
		if (strcmp(port->adrfam, "ipv4") &&
		    strcmp(port->adrfam, "ipv6")) {
			fprintf(stderr, "invalid adrfam %s\n",
				port->adrfam);
		}
	}
	if (!strcmp(port->trtype, "fc") || !strcmp(port->trtype, "loop")) {
		if (!strcmp(port->adrfam, port->trtype)) {
			strcpy(port->adrfam, port->trtype);
		}
		if (strlen(port->trsvcid)) {
			memset(port->trsvcid, 0, sizeof(port->trsvcid));
		}
	}
	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;

	ret = asprintf(&sql, add_port_sql, port->trtype, port->adrfam,
		       port->treq, port->traddr, port->trsvcid,
		       port->tsas, subtype);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_simple(sql);
	free(sql);
	ret = asprintf(&sql, select_portid_sql, port->trtype,
		       port->adrfam, port->traddr, port->trsvcid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_int(sql, "id", &portid);
	if (ret < 0)
		goto rollback;

	fprintf(stderr, "Generated port id %d\n", portid);
	port->port_id = portid;

	if (!strlen(port->traddr)) {
		fprintf(stderr, "port %d: update traddr\n", port->port_id);
		sprintf(port->traddr, "%d", port->port_id);
		ret = asprintf(&sql, update_traddr_sql, port->traddr,
			       port->port_id);
		if (ret < 0)
			goto rollback;
		ret = sql_exec_simple(sql);
		free(sql);
		if (ret < 0)
			goto rollback;
	}
	ret = sql_exec_simple("COMMIT TRANSACTION;");
	if (ret)
		return ret;
	if (port->port_id > 0xfffc) {
		fprintf(stderr, "resetting port_id counter\n");
		ret = sql_exec_simple("UPDATE sqlite_sequence SET seq = 1 "
				      "WHERE name = 'port';");
	}
	return ret;
rollback:
	ret = sql_exec_simple("ROLLBACK TRANSACTION;");
	return ret;
}

static char port_get_inode_sql[] =
	"SELECT id AS ino FROM ports "
	"WHERE id = '%s' AND parent_ino = '%d';";

int inode_get_port_ino(const char *port, int parent_ino, int *inode)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, port_get_inode_sql, port, parent_ino);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "ino", inode);
	free(sql);
	return ret;
}

static char stat_port_sql[] =
	"SELECT unixepoch(ctime) AS tv FROM ports WHERE id = '%s';";

int inode_stat_port(const char *port, struct stat *stbuf)
{
	char *sql;
	int ret, timeval;

	ret = asprintf(&sql, stat_port_sql, port);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return -ENOENT;
	stbuf->st_mode = S_IFREG | 0444;
	stbuf->st_nlink = 1;
	stbuf->st_size = 256;
	stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
	return 0;
}

static char fill_port_dir_sql[] =
	"SELECT id FROM ports;";

int inode_fill_port_dir(void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *errmsg;
	int ret;

	ret = sqlite3_exec(inode_db, fill_port_dir_sql, fill_root_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", fill_port_dir_sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	return ret;
}

static char fill_port_sql[] =
	"SELECT * FROM ports WHERE id = '%s';";

int inode_fill_port(const char *port, void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = "addr_",
		.buf = buf,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, fill_port_sql, port);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(inode_db, sql, fill_filter_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else {
		filler(buf, "ana_groups", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "subsystems", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "referrals", NULL, 0, FUSE_FILL_DIR_PLUS);
		ret = 0;
	}
	free(sql);
	return ret;
}

static char get_port_attr_sql[] =
	"SELECT %s FROM ports WHERE id = '%s';";

int inode_get_port_attr(const char *portid, const char *attr, char *buf)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, get_port_attr_sql, attr, portid);
	if (ret < 0)
		return ret;

	ret = sql_exec_str(sql, attr, buf);
	free(sql);
	return ret;
}

static char update_genctr_port_sql[] =
	"UPDATE host SET genctr = genctr + 1 "
	"FROM "
	"(SELECT hs.host_id AS host_id, sp.id AS port_id "
	"FROM host_subsys AS hs "
	"INNER JOIN subsys_port AS sp ON hs.subsys_id = sp.subsys_id) "
	"AS hg WHERE hg.host_id = host.id AND hg.port_id = '%d';";

int inode_modify_port(struct nofuse_port *port, char *attr)
{
	char *value, *sql;
	int ret;

	if (!strcmp(attr, "trtype"))
		value = port->trtype;
	else if (!strcmp(attr, "traddr"))
		value = port->traddr;
	else if (!strcmp(attr, "trsvcid"))
		value = port->trsvcid;
	else if (!strcmp(attr, "adrfam"))
		value = port->adrfam;
	else if (!strcmp(attr, "tsas"))
		value = port->tsas;
	else if (!strcmp(attr, "treq"))
		value = port->treq;
	else
		return -EINVAL;

	ret = asprintf(&sql, "UPDATE ports SET %s = '%s' "
		       "WHERE id = '%d';", attr, value,
		       port->port_id);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	ret = asprintf(&sql, update_genctr_port_sql, port->port_id);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char del_port_sql[] =
	"DELETE FROM ports WHERE id = '%d';";

int inode_del_port(struct nofuse_port *port)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_port_sql, port->port_id);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

#if 0

static char add_host_subsys_sql[] =
	"INSERT INTO host_subsys (host_id, subsys_id) "
	"SELECT host.id, subsys.id FROM hosts, subsystems "
	"WHERE host.nqn LIKE '%s' AND subsys.nqn LIKE '%s';";

int discdb_add_host_subsys(struct nvmet_host *host, struct nvmet_subsys *subsys)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_host_subsys_sql,
		       host->hostnqn, subsys->subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	ret = asprintf(&sql, "UPDATE host SET genctr = genctr + 1 "
		       "WHERE nqn LIKE '%s';", host->hostnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char del_host_subsys_sql[] =
	"DELETE FROM host_subsys AS hs "
	"WHERE hs.host_id IN "
	"(SELECT id FROM hosts WHERE nqn LIKE '%s') AND "
	"hs.subsys_id IN "
	"(SELECT id FROM subsystems WHERE nqn LIKE '%s');";

int discdb_del_host_subsys(struct nvmet_host *host, struct nvmet_subsys *subsys)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_host_subsys_sql,
		       host->hostnqn, subsys->subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_subsys_port_sql[] =
	"INSERT INTO subsys_port (subsys_id, port_id) "
	"SELECT s.id, p.id FROM subsystems AS s, ports AS p "
	"WHERE s.nqn LIKE '%s' AND p.id = '%d';";

static char update_genctr_host_subsys_sql[] =
	"UPDATE hosts SET genctr = genctr + 1 "
	"FROM "
	"(SELECT s.nqn AS subsys_nqn, hs.host_id AS host_id "
	"FROM host_subsys AS hs "
	"INNER JOIN subsystems AS s ON s.id = hs.subsys_id) AS hs "
	"WHERE hs.host_id = host.id AND hs.subsys_nqn LIKE '%s';";

int discdb_add_subsys_port(struct nvmet_subsys *subsys, struct nvmet_port *port)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_subsys_port_sql,
		       subsys->subsysnqn, port->port_id);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	ret = asprintf(&sql, update_genctr_host_subsys_sql,
		       subsys->subsysnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);

	return ret;
}

static char del_subsys_port_sql[] =
	"DELETE FROM subsys_port AS sp "
	"WHERE sp.subsys_id in "
	"(SELECT id FROM subsystems WHERE nqn LIKE '%s') AND "
	"sp.port_id IN "
	"(SELECT id FROM ports WHERE id = %d);";

int discdb_del_subsys_port(struct nvmet_subsys *subsys, struct nvmet_port *port)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_subsys_port_sql,
		       subsys->subsysnqn, port->port_id);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	ret = asprintf(&sql, update_genctr_host_subsys_sql,
		       subsys->subsysnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);

	return ret;
}

static char count_subsys_port_sql[] =
	"SELECT count(p.id) AS portnum "
	"FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN ports AS p ON p.id = sp.port_id "
	"WHERE p.trtype = '%s' AND p.traddr = '%s' AND p.trsvcid != '%d';";


int discdb_count_subsys_port(struct nvmet_port *port, int trsvcid)
{
	char *sql, *errmsg;
	struct sql_int_value_parm parm = {
		.col = "portnum",
		.val = 0,
		.done = 0,
	};
	int ret;

	ret = asprintf(&sql, count_subsys_port_sql, port->trtype,
		       port->traddr, trsvcid);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(nvme_db, sql, sql_int_value_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		parm.done = -EINVAL;
	}
	free(sql);
	if (parm.done > 0) {
		ret = parm.val;
	} else if (parm.done < 0) {
		ret = parm.done;
	} else {
		ret = 0;
	}
	return ret;
}

struct sql_disc_entry_parm {
	u8 *buffer;
	int cur;
	int len;
};

static int sql_disc_entry_cb(void *argp, int argc, char **argv, char **colname)
{
	int i;
	struct sql_disc_entry_parm *parm = argp;
	struct nvmf_disc_rsp_page_entry *entry;

	if (!argp) {
		fprintf(stderr, "%s: Invalid parameter\n", __func__);
		return 0;
	}
	if (!parm->buffer)
		goto next;
	entry = (struct nvmf_disc_rsp_page_entry *)(parm->buffer + parm->cur);
	if (parm->cur >= parm->len)
		goto next;

	memset(entry, 0, sizeof(*entry));
	entry->cntlid = (u16)NVME_CNTLID_DYNAMIC;
	entry->asqsz = htole16(32);
	entry->subtype = NVME_NQN_NVME;
	entry->treq = NVMF_TREQ_NOT_SPECIFIED;
	entry->tsas.tcp.sectype = NVMF_TCP_SECTYPE_NONE;

	for (i = 0; i < argc; i++) {
		size_t arg_len = argv[i] ? strlen(argv[i]) : 0;

		if (!strcmp(colname[i], "subsys_nqn")) {
			if (arg_len > NVMF_NQN_FIELD_LEN)
				arg_len = NVMF_NQN_FIELD_LEN;
			strncpy(entry->subnqn, argv[i], arg_len);
		} else if (!strcmp(colname[i], "id")) {
			char *eptr = NULL;
			int val;

			val = strtol(argv[i], &eptr, 10);
			if (argv[i] == eptr)
				continue;
			entry->portid = htole16(val);
		} else if (!strcmp(colname[i], "subtype")) {
			char *eptr = NULL;
			int val;

			val = strtol(argv[i], &eptr, 10);
			if (argv[i] == eptr)
				continue;
			entry->subtype = val;
		} else if (!strcmp(colname[i], "adrfam")) {
			if (!strcmp(argv[i], "ipv4")) {
				entry->adrfam = NVMF_ADDR_FAMILY_IP4;
			} else if (!strcmp(argv[i], "ipv6")) {
				entry->adrfam = NVMF_ADDR_FAMILY_IP6;
			} else if (!strcmp(argv[i], "fc")) {
				entry->adrfam = NVMF_ADDR_FAMILY_FC;
			} else if (!strcmp(argv[i], "ib")) {
				entry->adrfam = NVMF_ADDR_FAMILY_IB;
			} else if (!strcmp(argv[i], "pci")) {
				entry->adrfam = NVMF_ADDR_FAMILY_PCI;
			} else {
				entry->adrfam = NVMF_ADDR_FAMILY_LOOP;
			}
		} else if (!strcmp(colname[i], "trtype")) {
			if (!strcmp(argv[i], "tcp")) {
				entry->trtype = NVMF_TRTYPE_TCP;
			} else if (!strcmp(argv[i], "fc")) {
				entry->trtype = NVMF_TRTYPE_FC;
			} else if (!strcmp(argv[i], "rdma")) {
				entry->trtype = NVMF_TRTYPE_RDMA;
			} else {
				entry->trtype = NVMF_TRTYPE_LOOP;
			}
		} else if (!strcmp(colname[i], "traddr")) {
			if (!arg_len) {
				memset(entry->traddr, 0,
				       NVMF_NQN_FIELD_LEN);
				continue;
			}
			if (arg_len > NVMF_NQN_FIELD_LEN)
				arg_len = NVMF_NQN_FIELD_LEN;
			memcpy(entry->traddr, argv[i], arg_len);
		} else if (!strcmp(colname[i], "trsvcid")) {
			if (!arg_len) {
				memset(entry->trsvcid, 0,
				       NVMF_TRSVCID_SIZE);
				continue;
			}
			if (arg_len > NVMF_TRSVCID_SIZE)
				arg_len = NVMF_TRSVCID_SIZE;
			memcpy(entry->trsvcid, argv[i], arg_len);
		} else if (!strcmp(colname[i], "treq")) {
			if (arg_len &&
			    !strcmp(argv[i], "required")) {
				entry->treq = NVMF_TREQ_REQUIRED;
			} else if (arg_len &&
				   !strcmp(argv[i], "not required")) {
				entry->treq = NVMF_TREQ_NOT_REQUIRED;
			}
		} else if (!strcmp(colname[i], "tsas")) {
			if (arg_len && !strcmp(argv[i], "tls13")) {
				entry->tsas.tcp.sectype =
					NVMF_TCP_SECTYPE_TLS13;
			} else {
				entry->tsas.tcp.sectype =
					NVMF_TCP_SECTYPE_NONE;
			}
		} else {
			fprintf(stderr, "skip discovery type '%s'\n",
				colname[i]);
		}
	}
	if (entry->trtype == NVMF_TRTYPE_LOOP)
		entry->adrfam = NVMF_ADDR_FAMILY_LOOP;
	if (entry->trtype == NVMF_TRTYPE_FC)
		entry->adrfam = NVMF_ADDR_FAMILY_FC;
	if (entry->trtype == NVMF_TRTYPE_TCP &&
	    (entry->adrfam != NVMF_ADDR_FAMILY_IP4 &&
	     entry->adrfam != NVMF_ADDR_FAMILY_IP6)) {
		if (strchr(entry->traddr, ':'))
			entry->adrfam = NVMF_ADDR_FAMILY_IP6;
		else
			entry->adrfam = NVMF_ADDR_FAMILY_IP4;
	}
	if (!strlen(entry->traddr)) {
		fprintf(stderr, "Empty discovery record (%d, %d)\n",
			entry->portid, entry->trtype);
		return 0;
	}
next:
	parm->cur += sizeof(struct nvmf_disc_rsp_page_entry);
	return 0;
}

static char host_disc_entry_sql[] =
	"SELECT s.nqn AS subsys_nqn, "
	"p.id, p.subtype, p.trtype, p.traddr, p.trsvcid, p.treq, p.tsas "
	"FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN host_subsys AS hs ON hs.subsys_id = sp.subsys_id "
	"INNER JOIN hosts AS h ON hs.host_id = h.id "
	"INNER JOIN ports AS p ON sp.port_id = p.id "
	"WHERE h.nqn LIKE '%s';";

int discdb_host_disc_entries(const char *hostnqn, u8 *log, int log_len)
{
	struct sql_disc_entry_parm parm = {
		.buffer = log,
		.cur = 0,
		.len = log_len,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, host_disc_entry_sql, hostnqn);
	if (ret < 0)
		return ret;
	printf("Display disc entries for %s\n", hostnqn);
	ret = sqlite3_exec(nvme_db, sql, sql_disc_entry_cb, &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
	}
	free(sql);
	printf("disc entries: cur %d len %d\n", parm.cur, parm.len);
	ret = asprintf(&sql, host_disc_entry_sql, NVME_DISC_SUBSYS_NAME);
	if (ret < 0)
		return parm.cur;
	printf("Display disc entries for %s\n", NVME_DISC_SUBSYS_NAME);
	ret = sqlite3_exec(nvme_db, sql, sql_disc_entry_cb, &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
	}
	free(sql);
	printf("disc entries: cur %d len %d\n", parm.cur, parm.len);
	return parm.cur;
}

static char host_genctr_sql[] =
	"SELECT genctr FROM hosts WHERE nqn LIKE '%s';";

int discdb_host_genctr(const char *hostnqn)
{
	char *sql, *errmsg;
	struct sql_int_value_parm parm = {
		.col = "genctr",
		.val = 0,
		.done = 0,
	};
	int ret;

	ret = asprintf(&sql, host_genctr_sql, hostnqn);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(nvme_db, sql, sql_int_value_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		parm.done = -EINVAL;
	}
	free(sql);
	if (parm.done < 0) {
		errno = -parm.done;
		ret = -1;
	} else if (!parm.done) {
		return 0;
	} else {
		ret = parm.val;
	}
	return ret;
}

#endif

static int inode_create_root(void)
{
	hosts_ino = inode_add_root("hosts");
	if (hosts_ino < 0)
		return hosts_ino;
	subsys_ino = inode_add_root("subsystems");
	if (subsys_ino < 0) {
		inode_del_inode(hosts_ino);
		return subsys_ino;
	}
	ports_ino = inode_add_root("ports");
	if (ports_ino < 0) {
		inode_del_inode(subsys_ino);
		inode_del_inode(hosts_ino);
		return ports_ino;
	}
	return 0;
}

int inode_open(const char *filename)
{
	int ret;

	ret = sqlite3_open(filename, &inode_db);
	if (ret) {
		fprintf(stderr, "Can't open database: %s\n",
			sqlite3_errmsg(inode_db));
		sqlite3_close(inode_db);
		return -ENOENT;
	}
	ret = inode_init();
	if (ret) {
		fprintf(stderr, "Can't initialize database, error %d\n", ret);
		sqlite3_close(inode_db);
	}
	ret = inode_create_root();
	return ret;
}

void inode_close(const char *filename)
{
	inode_exit();
	sqlite3_close(inode_db);
	unlink(filename);
}
