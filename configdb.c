/*
 * configdb.c
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

#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <errno.h>

#include "common.h"
#include "configdb.h"

static sqlite3 *configdb_db;

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

	ret = sqlite3_exec(configdb_db, sql_str, sql_simple_cb, NULL, &errmsg);
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

static int sql_exec_int(const char *sql, const char *col, int *value)
{
	char *errmsg;
	struct sql_int_value_parm parm = {
		.col = col,
		.val = 0,
		.done = 0,
	};
	int ret;

	ret = sqlite3_exec(configdb_db, sql, sql_int_value_cb,
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
	else if (parm.done > 0) {
		if (value)
			*value = parm.val;
		parm.done = 0;
	} else {
		fprintf(stderr, "no value for '%s'\n", col);
		*value = 0;
		parm.done = -ENOENT;
	}
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

	ret = sqlite3_exec(configdb_db, sql, sql_str_value_cb,
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
	else if (parm.done > 0)
		parm.done = 0;
	else {
		fprintf(stderr, "no value for '%s'\n", col);
		parm.done = -ENOENT;
	}
	return parm.done;
}

#define NUM_TABLES 9

static const char *init_sql[NUM_TABLES] = {
"CREATE TABLE hosts ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
"nqn VARCHAR(223) UNIQUE NOT NULL, genctr INTEGER DEFAULT 0, "
"ctime TIME, atime TIME, mtime TIME );",
"CREATE TABLE subsystems ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
"nqn VARCHAR(223) UNIQUE NOT NULL, attr_allow_any_host INT DEFAULT 1, "
"attr_firmware VARCHAR(256), attr_ieee_oui VARCHAR(256), "
"attr_model VARCHAR(256), attr_serial VARCHAR(256), attr_version VARCHAR(256), "
"attr_type INT DEFAULT 3, ctime TIME, atime TIME, mtime TIME, "
"CHECK (attr_allow_any_host = 0 OR attr_allow_any_host = 1) );",
"CREATE TABLE namespaces ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
"device_nguid VARCHAR(256), device_uuid VARCHAR(256) UNIQUE NOT NULL, "
"device_path VARCHAR(256), device_enable INT DEFAULT 0, ana_grpid INT, "
"nsid INTEGER NOT NULL, subsys_id INTEGER, ctime TIME, atime TIME, mtime TIME, "
"CHECK (device_enable = 0 OR device_enable = 1), "
"FOREIGN KEY (subsys_id) REFERENCES subsystems(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT );",
"CREATE TABLE ports ( id INTEGER PRIMARY KEY, "
"addr_trtype CHAR(32) NOT NULL, addr_adrfam CHAR(32) DEFAULT '', "
"addr_treq char(32), "
"addr_traddr CHAR(255) NOT NULL, addr_trsvcid CHAR(32) DEFAULT '', "
"addr_tsas CHAR(255) DEFAULT '', "
"ctime TIME, atime TIME, mtime TIME, "
"UNIQUE(addr_trtype,addr_adrfam,addr_traddr,addr_trsvcid) );",
"CREATE UNIQUE INDEX port_addr_idx ON "
"ports(addr_trtype, addr_adrfam, addr_traddr, addr_trsvcid);",
"CREATE TABLE ana_groups ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
"grpid INT, ana_state INT DEFAULT 1, port_id INTEGER, "
"ctime TIME, atime TIME, mtime TIME, "
"UNIQUE(port_id, grpid), "
"FOREIGN KEY (port_id) REFERENCES ports(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT );",
"CREATE UNIQUE INDEX ana_group_idx ON "
"ana_groups(port_id, grpid);",
"CREATE TABLE host_subsys ( host_id INTEGER, subsys_id INTEGER, "
"ctime TIME, atime TIME, mtime TIME, "
"FOREIGN KEY (host_id) REFERENCES host(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT, "
"FOREIGN KEY (subsys_id) REFERENCES subsys(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT);",
"CREATE TABLE subsys_port ( subsys_id INTEGER, port_id INTEGER, "
"ctime TIME, atime TIME, mtime TIME, "
"FOREIGN KEY (subsys_id) REFERENCES subsystems(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT, "
"FOREIGN KEY (port_id) REFERENCES ports(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT);",
};

int configdb_init(void)
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
	"DROP INDEX ana_group_idx;",
	"DROP TABLE ana_groups;",
	"DROP INDEX port_addr_idx;",
	"DROP TABLE ports;",
	"DROP TABLE namespaces;",
	"DROP TABLE subsystems;",
	"DROP TABLE hosts;",
};

int configdb_exit(void)
{
	int i, ret;

	for (i = 0; i < NUM_TABLES; i++) {
		ret = sql_exec_simple(exit_sql[i]);
	}
	return ret;
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

static char count_table_id_sql[] =
	"SELECT count(id) AS num FROM %s;";

int configdb_count_table(const char *tbl, int *num)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, count_table_id_sql, tbl);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "num", num);
	free(sql);

	return ret;
}

static char add_host_sql[] =
	"INSERT INTO hosts (nqn, ctime) VALUES ('%s', CURRENT_TIMESTAMP);";

int configdb_add_host(const char *nqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_host_sql, nqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	return ret;
}

static char stat_host_sql[] =
	"SELECT unixepoch(ctime) AS tv FROM hosts WHERE nqn = '%s';";

int configdb_stat_host(const char *hostnqn, struct stat *stbuf)
{
		char *sql;
	int ret, timeval;

	ret = asprintf(&sql, stat_host_sql, hostnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return ret;
	if (stbuf) {
		stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
	}
	return 0;
}

static char fill_host_dir_sql[] =
	"SELECT nqn FROM hosts;";

int configdb_fill_host_dir(void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *errmsg;
	int ret;

	ret = sqlite3_exec(configdb_db, fill_host_dir_sql, fill_root_cb,
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

int configdb_del_host(const char *nqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_host_sql, nqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_subsys_sql[] =
	"INSERT INTO subsystems "
	"(nqn, attr_model, attr_version, attr_ieee_oui, attr_allow_any_host, attr_type, ctime) "
	"VALUES ('%s', 'nofuse', '2.0', '851255', '%d', '%d', CURRENT_TIMESTAMP);";

int configdb_add_subsys(struct nofuse_subsys *subsys)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_subsys_sql, subsys->nqn,
		       subsys->allow_any, subsys->type);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char get_discover_nqn_sql[] =
	"SELECT nqn FROM subsystems WHERE attr_type = '3';";

int configdb_get_discovery_nqn(char *nqn)
{
	return sql_exec_str(get_discover_nqn_sql, "nqn", nqn);
}

static char set_discover_nqn_sql[] =
	"UPDATE subsystems SET nqn = '%s' WHERE attr_type = '3';";

int configdb_set_discovery_nqn(char *nqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, set_discover_nqn_sql, nqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char stat_subsys_sql[] =
	"SELECT unixepoch(ctime) AS tv FROM subsystems WHERE nqn = '%s';";

int configdb_stat_subsys(const char *subsysnqn, struct stat *stbuf)
{
	char *sql;
	int ret, timeval;

	ret = asprintf(&sql, stat_subsys_sql, subsysnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return ret;
	if (stbuf) {
		stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
	}
	return 0;
}

static char fill_subsys_dir_sql[] =
	"SELECT nqn FROM subsystems;";

int configdb_fill_subsys_dir(void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *errmsg;
	int ret;

	ret = sqlite3_exec(configdb_db, fill_subsys_dir_sql, fill_root_cb,
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

int configdb_fill_subsys(const char *nqn, void *buf, fuse_fill_dir_t filler)
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
	ret = sqlite3_exec(configdb_db, sql, fill_filter_cb,
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

int configdb_get_subsys_attr(const char *nqn, const char *attr, char *buf)
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

static char set_subsys_attr_sql[] =
	"UPDATE subsystems SET %s = '%s' "
	"WHERE nqn = '%s';";

int configdb_set_subsys_attr(const char *nqn, const char *attr, const char *buf)
{
	char *sql;
	int ret;

	if (!strcmp(attr, "attr_type"))
		return -EPERM;
	ret = asprintf(&sql, set_subsys_attr_sql, attr, buf, nqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	if (sqlite3_changes(configdb_db) == 0)
		ret = -EPERM;
	return ret;
}

static char del_subsys_sql[] =
	"DELETE FROM subsystems WHERE nqn = '%s';";

int configdb_del_subsys(struct nofuse_subsys *subsys)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_subsys_sql, subsys->nqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_namespace_sql[] =
	"INSERT INTO namespaces (device_uuid, nsid, subsys_id, ctime) "
	"SELECT '%s', '%d', s.id, CURRENT_TIMESTAMP "
	"FROM subsystems AS s WHERE s.nqn = '%s' AND s.attr_type == '2';";

int configdb_add_namespace(const char *subsysnqn, int nsid)
{
	char *sql;
	uuid_t uuid;
	char uuid_str[65];
	int ret;

	uuid_generate(uuid);
	uuid_unparse(uuid, uuid_str);
	ret = asprintf(&sql, add_namespace_sql, uuid_str,
		       nsid, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	if (sqlite3_changes(configdb_db) == 0)
		return -EPERM;
	return ret;
}

static char count_namespaces_sql[] =
	"SELECT count(n.id) AS num FROM namespaces AS n "
	"INNER JOIN subsystems AS s ON s.id = n.subsys_id "
	"WHERE s.nqn = '%s';";

int configdb_count_namespaces(const char *subsysnqn, int *num)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, count_namespaces_sql, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "num", num);
	free(sql);

	return ret;
}

static char stat_namespace_sql[] =
	"SELECT unixepoch(n.ctime) AS tv FROM namespaces AS n "
	"INNER JOIN subsystems AS s ON s.id = n.subsys_id "
	"WHERE s.nqn = '%s' AND n.nsid = '%d';";

int configdb_stat_namespace(const char *subsysnqn, int nsid,
			 struct stat *stbuf)
{
	char *sql;
	int ret, timeval;

	ret = asprintf(&sql, stat_namespace_sql, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return ret;
	if (stbuf)
		stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
	return 0;
}

static char fill_namespace_dir_sql[] =
	"SELECT n.nsid AS nsid FROM namespaces AS n "
	"INNER JOIN subsystems AS s ON s.id = n.subsys_id "
	"WHERE s.nqn = '%s';";

int configdb_fill_namespace_dir(const char *nqn, void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, fill_namespace_dir_sql, nqn);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, fill_root_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;

	free(sql);
	return ret;
}

static char fill_namespace_sql[] =
	"SELECT n.* FROM namespaces AS n "
	"INNER JOIN subsystems AS s ON s.id = n.subsys_id "
	"WHERE s.nqn = '%s' AND n.nsid = '%d';";

static int fill_ns_cb(void *p, int argc, char **argv, char **colname)
{
	struct fill_parm_t *parm = p;
	const char prefix[] = "device_";
	int i;

	for (i = 0; i < argc; i++) {
		if (!strcmp(colname[i], "ana_grpid")) {
			parm->filler(parm->buf, colname[i], NULL,
				     0, FUSE_FILL_DIR_PLUS);
			continue;
		}
		if (strncmp(colname[i], prefix, strlen(prefix)))
			continue;
		if (!strcmp(colname[i], "device_enable"))
			parm->filler(parm->buf, colname[i] + strlen(prefix),
				     NULL, 0, FUSE_FILL_DIR_PLUS);
		else
			parm->filler(parm->buf, colname[i], NULL,
				     0, FUSE_FILL_DIR_PLUS);
	}
	return 0;
}

int configdb_fill_namespace(const char *nqn, int nsid,
			 void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, fill_namespace_sql, nqn, nsid);
	if (ret < 0)
		return ret;

	ret = sqlite3_exec(configdb_db, sql, fill_ns_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;

	free(sql);
	return ret;
}

static char get_namespace_attr_sql[] =
	"SELECT ns.%s FROM namespaces AS ns "
	"INNER JOIN subsystems AS s ON s.id = ns.subsys_id "
	"WHERE s.nqn = '%s' AND ns.nsid = '%d';";

int configdb_get_namespace_attr(const char *subsysnqn, int nsid,
			     const char *attr, char *buf)
{
	int ret;
	char *sql;

	if (!strcmp(attr, "enable"))
		attr = "device_enable";
	ret = asprintf(&sql, get_namespace_attr_sql, attr, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = sql_exec_str(sql, attr, buf);
	free(sql);
	return ret;
}

static char set_namespace_attr_sql[] =
	"UPDATE namespaces SET %s = '%s' FROM "
	"(SELECT ns.nsid AS nsid, s.nqn AS nqn "
	"FROM namespaces AS ns "
	"INNER JOIN subsystems AS s ON s.id = ns.subsys_id) AS sel "
	"WHERE sel.nqn = '%s' AND sel.nsid = '%d';";

int configdb_set_namespace_attr(const char *subsysnqn, int nsid,
			     const char *attr, const char *buf)
{
	int ret;
	char *sql;

	if (!strcmp(attr, "enable"))
		attr = "device_enable";
	ret = asprintf(&sql, set_namespace_attr_sql, attr, buf,
		       subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char get_namespace_anagrp_sql[] =
	"SELECT ns.ana_grpid AS grpid FROM namespaces AS ns "
	"INNER JOIN subsystems AS s ON s.id = ns.subsys_id "
	"WHERE s.nqn = '%s' AND ns.nsid = '%d';";

int configdb_get_namespace_anagrp(const char *subsysnqn, int nsid,
			       int *ana_grpid)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, get_namespace_anagrp_sql, subsysnqn, nsid);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "grpid", ana_grpid);
	free(sql);
	return ret;
}

static char set_namespace_anagrp_sql[] =
	"UPDATE namespaces SET ana_grpid = sel.grpid "
	"FROM "
	"(SELECT s.nqn AS subsysnqn, p.id AS portid, ag.grpid AS grpid "
	"FROM  subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN ports AS p ON p.id = sp.port_id "
	"INNER JOIN ana_groups AS ag ON ag.port_id = p.id) AS sel "
	"WHERE sel.subsysnqn = '%s' "
	"AND sel.grpid = '%d' AND nsid = '%d';";

int configdb_set_namespace_anagrp(const char *subsysnqn, int nsid,
			       int ana_grpid)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, set_namespace_anagrp_sql,
		       subsysnqn, ana_grpid, nsid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char del_namespace_sql[] =
	"DELETE FROM namespaces AS ns WHERE ns.subsys_id IN "
	"(SELECT id FROM subsystems WHERE nqn = '%s') AND "
	"ns.nsid = '%d';";

int configdb_del_namespace(const char *subsysnqn, int nsid)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, del_namespace_sql, subsysnqn, nsid);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_port_sql[] =
	"INSERT INTO ports (id, addr_trtype, addr_traddr, addr_adrfam, ctime)"
	" VALUES ('%d', 'tcp', '127.0.0.1', 'ipv4', CURRENT_TIMESTAMP);";

int configdb_add_port(unsigned int portid)
{
	char *sql;
	int ret;

	if (!portid) {
		fprintf(stderr, "no port id specified\n");
		return -EINVAL;
	}

	ret = asprintf(&sql, add_port_sql, portid);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char stat_port_sql[] =
	"SELECT unixepoch(ctime) AS tv FROM ports WHERE id = '%d';";

int configdb_stat_port(unsigned int port, struct stat *stbuf)
{
	char *sql;
	int ret, timeval;

	ret = asprintf(&sql, stat_port_sql, port);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return ret;
	if (stbuf) {
		stbuf->st_nlink = 1;
		stbuf->st_size = 256;
		stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
	}
	return 0;
}

static char fill_port_dir_sql[] =
	"SELECT id FROM ports;";

int configdb_fill_port_dir(void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *errmsg;
	int ret;

	ret = sqlite3_exec(configdb_db, fill_port_dir_sql, fill_root_cb,
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
	"SELECT * FROM ports WHERE id = '%d';";

int configdb_fill_port(unsigned int port, void *buf, fuse_fill_dir_t filler)
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
	ret = sqlite3_exec(configdb_db, sql, fill_filter_cb,
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
	"SELECT %s FROM ports WHERE id = '%d';";

int configdb_get_port_attr(unsigned int port, const char *attr, char *buf)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, get_port_attr_sql, attr, port);
	if (ret < 0)
		return ret;

	ret = sql_exec_str(sql, attr, buf);
	free(sql);
	return ret;
}

static char update_genctr_port_sql[] =
	"UPDATE hosts SET genctr = genctr + 1 "
	"FROM "
	"(SELECT hs.host_id AS host_id, sp.port_id AS port_id "
	"FROM host_subsys AS hs "
	"INNER JOIN subsys_port AS sp ON hs.subsys_id = sp.subsys_id) "
	"AS hg WHERE hg.host_id = hosts.id AND hg.port_id = '%d';";

int configdb_set_port_attr(unsigned int port, const char *attr, const char *value)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, "UPDATE ports SET %s = '%s' "
		       "WHERE id = '%d';", attr, value, port);
	if (ret < 0) {
		return ret;
	}
	ret = sql_exec_simple(sql);
	free(sql);
	ret = asprintf(&sql, update_genctr_port_sql, port);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char del_port_sql[] =
	"DELETE FROM ports WHERE id = '%d';";

int configdb_del_port(unsigned int portid)
{
	char *sql;
	int ret, portnum = 0;

	ret = configdb_count_subsys_port(portid, &portnum);
	if (ret < 0)
		return ret;
	if (portnum > 0)
		return -EBUSY;
	ret = asprintf(&sql, del_port_sql, portid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_ana_group_sql[] =
	"INSERT INTO ana_groups (grpid, port_id, ctime) "
	"SELECT '%d', p.id, CURRENT_TIMESTAMP "
	"FROM ports AS p WHERE p.id = '%d';";

int configdb_add_ana_group(int port, int grpid, int ana_state)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_ana_group_sql, grpid, port, ana_state);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0) {
		sql_exec_simple("SELECT * FROM ana_groups;");
		sql_exec_simple("SELECT * FROM ports;");
	}

	return ret;
}

static char count_ana_groups_sql[] =
	"SELECT count(ag.id) AS num FROM ana_groups AS ag "
	"INNER JOIN ports AS p ON p.id = ag.port_id "
	"WHERE p.id = '%s';";

int configdb_count_ana_groups(const char *port, int *num)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, count_ana_groups_sql, port);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "num", num);
	free(sql);

	return ret;
}

static char stat_ana_group_sql[] =
	"SELECT unixepoch(ag.ctime) AS tv FROM ana_groups AS ag "
	"INNER JOIN ports AS p ON p.id = ag.port_id "
	"WHERE p.id = '%s' AND ag.grpid = '%s';";

int configdb_stat_ana_group(const char *port, const char *ana_grpid,
			 struct stat *stbuf)
{
	int ret, timeval;
	char *sql;

	ret = asprintf(&sql, stat_ana_group_sql, port, ana_grpid);
	if (ret < 0)
		return ret;
	sql_exec_simple("SELECT * FROM ana_groups;");
	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return ret;
	if (stbuf) {
		stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
		stbuf->st_mode = S_IFREG | 0644;
		stbuf->st_nlink = 1;
		stbuf->st_size = 64;
	}
	return 0;
}

static char fill_ana_groups_sql[] =
	"SELECT ag.grpid AS grpid FROM ana_groups AS ag "
	"INNER JOIN ports AS p ON p.id = ag.port_id "
	"WHERE p.id = '%s';";

int configdb_fill_ana_groups(const char *port,
			  void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, fill_ana_groups_sql, port);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, fill_root_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", fill_host_dir_sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	free(sql);
	return ret;
}

static char get_ana_group_sql[] =
	"SELECT ag.ana_state AS ana_state FROM ana_groups AS ag "
	"INNER JOIN ports AS p ON p.id = ag.port_id "
	"WHERE p.id = '%s' AND ag.grpid = '%s';";

int configdb_get_ana_group(const char *port, const char *ana_grpid,
			int *ana_state)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, get_ana_group_sql, port, ana_grpid);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "ana_state", ana_state);
	free(sql);
	return ret;
}

static char set_ana_group_sql[] =
	"UPDATE ana_groups SET ana_state = '%d' "
	"WHERE port_id = '%s' AND grpid = '%s';";

int configdb_set_ana_group(const char *port, const char *ana_grpid,
			int ana_state)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, set_ana_group_sql, ana_state, port, ana_grpid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char del_ana_group_sql[] =
	"DELETE FROM ana_groups AS ag WHERE ag.port_id IN "
	"(SELECT id FROM ports WHERE id = '%d') AND "
	"ag.grpid = '%d';";

int configdb_del_ana_group(unsigned int portid, int grpid)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_ana_group_sql, portid, grpid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	return ret;
}

static char add_host_subsys_sql[] =
	"INSERT INTO host_subsys (host_id, subsys_id, ctime) "
	"SELECT h.id, s.id, CURRENT_TIMESTAMP FROM hosts AS h, subsystems AS s "
	"WHERE h.nqn = '%s' AND s.nqn = '%s' AND s.attr_allow_any_host != '1';";

int configdb_add_host_subsys(const char *hostnqn, const char *subsysnqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_host_subsys_sql,
		       hostnqn, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	ret = asprintf(&sql, "UPDATE hosts SET genctr = genctr + 1 "
		       "WHERE nqn = '%s';", hostnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char fill_host_subsys_sql[] =
	"SELECT h.nqn AS hostnqn FROM host_subsys AS hs "
	"INNER JOIN hosts AS h ON h.id = hs.host_id "
	"INNER JOIN subsystems AS s ON s.id = hs.subsys_id "
	"WHERE s.nqn = '%s';";

int configdb_fill_host_subsys(const char *subsysnqn,
			   void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, fill_host_subsys_sql, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, fill_root_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", fill_host_dir_sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	free(sql);
	return ret;
}

static char count_host_subsys_sql[] =
	"SELECT count(hs.host_id) AS num FROM host_subsys AS hs "
	"INNER JOIN subsystems AS s ON s.id = hs.subsys_id "
	"WHERE s.nqn = '%s';";

int configdb_count_host_subsys(const char *subsysnqn, int *num_hosts)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, count_host_subsys_sql, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "num", num_hosts);
	free(sql);
	return ret;
}

static char stat_host_subsys_sql[] =
	"SELECT unixepoch(hs.ctime) AS tv FROM host_subsys AS hs "
	"INNER JOIN subsystems AS s ON s.id = hs.subsys_id "
	"INNER JOIN hosts AS h ON h.id = hs.host_id "
	"WHERE h.nqn = '%s' AND s.nqn = '%s';";

int configdb_stat_host_subsys(const char *hostnqn, const char *subsysnqn,
			   struct stat *stbuf)
{
	char *sql;
	int ret, timeval;

	ret = asprintf(&sql, stat_host_subsys_sql, hostnqn, subsysnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return ret;
	if (stbuf) {
		stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
		stbuf->st_mode = S_IFLNK | 0755;
		stbuf->st_nlink = 1;
	}
	return 0;
}

static char del_host_subsys_sql[] =
	"DELETE FROM host_subsys AS hs "
	"WHERE hs.host_id IN "
	"(SELECT id FROM hosts WHERE nqn = '%s') AND "
	"hs.subsys_id IN "
	"(SELECT id FROM subsystems WHERE nqn = '%s');";

int configdb_del_host_subsys(const char *hostnqn, const char *subsysnqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_host_subsys_sql,
		       hostnqn, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_subsys_port_sql[] =
	"INSERT INTO subsys_port (subsys_id, port_id, ctime) "
	"SELECT s.id, p.id, CURRENT_TIMESTAMP FROM subsystems AS s, ports AS p "
	"WHERE s.nqn = '%s' AND p.id = '%d';";

static char update_genctr_host_subsys_sql[] =
	"UPDATE hosts SET genctr = genctr + 1 "
	"FROM "
	"(SELECT s.nqn AS subsys_nqn, hs.host_id AS host_id "
	"FROM host_subsys AS hs "
	"INNER JOIN subsystems AS s ON s.id = hs.subsys_id) AS hs "
	"WHERE hs.host_id = hosts.id AND hs.subsys_nqn = '%s';";

int configdb_add_subsys_port(const char *subsysnqn, unsigned int port)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_subsys_port_sql,
		       subsysnqn, port);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);

	ret = asprintf(&sql, update_genctr_host_subsys_sql,
		       subsysnqn);
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

int configdb_del_subsys_port(const char *subsysnqn, unsigned int port)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_subsys_port_sql,
		       subsysnqn, port);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);

	ret = asprintf(&sql, update_genctr_host_subsys_sql,
		       subsysnqn);
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
	"WHERE p.id = '%d';";


int configdb_count_subsys_port(unsigned int port, int *portnum)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, count_subsys_port_sql, port);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "portnum", portnum);
	free(sql);
	return ret;
}

static char fill_subsys_port_sql[] =
	"SELECT s.nqn AS subsysnqn FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN ports AS p ON p.id = sp.port_id "
	"WHERE p.id = '%d';";

int configdb_fill_subsys_port(unsigned int port,
			   void *buf, fuse_fill_dir_t filler)
{
	struct fill_parm_t parm = {
		.filler = filler,
		.prefix = NULL,
		.buf = buf,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, fill_subsys_port_sql, port);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, fill_root_cb,
			   &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", fill_host_dir_sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	free(sql);
	return ret;
}

static char stat_subsys_port_sql[] =
	"SELECT unixepoch(sp.ctime) AS tv FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN ports AS p ON p.id = sp.port_id "
	"WHERE s.nqn = '%s' AND p.id = '%d';";

int configdb_stat_subsys_port(const char *subsysnqn, unsigned int port,
			   struct stat *stbuf)
{
	char *sql;
	int ret, timeval;

	ret = asprintf(&sql, stat_subsys_port_sql, subsysnqn, port);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "tv", &timeval);
	free(sql);
	if (ret < 0)
		return ret;
	if (stbuf) {
		stbuf->st_ctime = stbuf->st_atime = stbuf->st_mtime = timeval;
		stbuf->st_mode = S_IFLNK | 0755;
		stbuf->st_nlink = 1;
	}
	return 0;
}

static char allowed_host_sql[] =
	"SELECT count(s.nqn) AS subsys_num "
	"FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN host_subsys AS hs ON hs.subsys_id = sp.subsys_id "
	"INNER JOIN hosts AS h ON hs.host_id = h.id "
	"INNER JOIN ports AS p ON sp.port_id = p.id "
	"WHERE h.nqn = '%s' AND s.nqn = '%s' AND p.id = '%d';";

static char allow_any_sql[] =
	"SELECT count(s.nqn) AS subsys_num "
	"FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN ports AS p ON sp.port_id = p.id "
	"WHERE s.attr_allow_any_host = '1' "
	"AND s.nqn = '%s' AND p.id = '%d';";

int configdb_check_allowed_host(const char *hostnqn, const char *subsysnqn,
			     unsigned int portid)
{
	int ret, num = 0;
	char *sql;

	ret = asprintf(&sql, allowed_host_sql, hostnqn,
		       subsysnqn, portid);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "subsys_num", &num);
	free(sql);
	if (!ret && num > 0) {
		printf("host %s allowed from subsys %s\n",
		       hostnqn, subsysnqn);
		return num;
	}
	ret = asprintf(&sql, allow_any_sql, subsysnqn, portid);
	if (ret < 0)
		return ret;

	ret = sql_exec_int(sql, "subsys_num", &num);
	free(sql);
	if (ret < 0)
		return ret;
	if (num > 0)
		printf("any host allowed from subsys %s\n",
		       subsysnqn);
	return num;
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
	entry->subtype = NVME_NQN_NVM;
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
	"p.id, s.attr_type AS subtype, p.addr_trtype AS trtype, "
	"p.addr_traddr AS traddr, p.addr_trsvcid AS trsvcid, "
	"p.addr_treq AS treq, p.addr_tsas AS tsas "
	"FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN host_subsys AS hs ON hs.subsys_id = sp.subsys_id "
	"INNER JOIN hosts AS h ON hs.host_id = h.id "
	"INNER JOIN ports AS p ON sp.port_id = p.id "
	"WHERE h.nqn LIKE '%s';";

static char any_disc_entry_sql[] =
	"SELECT s.nqn AS subsys_nqn, "
	"p.id, s.attr_type AS subtype, p.addr_trtype AS trtype, "
	"p.addr_traddr AS traddr, p.addr_trsvcid AS trsvcid, "
	"p.addr_treq AS treq, p.addr_tsas AS tsas "
	"FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN ports AS p ON sp.port_id = p.id "
	"WHERE s.attr_allow_any_host = '1';";

int configdb_host_disc_entries(const char *hostnqn, u8 *log, int log_len)
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
	ret = sqlite3_exec(configdb_db, sql, sql_disc_entry_cb, &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
	}
	free(sql);
	printf("disc entries: cur %d len %d\n", parm.cur, parm.len);

	printf("Display disc entries for any host\n");
	ret = sqlite3_exec(configdb_db, any_disc_entry_sql,
			   sql_disc_entry_cb, &parm, &errmsg);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
	}
	printf("disc entries: cur %d len %d\n", parm.cur, parm.len);
	return parm.cur;
}

static char host_genctr_sql[] =
	"SELECT genctr FROM hosts WHERE nqn LIKE '%s';";

int configdb_host_genctr(const char *hostnqn, int *genctr)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, host_genctr_sql, hostnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "genctr", genctr);
	free(sql);
	return ret;
}

static char subsys_identify_ctrl_sql[] =
	"SELECT s.nqn, s.attr_firmware AS firmware, "
	"s.attr_ieee_oui AS ieee_oui, s.attr_model AS model, "
	"s.attr_serial AS serial, s.attr_type AS type, "
	"s.attr_version AS version "
	"FROM subsystems AS s WHERE s.nqn = '%s';";

static int subsys_identify_ctrl_cb(void *p, int argc, char **argv, char **col)
{
	struct nvme_id_ctrl *id = p;
	int i;

	for (i = 0; i < argc; i++) {
		if (!argv[i])
			continue;
		if (!strcmp(col[i], "nqn")) {
			strcpy(id->subnqn, argv[i]);
		} else if (!strcmp(col[i], "firmware")) {
			strcpy(id->fr, argv[i]);
		} else if (!strcmp(col[i], "model")) {
			strcpy(id->mn, argv[i]);
		} else if (!strcmp(col[i], "ieee_oui")) {
			u32 oui, oui_le;
			char *eptr = NULL;

			oui = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr)
				continue;
			oui_le = htole32(oui & 0xfff);
			memcpy(id->ieee, &oui_le, sizeof(id->ieee));
		} else if (!strcmp(col[i], "type")) {
			if (!strcmp(argv[i], "2"))
				id->cntrltype = NVME_CTRL_CNTRLTYPE_IO;
			else
				id->cntrltype = NVME_CTRL_CNTRLTYPE_DISC;
		} else if (!strcmp(col[i], "version")) {
			int maj, min;

			if (sscanf(argv[i], "%d.%d", &maj, &min) != 2) {
				maj = 2;
				min = 0;
			}
			id->ver = htole32((maj & 0xff) << 16 | (min & 0xff) << 8);
		}
	}
	return 0;
}

int configdb_subsys_identify_ctrl(const char *subsysnqn,
				  struct nvme_id_ctrl *id)
{
	int ret;
	char *sql, *errmsg;

	ret = asprintf(&sql, subsys_identify_ctrl_sql, subsysnqn);
	if (ret < 0)
		return ret;

	ret = sqlite3_exec(configdb_db, sql, subsys_identify_ctrl_cb,
			   id, &errmsg);
	free(sql);
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	return ret;
}

int configdb_open(const char *filename)
{
	int ret;

	ret = sqlite3_open(filename, &configdb_db);
	if (ret) {
		fprintf(stderr, "Can't open database: %s\n",
			sqlite3_errmsg(configdb_db));
		sqlite3_close(configdb_db);
		return -ENOENT;
	}
	ret = configdb_init();
	if (ret) {
		fprintf(stderr, "Can't initialize database, error %d\n", ret);
		sqlite3_close(configdb_db);
	}
	return ret;
}

void configdb_close(const char *filename)
{
	configdb_exit();
	sqlite3_close(configdb_db);
	unlink(filename);
}