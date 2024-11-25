/* SPDX-License-Identifier: DUAL GPL-2.0/BSD */
/*
 * configdb.c
 * SQLite3 configfs emulation
 *
 * Copyright (c) 2021 Hannes Reinecke <hare@suse.de>
 */
#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <errno.h>

#include "common.h"
#include "configdb.h"
#include "firmware.h"

static sqlite3 *configdb_db;

#define COMMIT_TRANSACTION \
	_ret = sql_exec_simple("COMMIT TRANSACTION;");	\
	if (_ret) {						\
		fprintf(stderr, "%s: commit failed, "		\
			"database inconsistent.\n", __func__);	\
		return _ret;					\
	}

#define ROLLBACK_TRANSACTION \
	_ret = sql_exec_simple("ROLLBACK TRANSACTION;");	\
	if (_ret) {						\
		fprintf(stderr, "%s: rollback failed, "		\
			"database inconsistent.\n", __func__);	\
		return _ret;					\
	}

static int sql_exec_error(int ret, const char *sql, char *errmsg)
{
	if (ret != SQLITE_OK) {
		fprintf(stderr, "SQL error executing %s\n", sql);
		fprintf(stderr, "SQL error: %s\n", errmsg);
		sqlite3_free(errmsg);
		ret = (ret == SQLITE_BUSY) ? -EBUSY : -EINVAL;
	} else
		ret = 0;
	return ret;
}

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

static int sql_exec_simple(const char *sql)
{
	int ret;
	char *errmsg = NULL;

	ret = sqlite3_exec(configdb_db, sql, sql_simple_cb, NULL, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
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
	ret = sql_exec_error(ret, sql, errmsg);
	if (ret < 0) {
		parm.done = -ret;
	}
	if (parm.done < 0)
		fprintf(stderr, "value error for '%s': %s\n", col,
			strerror(-parm.done));
	else if (parm.done > 0) {
		if (value)
			*value = parm.val;
		parm.done = 0;
	} else {
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
	ret = sql_exec_error(ret, sql, errmsg);
	if (ret < 0) {
		parm.done = ret;
	}
	if (parm.done < 0)
		fprintf(stderr, "value error for '%s': %s\n", col,
			strerror(-parm.done));
	else if (parm.done > 0)
		parm.done = 0;
	else
		parm.done = -ENOENT;
	return parm.done;
}

static int stat_cb(void *p, int argc, char **argv, char **col)
{
	struct stat *stbuf = p;
	int i;

	if (!p)
		return 0;
	for (i = 0; i < argc; i++) {
		unsigned long timeval;
		char *eptr = NULL;

		if (!argv[i] || !strlen(argv[i]))
			continue;
		timeval = strtoul(argv[i], &eptr, 10);
		if (timeval == ULONG_MAX || argv[i] == eptr)
			continue;
		if (!strcmp(col[i], "ctime")) {
			stbuf->st_ctime = timeval;
		} else if (strcmp(col[i], "mtime")) {
			stbuf->st_mtime = timeval;
		} else if (strcmp(col[i], "atime")) {
			stbuf->st_atime = timeval;
		}
	}
	return 0;
}

int sql_exec_stat(const char *sql, struct stat *stbuf)
{
	char *errmsg;
	struct stat st;
	int ret;

	if (!stbuf)
		stbuf = &st;
	stbuf->st_ctime = stbuf->st_mtime = stbuf->st_atime = 0;
		ret = sqlite3_exec(configdb_db, sql, stat_cb, stbuf, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	if (ret < 0)
		return ret;
	if (stbuf->st_ctime == 0)
		return -ENOENT;
	if (!stbuf->st_mtime)
		stbuf->st_mtime = stbuf->st_ctime;
	if (!stbuf->st_atime)
		stbuf->st_atime = stbuf->st_mtime;

	return ret;
}

#define NUM_TABLES 12

static const char *init_sql[NUM_TABLES] = {
	/* hosts */
	"CREATE TABLE hosts ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
	"nqn VARCHAR(223) UNIQUE NOT NULL, genctr INTEGER DEFAULT 0, "
	"ctime TIME, atime TIME, mtime TIME );",
	/* subsystems */
	"CREATE TABLE subsystems ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
	"nqn VARCHAR(223) UNIQUE NOT NULL, attr_allow_any_host INT DEFAULT 1, "
	"attr_firmware VARCHAR(256), attr_ieee_oui VARCHAR(256), "
	"attr_model VARCHAR(256), attr_serial VARCHAR(256), "
	"attr_version VARCHAR(256), "
	"attr_type INT DEFAULT 3, ctime TIME, atime TIME, mtime TIME, "
	"ana_chgcnt INT DEFAULT 0, "
	"CHECK (attr_allow_any_host = 0 OR attr_allow_any_host = 1) );",
	/* ana_groups */
	"CREATE TABLE ana_groups ( id INTEGER PRIMARY KEY, "
	"CHECK (id > 0) );"
	/* controllers */
	"CREATE TABLE controllers ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
	"cntlid INT, subsys_id INT, ctrl_type INT, max_queues INT, "
	"ana_chg_ctr INT, ns_chg_ctr INT, disc_chg_ctr INT, "
	"UNIQUE(cntlid, subsys_id), "
	"FOREIGN KEY (subsys_id) REFERENCES subsystems(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT );",
	/* cntlid index */
	"CREATE UNIQUE INDEX cntlid_idx ON "
	"controllers(cntlid, subsys_id);",
	/* namespaces */
	"CREATE TABLE namespaces ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
	"device_eui64 VARCHAR(256), device_nguid VARCHAR(256), "
	"device_uuid VARCHAR(256) UNIQUE NOT NULL, "
	"device_path VARCHAR(256), device_enable INT DEFAULT 0, "
	"ana_group_id INT, "
	"nsid INTEGER NOT NULL, subsys_id INTEGER, "
	"ctime TIME, atime TIME, mtime TIME, "
	"UNIQUE (subsys_id, nsid), "
	"CHECK (device_enable = 0 OR device_enable = 1), "
	"FOREIGN KEY (ana_group_id) REFERENCES ana_groups(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT, "
	"FOREIGN KEY (subsys_id) REFERENCES subsystems(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT );",
	/* nsid_idx */
	"CREATE UNIQUE INDEX nsid_idx ON "
	"namespaces(subsys_id, nsid); "
	/* ports */
	"CREATE TABLE ports ( id INTEGER PRIMARY KEY, "
	"addr_trtype CHAR(32) NOT NULL, addr_adrfam CHAR(32) DEFAULT '', "
	"addr_treq char(32), "
	"addr_traddr CHAR(255) NOT NULL, addr_trsvcid CHAR(32) DEFAULT '', "
	"addr_tsas CHAR(255) DEFAULT '', "
	"ctime TIME, atime TIME, mtime TIME, "
	"UNIQUE(addr_trtype,addr_adrfam,addr_traddr,addr_trsvcid) );",
	/* port_addr_idx */
	"CREATE UNIQUE INDEX port_addr_idx ON "
	"ports(addr_trtype, addr_adrfam, addr_traddr, addr_trsvcid);",
	/* ana_port_group */
	"CREATE TABLE ana_port_group ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
	"ana_group_id INT, ana_state INT DEFAULT '1', port_id INTEGER, "
	"chgcnt INT DEFAULT '0', ctime TIME, atime TIME, mtime TIME, "
	"FOREIGN KEY (ana_group_id) REFERENCES ana_groups(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT, "
	"FOREIGN KEY (port_id) REFERENCES ports(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT );",
	/* host_subsys */
	"CREATE TABLE host_subsys ( host_id INTEGER, subsys_id INTEGER, "
	"ctime TIME, atime TIME, mtime TIME, "
	"FOREIGN KEY (host_id) REFERENCES host(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT, "
	"FOREIGN KEY (subsys_id) REFERENCES subsys(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT);",
	/* subsys_port */
	"CREATE TABLE subsys_port ( subsys_id INTEGER, port_id INTEGER, "
	"ctime TIME, atime TIME, mtime TIME, "
	"FOREIGN KEY (subsys_id) REFERENCES subsystems(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT, "
	"FOREIGN KEY (port_id) REFERENCES ports(id) "
	"ON UPDATE CASCADE ON DELETE RESTRICT);",
};

void configdb_update_hook(void *arg, int cmd, const char *db,
			  const char *tbl, sqlite3_int64 rowid)
{
	if (!strcmp(tbl, "controllers"))
		raise_aen(NVME_AER_NOTICE_NS_CHANGED,
			  NVME_AEN_BIT_NS_ATTR);
	if (!strcmp(tbl, "ana_port_group"))
		raise_aen(NVME_AER_NOTICE_ANA,
			  NVME_AEN_BIT_ANA_CHANGE);
	if (!strcmp(tbl, "subsys_port") ||
	    !strcmp(tbl, "host_subsys"))
		raise_aen(NVME_AER_NOTICE_DISC_CHANGED,
			  NVME_AEN_BIT_DISC_CHANGE);
}

int configdb_init(void)
{
	int i, ret;

	for (i = 0; i < NUM_TABLES; i++) {
		ret = sql_exec_simple(init_sql[i]);
		if (ret)
			break;
	}
	sqlite3_update_hook(configdb_db, configdb_update_hook, NULL);

	return ret;
}

static const char *exit_sql[NUM_TABLES] =
{
	"DROP TABLE subsys_port;",
	"DROP TABLE host_subsys;",
	"DROP TABLE ana_port_group;",
	"DROP INDEX port_addr_idx;",
	"DROP TABLE ports;",
	"DROP INDEX nsid_idx;",
	"DROP TABLE namespaces;",
	"DROP INDEX cntlid_idx;",
	"DROP TABLE controllers;",
	"DROP TABLE ana_groups;",
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
	"INSERT INTO hosts (nqn, ctime, mtime) "
	"VALUES ('%s', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);";

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
	"SELECT unixepoch(ctime) AS ctime FROM hosts WHERE nqn = '%s';";

int configdb_stat_host(const char *hostnqn, struct stat *stbuf)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, stat_host_sql, hostnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_stat(sql, stbuf);
	free(sql);
	return ret;
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
	ret = sql_exec_error(ret, fill_host_dir_sql, errmsg);
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
	"(nqn, attr_model, attr_version, attr_ieee_oui, attr_firmware, attr_allow_any_host, attr_type, ctime) "
	"VALUES ('%s', 'nofuse', '2.0', '851255', '%s', '%d', '%d', CURRENT_TIMESTAMP);";

int configdb_add_subsys(const char *subsysnqn, int type)
{
	char *sql;
	int ret, allow_any = 0;

	if (type == NVME_NQN_CUR)
		allow_any = 1;
	ret = asprintf(&sql, add_subsys_sql, subsysnqn,
		       firmware_rev, allow_any, type);
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

int configdb_set_discovery_nqn(const char *nqn)
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
	"SELECT unixepoch(ctime) AS ctime, unixepoch(mtime) AS mtime "
	"FROM subsystems WHERE nqn = '%s';";

int configdb_stat_subsys(const char *subsysnqn, struct stat *stbuf)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, stat_subsys_sql, subsysnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_stat(sql, stbuf);
	free(sql);
	return ret;
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
	return sql_exec_error(ret, fill_subsys_dir_sql, errmsg);
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
	ret = sql_exec_error(ret, sql, errmsg);
	if (ret == 0) {
		filler(buf, "allowed_hosts", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "namespaces", NULL, 0, FUSE_FILL_DIR_PLUS);
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
	"UPDATE subsystems SET %s = '%s', mtime = CURRENT_TIMESTAMP "
	"WHERE nqn = '%s';";

int configdb_set_subsys_attr(const char *nqn, const char *attr,
			     const char *buf)
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

int configdb_del_subsys(const char *nqn)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, del_subsys_sql, nqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_namespace_sql[] =
	"INSERT INTO namespaces "
	"(device_uuid, device_nguid, device_eui64, nsid, "
	"subsys_id, ana_group_id, ctime) "
	"SELECT '%s', '%s', '%s', '%u', s.id, ag.id, CURRENT_TIMESTAMP "
	"FROM subsystems AS s, ana_groups AS ag "
	"WHERE s.nqn = '%s' AND s.attr_type == '2' AND ag.id = '1';";

static char namespace_chg_aen_sql[] =
	"UPDATE controllers SET ns_chg_ctr = ns_chg_ctr + 1 "
	"FROM "
	"(SELECT s.nqn AS subsysnqn, n.nsid "
	" FROM subsystems AS s "
	" INNER JOIN namespaces AS n ON n.subsys_id = s.id "
	" INNER JOIN controllers AS c on c.subsys_id = s.id) AS sel "
	"WHERE sel.subsysnqn = '%s' AND sel.nsid = '%d';";

int configdb_add_namespace(const char *subsysnqn, u32 nsid)
{
	char *sql;
	uuid_t uuid;
	char uuid_str[65], nguid_str[33], eui64_str[33];
	unsigned int nguid1, nguid2;
	int ret, _ret;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;
	uuid_generate(uuid);
	uuid_unparse(uuid, uuid_str);
	memcpy(&nguid1, &uuid[8], 4);
	memcpy(&nguid2, &uuid[12], 4);
	sprintf(nguid_str, "%08x%08x%s",
		nguid1, nguid2, NOFUSE_NGUID_PREFIX);
	sprintf(eui64_str, "0efd37%hhx%08x",
		uuid[11], nguid2);
	ret = asprintf(&sql, add_namespace_sql, uuid_str, nguid_str, eui64_str,
		       nsid, subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
	if (sqlite3_changes(configdb_db) == 0) {
		ret = -EPERM;
		goto done;
	}
	ret = asprintf(&sql, namespace_chg_aen_sql, subsysnqn, nsid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
done:
	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
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
	"SELECT unixepoch(n.ctime) AS ctime, unixepoch(n.mtime) AS mtime "
	"FROM namespaces AS n "
	"INNER JOIN subsystems AS s ON s.id = n.subsys_id "
	"WHERE s.nqn = '%s' AND n.nsid = '%u';";

int configdb_stat_namespace(const char *subsysnqn, u32 nsid,
			 struct stat *stbuf)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, stat_namespace_sql, subsysnqn, nsid);
	if (ret < 0)
		return ret;

	ret = sql_exec_stat(sql, stbuf);
	free(sql);
	return ret;
}

static char fill_namespace_dir_sql[] =
	"SELECT n.nsid AS nsid FROM namespaces AS n "
	"INNER JOIN subsystems AS s ON s.id = n.subsys_id "
	"WHERE s.nqn = '%s';";

int configdb_fill_namespace_dir(const char *nqn, void *buf,
				fuse_fill_dir_t filler)
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
	ret = sql_exec_error(ret, fill_namespace_dir_sql, errmsg);
	free(sql);
	return ret;
}

static char fill_namespace_sql[] =
	"SELECT n.* FROM namespaces AS n "
	"INNER JOIN subsystems AS s ON s.id = n.subsys_id "
	"WHERE s.nqn = '%s' AND n.nsid = '%u';";

static int fill_ns_cb(void *p, int argc, char **argv, char **colname)
{
	struct fill_parm_t *parm = p;
	const char prefix[] = "device_";
	int i;

	for (i = 0; i < argc; i++) {
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

int configdb_fill_namespace(const char *nqn, u32 nsid,
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
	ret = sql_exec_error(ret, fill_namespace_sql, errmsg);
	free(sql);
	filler(buf, "ana_grpid", NULL, 0, FUSE_FILL_DIR_PLUS);
	return ret;
}

static char get_namespace_attr_sql[] =
	"SELECT ns.%s FROM namespaces AS ns "
	"INNER JOIN subsystems AS s ON s.id = ns.subsys_id "
	"WHERE s.nqn = '%s' AND ns.nsid = '%u';";

int configdb_get_namespace_attr(const char *subsysnqn, u32 nsid,
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
	"WHERE sel.nqn = '%s' AND sel.nsid = '%u';";

int configdb_set_namespace_attr(const char *subsysnqn, u32 nsid,
				const char *attr, const char *buf)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;
	if (!strcmp(attr, "enable"))
		attr = "device_enable";
	ret = asprintf(&sql, set_namespace_attr_sql, attr, buf,
		       subsysnqn, nsid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
	if (sqlite3_changes(configdb_db) == 0) {
		printf("%s: no rows modified\n", __func__);
		goto done;
	}
	ret = asprintf(&sql, namespace_chg_aen_sql, subsysnqn, nsid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
done:
	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

static char get_namespace_anagrp_sql[] =
	"SELECT ag.id AS grpid FROM ana_groups AS ag "
	"INNER JOIN namespaces AS ns ON ns.ana_group_id = ag.id "
	"INNER JOIN subsystems AS s ON s.id = ns.subsys_id "
	"WHERE s.nqn = '%s' AND ns.nsid = '%u';";

int configdb_get_namespace_anagrp(const char *subsysnqn, u32 nsid,
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
	"UPDATE namespaces SET ana_group_id = sel.grpid "
	"FROM "
	"(SELECT ag.id AS grpid "
	"FROM ana_groups AS ag) AS sel "
	"WHERE sel.grpid = '%d' AND nsid = '%u';";

static char set_namespace_anagrp_aen_sql[] =
	"UPDATE controllers SET ana_chg_ctr = ana_chg_ctr + 1 "
	"FROM "
	"(SELECT s.nqn AS subsysnqn "
	" FROM subsystems AS s "
	" INNER JOIN controllers AS c ON c.subsys_id = s.id ) AS sel "
	"WHERE sel.subsysnqn = '%s';";

int configdb_set_namespace_anagrp(const char *subsysnqn, u32 nsid,
				  int ana_grpid)
{
	char *sql;
	int ret, _ret, new_ana_grpid;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;
	ret = asprintf(&sql, set_namespace_anagrp_sql,
		       subsysnqn, ana_grpid, nsid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = configdb_get_namespace_anagrp(subsysnqn, nsid,
					    &new_ana_grpid);
	if (ret < 0)
		goto rollback;
	if (new_ana_grpid != ana_grpid) {
		printf("%s: ana group id %d should be %d\n",
		       __func__, new_ana_grpid, ana_grpid);
		ret = -ENOENT;
		goto done;
	}

	ret = asprintf(&sql, set_namespace_anagrp_aen_sql,
		       subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
done:
	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

static char del_namespace_sql[] =
	"DELETE FROM namespaces AS ns WHERE ns.subsys_id IN "
	"(SELECT id FROM subsystems WHERE nqn = '%s') AND "
	"ns.nsid = '%u';";

int configdb_del_namespace(const char *subsysnqn, u32 nsid)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;
	ret = asprintf(&sql, del_namespace_sql, subsysnqn, nsid);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
	if (sqlite3_changes(configdb_db) == 0) {
		printf("%s: no rows deleted\n", __func__);
		ret = -ENOENT;
		goto done;
	}
	ret = asprintf(&sql, namespace_chg_aen_sql, subsysnqn, nsid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
done:
	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

static char add_ctrl_sql[] =
	"INSERT INTO controllers ( cntlid, subsys_id ) "
	"SELECT '%d', s.id FROM subsystems AS s "
	"WHERE s.nqn = '%s';";
int configdb_add_ctrl(const char *subsysnqn, int cntlid)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, add_ctrl_sql, cntlid, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char del_ctrl_sql[] =
	"DELETE FROM controllers AS c WHERE c.subsys_id IN "
	"(SELECT id FROM subsystems WHERE nqn = '%s') AND "
	"c.cntlid = '%d';";

int configdb_del_ctrl(const char *subsysnqn, int cntlid)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, del_ctrl_sql, subsysnqn, cntlid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char add_port_sql[] =
	"INSERT INTO ports (id, addr_trtype, addr_traddr, addr_adrfam, ctime)"
	" VALUES ('%d', 'tcp', '127.0.0.1', '%s', CURRENT_TIMESTAMP);";

int configdb_add_port(unsigned int portid)
{
	char *sql;
	int ret;

	if (!portid) {
		fprintf(stderr, "no port id specified\n");
		return -EINVAL;
	}

	ret = asprintf(&sql, add_port_sql, portid, ADRFAM_STR_IPV4);
	if (ret < 0)
		return ret;

	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char stat_port_sql[] =
	"SELECT unixepoch(ctime) AS ctime, unixepoch(mtime) AS mtime "
	"FROM ports WHERE id = '%d';";

int configdb_stat_port(unsigned int port, struct stat *stbuf)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, stat_port_sql, port);
	if (ret < 0)
		return ret;

	ret = sql_exec_stat(sql, stbuf);
	free(sql);
	return ret;
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
	ret = sql_exec_error(ret, fill_port_dir_sql, errmsg);
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
	ret = sql_exec_error(ret, sql, errmsg);
	if (ret == 0) {
		filler(buf, "ana_groups", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "subsystems", NULL, 0, FUSE_FILL_DIR_PLUS);
		filler(buf, "referrals", NULL, 0, FUSE_FILL_DIR_PLUS);
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

static char set_port_attr_sql[] =
	"UPDATE ports SET %s = '%s', mtime = CURRENT_TIMESTAMP "
	"WHERE id = '%d';";

static char update_genctr_port_sql[] =
	"UPDATE hosts SET genctr = genctr + 1 "
	"FROM "
	"(SELECT hs.host_id AS host_id, sp.port_id AS port_id "
	"FROM host_subsys AS hs "
	"INNER JOIN subsys_port AS sp ON hs.subsys_id = sp.subsys_id) "
	"AS hg WHERE hg.host_id = hosts.id AND hg.port_id = '%d';";

int configdb_set_port_attr(unsigned int port, const char *attr,
			   const char *value)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, set_port_attr_sql, attr, value, port);
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
	"INSERT INTO ana_port_group (ana_group_id, port_id, ana_state, ctime) "
	"SELECT ag.id, p.id, '%d', CURRENT_TIMESTAMP "
	"FROM ports AS p, ana_groups AS ag "
	"WHERE p.id = '%d' AND ag.id = '%d';";

int configdb_add_ana_group(int port, int grpid, int ana_state)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, add_ana_group_sql, ana_state, port, grpid);
	if (ret < 0)
		return ret;
	ret = sql_exec_simple(sql);
	free(sql);
	return ret;
}

static char count_ana_port_group_sql[] =
	"SELECT count(ap.id) AS num FROM ana_port_group AS ap "
	"INNER JOIN ports AS p ON p.id = ap.port_id "
	"WHERE p.id = '%s';";

int configdb_count_ana_groups(const char *port, int *num)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, count_ana_port_group_sql, port);
	if (ret < 0)
		return ret;
	ret = sql_exec_int(sql, "num", num);
	free(sql);

	return ret;
}

static char stat_ana_group_sql[] =
	"SELECT unixepoch(ap.ctime) AS ctime, unixepoch(ap.mtime) AS mtime "
	"FROM ana_port_group AS ap "
	"INNER JOIN ports AS p ON p.id = ap.port_id "
	"INNER JOIN ana_groups AS ag ON ap.ana_group_id = ag.id "
	"WHERE p.id = '%s' AND ag.id = '%s';";

int configdb_stat_ana_group(const char *port, const char *ana_grpid,
			    struct stat *stbuf)
{
	int ret;
	char *sql;

	ret = asprintf(&sql, stat_ana_group_sql, port, ana_grpid);
	if (ret < 0)
		return ret;
	ret = sql_exec_stat(sql, stbuf);
	free(sql);
	return ret;
}

static char fill_ana_port_group_sql[] =
	"SELECT ag.id AS grpid FROM ana_groups AS ag "
	"INNER JOIN ana_port_group AS ap ON ag.id = ap.ana_group_id "
	"INNER JOIN ports AS p ON p.id = ap.port_id "
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

	ret = asprintf(&sql, fill_ana_port_group_sql, port);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, fill_root_cb,
			   &parm, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

static char get_ana_group_sql[] =
	"SELECT ap.ana_state AS ana_state FROM ana_port_group AS ap "
	"INNER JOIN ports AS p ON p.id = ap.port_id "
	"INNER JOIN ana_groups AS ag ON ag.id = ap.ana_group_id "
	"WHERE p.id = '%s' AND ag.id = '%s';";

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
	"UPDATE ana_port_group SET ana_state = '%d', chgcnt = chgcnt + 1 "
	"FROM "
	"(SELECT ap.id AS ag_id, ap.port_id AS port_id, ag.id AS grpid "
	" FROM ana_port_group AS ap "
	" INNER JOIN ana_groups AS ag ON ap.ana_group_id = ag.id) AS sel "
	"WHERE id = sel.ag_id AND sel.port_id = '%s' AND sel.grpid = '%s';";

static char set_ana_group_aen_sql[] =
	"UPDATE controllers SET ana_chg_ctr = ana_chg_ctr + 1 "
	"FROM "
	"(SELECT sp.port_id AS portid FROM subsys_port AS sp "
	" INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	" INNER JOIN controllers AS c on c.subsys_id = s.id ) AS sel "
	"WHERE sel.portid = '%s';";

int configdb_set_ana_group(const char *port, const char *ana_grpid,
			   int ana_state)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;
	ret = asprintf(&sql, set_ana_group_sql, ana_state, port, ana_grpid);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
	ret = asprintf(&sql, set_ana_group_aen_sql, port);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;
	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
	return ret;
}

static char del_ana_group_sql[] =
	"DELETE FROM ana_port_group AS ap WHERE ap.port_id IN "
	"(SELECT id FROM ports WHERE id = '%d') AND "
	"ap.ana_group_id IN "
	"(SELECT id FROM ana_groups WHERE id = '%d');";

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

static char discovery_chg_aen_sql[] =
	"UPDATE controllers SET disc_chg_ctr = disc_chg_ctr + 1 "
	"FROM "
	"(SELECT s.nqn AS subsysnqn "
	" FROM subsystems AS s "
	" INNER JOIN controllers AS c ON c.subsys_id = s.id ) AS sel "
	"WHERE sel.subsysnqn = '%s';";

int configdb_add_host_subsys(const char *hostnqn, const char *subsysnqn)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;

	ret = asprintf(&sql, add_host_subsys_sql,
		       hostnqn, subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = asprintf(&sql, "UPDATE hosts SET genctr = genctr + 1 "
		       "WHERE nqn = '%s';", hostnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = asprintf(&sql, discovery_chg_aen_sql, subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
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
	ret = sql_exec_error(ret, sql, errmsg);
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
	"SELECT unixepoch(hs.ctime) AS ctime, unixepoch(hs.mtime) AS mtime "
	"FROM host_subsys AS hs "
	"INNER JOIN subsystems AS s ON s.id = hs.subsys_id "
	"INNER JOIN hosts AS h ON h.id = hs.host_id "
	"WHERE h.nqn = '%s' AND s.nqn = '%s';";

int configdb_stat_host_subsys(const char *hostnqn, const char *subsysnqn,
			      struct stat *stbuf)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, stat_host_subsys_sql, hostnqn, subsysnqn);
	if (ret < 0)
		return ret;

	ret = sql_exec_stat(sql, stbuf);
	free(sql);
	return ret;
}

static char del_host_subsys_sql[] =
	"DELETE FROM host_subsys AS hs "
	"WHERE hs.host_id IN "
	"(SELECT id FROM hosts WHERE nqn = '%s') AND "
	"hs.subsys_id IN "
	"(SELECT id FROM subsystems WHERE nqn = '%s');";

int configdb_del_host_subsys(const char *hostnqn, const char *subsysnqn)
{
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;

	ret = asprintf(&sql, del_host_subsys_sql,
		       hostnqn, subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = asprintf(&sql, discovery_chg_aen_sql, subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
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
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;

	ret = asprintf(&sql, add_subsys_port_sql,
		       subsysnqn, port);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = asprintf(&sql, update_genctr_host_subsys_sql,
		       subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = asprintf(&sql, discovery_chg_aen_sql, subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
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
	int ret, _ret;
	char *sql;

	ret = sql_exec_simple("BEGIN TRANSACTION;");
	if (ret < 0)
		return ret;

	ret = asprintf(&sql, del_subsys_port_sql,
		       subsysnqn, port);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = asprintf(&sql, update_genctr_host_subsys_sql,
		       subsysnqn);
	if (ret < 0)
		goto rollback;

	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	ret = asprintf(&sql, discovery_chg_aen_sql, subsysnqn);
	if (ret < 0)
		goto rollback;
	ret = sql_exec_simple(sql);
	free(sql);
	if (ret < 0)
		goto rollback;

	COMMIT_TRANSACTION;
	return ret;
rollback:
	ROLLBACK_TRANSACTION;
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
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

static char stat_subsys_port_sql[] =
	"SELECT unixepoch(sp.ctime) AS ctime, unixepoch(sp.mtime) AS mtime "
	"FROM subsys_port AS sp "
	"INNER JOIN subsystems AS s ON s.id = sp.subsys_id "
	"INNER JOIN ports AS p ON p.id = sp.port_id "
	"WHERE s.nqn = '%s' AND p.id = '%d';";

int configdb_stat_subsys_port(const char *subsysnqn, unsigned int port,
			      struct stat *stbuf)
{
	char *sql;
	int ret;

	ret = asprintf(&sql, stat_subsys_port_sql, subsysnqn, port);
	if (ret < 0)
		return ret;

	ret = sql_exec_stat(sql, stbuf);
	free(sql);
	return ret;
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

struct sql_entry_parm {
	u8 *buffer;
	int cur;
	int len;
};

static int sql_disc_entry_cb(void *argp, int argc, char **argv, char **colname)
{
	int i;
	struct sql_entry_parm *parm = argp;
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
			if (!strcmp(argv[i], ADRFAM_STR_IPV4)) {
				entry->adrfam = NVMF_ADDR_FAMILY_IP4;
			} else if (!strcmp(argv[i], ADRFAM_STR_IPV6)) {
				entry->adrfam = NVMF_ADDR_FAMILY_IP6;
			} else if (!strcmp(argv[i], ADRFAM_STR_FC)) {
				entry->adrfam = NVMF_ADDR_FAMILY_FC;
			} else if (!strcmp(argv[i], ADRFAM_STR_IB)) {
				entry->adrfam = NVMF_ADDR_FAMILY_IB;
			} else if (!strcmp(argv[i], ADRFAM_STR_PCI)) {
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
	struct sql_entry_parm parm = {
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
	ret = sqlite3_exec(configdb_db, sql, sql_disc_entry_cb,
			   &parm, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	printf("disc entries: cur %d len %d\n", parm.cur, parm.len);

	printf("Display disc entries for any host\n");
	ret = sqlite3_exec(configdb_db, any_disc_entry_sql,
			   sql_disc_entry_cb, &parm, &errmsg);
	ret = sql_exec_error(ret, any_disc_entry_sql, errmsg);
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
			memcpy(id->mn, argv[i], strlen(argv[i]));
		} else if (!strcmp(col[i], "serial")) {
			memcpy(id->sn, argv[i], strlen(argv[i]));
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
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

static int ns_list_cb(void *argp, int argc, char **argv, char **col)
{
	struct sql_entry_parm *parm = argp;
	int i;

	if (!argp) {
		fprintf(stderr, "%s: Invalid parameter\n", __func__);
		return 0;
	}

	for (i = 0; i < argc; i++) {
		size_t arg_len = argv[i] ? strlen(argv[i]) : 0;

		if (!strcmp(col[i], "nsid")) {
			void *buf = parm->buffer + parm->cur;
			char *eptr = NULL;
			u32 nsid, _nsid = 0;

			if (!arg_len)
				continue;

			_nsid = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr) {
				printf("%s: parsing error on 'nsid'\n",
				       __func__);
				_nsid = 0;
				continue;
			}
			nsid = htole32(_nsid);
			memcpy(buf, &nsid, sizeof(u32));
			parm->cur += sizeof(u32);
		}
	}
	return 0;
}

static char identify_active_ns_sql[] =
	"SELECT ns.nsid FROM namespaces AS ns "
	"INNER JOIN subsystems AS s "
	"ON ns.subsys_id = s.id "
	"WHERE s.nqn = '%s' AND ns.device_enable = '1' "
	"ORDER BY ns.nsid;";

int configdb_identify_active_ns(const char *subsysnqn, u8 *ns_list, size_t len)
{
	struct sql_entry_parm parm = {
		.len = len,
		.buffer = ns_list,
		.cur = 0,
	};
	char *sql, *errmsg;
	int ret;

	ret = asprintf(&sql, identify_active_ns_sql, subsysnqn);
	if (ret < 0)
		return ret;
	ret = sqlite3_exec(configdb_db, sql, ns_list_cb,
			   &parm, &errmsg);
	ret = sql_exec_error(ret, sql, errmsg);
	free(sql);
	return ret;
}

static char count_ana_grps_sql[] =
	"SELECT ap.ana_state, ap.chgcnt, count(ns.nsid) AS num "
	"FROM ana_port_group AS ap "
	"INNER JOIN subsys_port AS sp ON sp.port_id = ap.port_id "
	"INNER JOIN subsystems AS s ON sp.subsys_id = s.id "
	"INNER JOIN namespaces AS ns ON ns.subsys_id = s.id "
	"INNER JOIN ana_groups AS ag ON ap.ana_group_id = ag.id "
	"WHERE s.nqn = '%s' AND ap.port_id = '%d' AND ag.id = '%d';";

static int count_ana_grps_cb(void *argp, int argc, char **argv, char **col)
{
	int i;
	struct nvme_ana_group_desc *grp_desc = argp;
	unsigned int ana_state = 0xff, chgcnt = 0, num;

	if (!argp) {
		fprintf(stderr, "%s: Invalid parameter\n", __func__);
		return 0;
	}

	for (i = 0; i < argc; i++) {
		size_t arg_len = argv[i] ? strlen(argv[i]) : 0;
		char *eptr = NULL;

		if (!arg_len) {
			continue;
		}
		if (!strcmp(col[i], "ana_state")) {
			ana_state = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr) {
				printf("%s: parsing error on 'state'\n",
				       __func__);
				ana_state = 0xff;
				continue;
			}
		}
		if (!strcmp(col[i], "chgcnt")) {
			chgcnt = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr) {
				printf("%s: parsing error on 'chgcnt'\n",
				       __func__);
				continue;
			}
		}
		if (!strcmp(col[i], "num")) {
			num = strtoul(argv[i], &eptr, 10);
			if (argv[i] == eptr) {
				printf("%s: parsing error on 'nsid'\n",
				       __func__);
				num = 0;
				continue;
			}
		}
	}
	if (ana_state != 0xff && num != 0) {
		grp_desc->chgcnt = htole64(chgcnt);
		grp_desc->state = ana_state;
		grp_desc->nnsids = htole32(num);
	}
	return 0;
}

static char ana_grp_log_entry_sql[] =
	"SELECT ns.nsid FROM ana_port_group AS ap "
	"INNER JOIN subsys_port AS sp ON sp.port_id = ap.port_id "
	"INNER JOIN subsystems AS s ON sp.subsys_id = s.id "
	"INNER JOIN namespaces AS ns ON ns.subsys_id = s.id "
	"INNER JOIN ana_groups AS ag ON ap.ana_group_id = ag.id "
	"WHERE s.nqn = '%s' AND ap.port_id = '%d' AND ag.id = '%d';";

int configdb_ana_log_entries(const char *subsysnqn, unsigned int portid,
			     u8 *log, int log_len)
{
	struct nvme_ana_rsp_hdr *hdr = (struct nvme_ana_rsp_hdr *)log;
	struct nvme_ana_group_desc *grp_desc = hdr->entries;
	struct sql_entry_parm parm;
	char *sql, *errmsg;
	int ret, ngrps = 0, grpid;

	memset(grp_desc, 0, 32);
	parm.buffer = (u8 *)grp_desc;
	parm.len = log_len - sizeof(struct nvme_ana_rsp_hdr);
	for (grpid = 1; grpid <= MAX_ANAGRPID; grpid++) {
		u32 nnsids;

		parm.buffer = (u8 *)grp_desc;
		ret = asprintf(&sql, count_ana_grps_sql,
			       subsysnqn, portid, grpid);
		if (ret < 0)
			return ret;
		ret = sqlite3_exec(configdb_db, sql, count_ana_grps_cb,
				   parm.buffer, &errmsg);
		ret = sql_exec_error(ret, sql, errmsg);
		free(sql);
		if (ret < 0)
			return ret;
		nnsids = le32toh(grp_desc->nnsids);
		if (!nnsids)
			continue;

		grp_desc->grpid = htole16(grpid);
		printf("%s: grpid %u %d nsids state %d\n",
		       __func__, grpid, nnsids, grp_desc->state);

		parm.len -= sizeof(struct nvme_ana_group_desc);
		parm.buffer = (u8 *)grp_desc->nsids;
		parm.cur = 0;
		ret = asprintf(&sql, ana_grp_log_entry_sql,
			       subsysnqn, portid, grpid);
		if (ret < 0)
			return ret;
		ret = sqlite3_exec(configdb_db, sql, ns_list_cb,
				   &parm, &errmsg);
		ret = sql_exec_error(ret, sql, errmsg);
		free(sql);
		if (ret < 0)
			return ret;
		grp_desc = (struct nvme_ana_group_desc *)
			(parm.buffer + parm.cur);
		parm.len -= parm.cur;
		memset(grp_desc, 0, sizeof(*grp_desc));
		ngrps++;
		if (parm.len < 32)
			break;
	}
	hdr->ngrps = htole16(ngrps);
	printf("%s: %d ana groups\n", __func__, ngrps);
	return parm.len;
}

int configdb_open(const char *filename)
{
	int ret, i;

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
	for (i = 0; i < MAX_ANAGRPID; i++) {
		int ret;
		char *sql;

		ret = asprintf(&sql,
			       "INSERT INTO ana_groups (id) VALUES ('%d');",
			       i + 1);
		if (ret < 0)
			break;
		ret = sql_exec_simple(sql);
		free(sql);
		if (ret < 0)
			break;
	}
	return ret;
}

void configdb_close(const char *filename)
{
	configdb_exit();
	sqlite3_close(configdb_db);
	unlink(filename);
}
