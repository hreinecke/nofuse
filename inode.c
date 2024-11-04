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

#include <stdio.h>
#include <unistd.h>
#include <sqlite3.h>
#include <errno.h>

#include "common.h"
#include "inode.h"

static sqlite3 *inode_db;

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
			strerror(parm.done));
	else
		*value = parm.val;
	return parm.done;
}

#define NUM_TABLES 7

static const char *init_sql[NUM_TABLES] = {
"CREATE TABLE inode ( ino INTEGER PRIMARY KEY AUTOINCREMENT, "
"pathname VARCHAR(256) NOT NULL, parent_ino INTEGER, mode INTEGER, "
"ctime TIME, atime TIME, mtime TIME, data_type INTEGER, data_id INTEGER);",
"CREATE TABLE host ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
"nqn VARCHAR(223) UNIQUE NOT NULL, genctr INTEGER DEFAULT 0, "
"parent_ino INTEGER, FOREIGN KEY (parent_ino) REFERENCES inode(ino));",
"CREATE TABLE subsys ( id INTEGER PRIMARY KEY AUTOINCREMENT, "
"nqn VARCHAR(223) UNIQUE NOT NULL, allow_any INT DEFAULT 1, "
"type INT DEFAULT 3, parent_ino INTEGER, "
"FOREIGN KEY (parent_ino) REFERENCES inode(ino));",
"CREATE TABLE port ( portid INTEGER PRIMARY KEY AUTOINCREMENT,"
"trtype CHAR(32) NOT NULL, adrfam CHAR(32) DEFAULT '', "
"subtype INT DEFAULT 2, treq char(32), traddr CHAR(255) NOT NULL, "
"trsvcid CHAR(32) DEFAULT '', tsas CHAR(255) DEFAULT '', parent_ino INTEGER, "
"UNIQUE(trtype,adrfam,traddr,trsvcid), "
"FOREIGN KEY (parent_ino) REFERENCES inode (ino) );"
"CREATE UNIQUE INDEX port_addr ON port(trtype, adrfam, traddr, trsvcid);",
"CREATE TABLE host_subsys ( host_id INTEGER, subsys_id INTEGER, "
"parent_ino INTEGER, FOREIGN KEY (parent_ino) REFERENCES inode(ino), "
"FOREIGN KEY (host_id) REFERENCES host(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT, "
"FOREIGN KEY (subsys_id) REFERENCES subsys(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT);",
"CREATE TABLE subsys_port ( subsys_id INTEGER, port_id INTEGER, "
"parent_ino INTEGER, FOREIGN KEY (parent_ino) REFERENCES inode(ino), "
"FOREIGN KEY (subsys_id) REFERENCES subsys(id) "
"ON UPDATE CASCADE ON DELETE RESTRICT, "
"FOREIGN KEY (port_id) REFERENCES port(portid) "
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
	"DROP TABLE port;",
	"DROP TABLE subsys;",
	"DROP TABLE host;",
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

static char add_inode_sql[] =
	"INSERT INTO inode (pathname, parent_ino) VALUES ('%s','%d');";
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

static char del_host_sql[] =
	"DELETE FROM host WHERE nqn = '%s';";

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
	"INSERT INTO subsys (nqn, allow_any, type, parent_ino) "
	"VALUES ('%s', '%d', '%d', '%d');";

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

static char del_subsys_sql[] =
	"DELETE FROM subsys WHERE id = '%d';";

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
	"INSERT INTO port (trtype, adrfam, treq, traddr, trsvcid, tsas, subtype)"
	" VALUES ('%s','%s','%s','%s','%s','%s','%d');";

static char select_portid_sql[] =
	"SELECT portid FROM port "
	"WHERE trtype = '%s' AND adrfam = '%s' AND "
	"traddr = '%s' AND trsvcid = '%s';";

static char update_traddr_sql[] =
	"UPDATE port SET traddr = '%s' "
	"WHERE portid = '%d';";

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
	ret = sql_exec_int(sql, "portid", &portid);
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

static char update_genctr_port_sql[] =
	"UPDATE host SET genctr = genctr + 1 "
	"FROM "
	"(SELECT hs.host_id AS host_id, sp.portid AS portid "
	"FROM host_subsys AS hs "
	"INNER JOIN subsys_port AS sp ON hs.subsys_id = sp.subsys_id) "
	"AS hg WHERE hg.host_id = host.id AND hg.portid = '%d';";

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

	ret = asprintf(&sql, "UPDATE port SET %s = '%s' "
		       "WHERE portid = '%d';", attr, value,
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
	"DELETE FROM port WHERE portid = '%d';";

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
	"SELECT host.id, subsys.id FROM host, subsys "
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
	"(SELECT id FROM host WHERE nqn LIKE '%s') AND "
	"hs.subsys_id IN "
	"(SELECT id FROM subsys WHERE nqn LIKE '%s');";

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
	"SELECT subsys.id, port.portid FROM subsys, port "
	"WHERE subsys.nqn LIKE '%s' AND port.portid = '%d';";

static char update_genctr_host_subsys_sql[] =
	"UPDATE host SET genctr = genctr + 1 "
	"FROM "
	"(SELECT s.nqn AS subsys_nqn, hs.host_id AS host_id "
	"FROM host_subsys AS hs "
	"INNER JOIN subsys AS s ON s.id = hs.subsys_id) AS hs "
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
	"(SELECT id FROM subsys WHERE nqn LIKE '%s') AND "
	"sp.port_id IN "
	"(SELECT portid FROM port WHERE portid = %d);";

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
	"SELECT count(p.portid) AS portnum "
	"FROM subsys_port AS sp "
	"INNER JOIN subsys AS s ON s.id = sp.subsys_id "
	"INNER JOIN port AS p ON p.portid = sp.port_id "
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
		} else if (!strcmp(colname[i], "portid")) {
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
	"p.portid, p.subtype, p.trtype, p.traddr, p.trsvcid, p.treq, p.tsas "
	"FROM subsys_port AS sp "
	"INNER JOIN subsys AS s ON s.id = sp.subsys_id "
	"INNER JOIN host_subsys AS hs ON hs.subsys_id = sp.subsys_id "
	"INNER JOIN host AS h ON hs.host_id = h.id "
	"INNER JOIN port AS p ON sp.port_id = p.portid "
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
	"SELECT genctr FROM host WHERE nqn LIKE '%s';";

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
	return ret;
}

void inode_close(const char *filename)
{
	inode_exit();
	sqlite3_close(inode_db);
	unlink(filename);
}
