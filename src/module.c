/*
 *
 *  Wireless daemon for Linux
 *
 *  Copyright (C) 2019  Intel Corporation. All rights reserved.
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <ell/ell.h>

#include "src/iwd.h"

struct dependency {
	struct dependency *next;
	struct module *module;
};

struct module {
	struct iwd_module_desc *desc;
	struct dependency *depends;
	bool visited : 1;
	bool processed : 1;
};

extern struct iwd_module_desc __start___iwd_module[];
extern struct iwd_module_desc __stop___iwd_module[];
extern struct iwd_module_depends __start___iwd_module_dep[];
extern struct iwd_module_depends __stop___iwd_module_dep[];

static struct iwd_module_desc **modules_sorted;

static struct module *module_find(struct module *modules, size_t count,
						const char *name)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		if (!strcmp(modules[i].desc->name, name))
			return &modules[i];

	return NULL;
}

static int module_topological_order(struct module *module,
					struct iwd_module_desc **sorted,
					size_t *offset)
{
	struct dependency *d;
	int r;

	module->visited = true;

	for (d = module->depends; d; d = d->next) {
		if (d->module->processed)
			continue;

		if (d->module->visited) {
			l_error("Circular dependency between %s and %s",
					module->desc->name,
					d->module->desc->name);
			return -EINVAL;
		}

		r = module_topological_order(d->module, sorted, offset);
		if (r < 0)
			return r;
	}

	module->processed = true;
	sorted[*offset] = module->desc;
	*offset += 1;
	return 0;
}

int iwd_modules_init()
{
	struct iwd_module_desc *desc;
	struct iwd_module_depends *dep;
	L_AUTO_FREE_VAR(struct module *, modules) = NULL;
	L_AUTO_FREE_VAR(struct dependency *, deps) = NULL;
	L_AUTO_FREE_VAR(struct iwd_module_desc **, sorted) = NULL;
	unsigned int i = 0;
	size_t n_modules;
	size_t n_deps;
	size_t offset;
	int r;

	l_debug("");

	n_modules = (__stop___iwd_module - __start___iwd_module);
	modules = l_new(struct module, n_modules);

	for (desc = __start___iwd_module; desc < __stop___iwd_module; desc++)
		modules[i++].desc = desc;

	n_deps = (__stop___iwd_module_dep - __start___iwd_module_dep);
	deps = l_new(struct dependency, n_deps);

	for (dep = __start___iwd_module_dep, i = 0;
				dep < __stop___iwd_module_dep; dep++, i++) {
		struct module *src;
		struct module *dst;

		src = module_find(modules, n_modules, dep->self);
		dst = module_find(modules, n_modules, dep->target);
		if (!src || !dst) {
			l_error("Module dependency %s->%s not found",
					dep->self, dep->target);
			return -EINVAL;
		}

		deps[i].next = src->depends;
		deps[i].module = dst;
		src->depends = &deps[i];
	}

	sorted = l_new(struct iwd_module_desc *, n_modules);

	for (i = 0, offset = 0; i < n_modules; i++) {
		if (modules[i].processed)
			continue;

		if (module_topological_order(&modules[i], sorted,
							&offset) < 0)
			return -EINVAL;
	}

	modules_sorted = sorted;
	sorted = NULL;

	for (i = 0; i < n_modules; i++) {
		desc = modules_sorted[i];
		r = desc->init();

		if (r < 0) {
			l_error("Module %s failed to start: %d", desc->name, r);
			return r;
		}

		desc->active = true;
	}

	return 0;
}

void iwd_modules_exit()
{
	struct iwd_module_desc *desc;
	unsigned int i;
	size_t n_modules = (__stop___iwd_module - __start___iwd_module);

	l_debug("");

	if (!modules_sorted)
		return;

	for (i = 0; i < n_modules; i++) {
		desc = modules_sorted[i];
		if (!desc->active)
			continue;

		desc->exit();
		desc->active = false;
	}

	l_free(modules_sorted);
	modules_sorted = NULL;
}
