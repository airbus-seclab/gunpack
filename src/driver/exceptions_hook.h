/*
 * Copyright 2015 Julien Lenoir / Airbus Group Innovations
 * contact: julien.lenoir@airbus.com
 */

/*
 * This file is part of Gunpack.
 *
 * Gunpack is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Gunpack is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Gunpack.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef EXCEPTIONS_HOOK_H
#define EXCEPTIONS_HOOK_H

#include "win_kernl.h"

int HookExceptionDispatcher(PVOID KernelImageBase, ULONG KernelImageSize);
int UnHookExceptionDispatcher();
int HookKiTrap0E(PVOID KernelImageBase, ULONG KernelImageSize);
int UnHookKiTrap0E();

#endif