/*
 * Copyright (C) 2013 Hiroyuki Ikezoe
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#ifndef PERF_SWEVENT_H
#define PERF_SWEVENT_H

#include <stdbool.h>

int perf_swevent_write_value_at_address(unsigned long int address, int value);
void perf_swevent_reap_child_process(int number_of_children);

#endif /* PERF_SWEVENT_H */
/*
vi:ts=2:nowrap:ai:expandtab:sw=2
*/
